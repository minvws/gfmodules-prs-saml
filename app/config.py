import configparser
import os
from enum import Enum
from pathlib import Path
from typing import Any

from gfmodules.logging import ConfigLogging as GFConfigLogging
from gfmodules.logging.ini import split_comma_separated
from pydantic import BaseModel, Field, field_validator, model_validator

_PATH = "app.conf"
_ENVIRONMENT_CONFIG_PATH_NAME = "FASTAPI_CONFIG_PATH"
_CONFIG = None


class LogLevel(str, Enum):
    debug = "debug"
    info = "info"
    warning = "warning"
    error = "error"
    critical = "critical"


class ConfigApp(BaseModel):
    loglevel: LogLevel = Field(default=LogLevel.info)


class ConfigLogging(GFConfigLogging):
    _split_console_streams = field_validator("console_streams", mode="before")(
        split_comma_separated()
    )


class ConfigUvicorn(BaseModel):
    swagger_enabled: bool = Field(default=False)
    docs_url: str = Field(default="/docs")
    redoc_url: str = Field(default="/redoc")
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8534, gt=0, lt=65535)
    reload: bool = Field(default=True)
    reload_delay: float = Field(default=1)
    reload_dirs: list[str] = Field(default=["app"])
    use_ssl: bool = Field(default=False)
    ssl_base_dir: str | None = Field(default=None)
    ssl_cert_file: str | None = Field(default=None)
    ssl_key_file: str | None = Field(default=None)
    root_path: str = Field(default="")


class ConfigSaml(BaseModel):
    enabled: bool = False
    idp_metadata_file: Path | None = None
    entity_id: str | None = Field(default=None, min_length=1)
    audience: str | None = Field(default=None, min_length=1)
    acs_url: str | None = Field(default=None, min_length=1)
    service_uuid: str | None = Field(default=None, min_length=1)
    decryption_key_file: Path | None = None
    decryption_certificate_file: Path | None = None
    decryption_key_name: str | None = Field(default=None, min_length=1)
    accepted_identifier_types: str = "urn:nl-eid-gdi:1.0:id:legacy-BSN"
    allow_representation: bool = False
    minimum_loa: str = "http://eidas.europa.eu/LoA/substantial"
    clock_skew_seconds: int = Field(default=60, ge=0, le=120)
    max_xml_bytes: int = Field(default=2097152, ge=1024, le=10485760)

    @model_validator(mode="after")
    def require_enabled_settings(self) -> "ConfigSaml":
        if (
            self.decryption_key_name is not None
            and not self.decryption_key_name.strip()
        ):
            raise ValueError("Invalid decryption key name")
        types = {item.strip() for item in self.accepted_identifier_types.split(",")}
        if types != {"urn:nl-eid-gdi:1.0:id:legacy-BSN"}:
            raise ValueError("Unsupported identifier types")
        if self.enabled and any(
            value is None or (isinstance(value, str) and not value.strip())
            for value in (
                self.idp_metadata_file,
                self.entity_id,
                self.audience,
                self.acs_url,
                self.service_uuid,
                self.decryption_key_file,
                self.decryption_certificate_file,
            )
        ):
            raise ValueError("Enabled SAML requires all integration settings")
        return self

    def resolve_paths(self, directory: Path) -> None:
        for name in (
            "idp_metadata_file",
            "decryption_key_file",
            "decryption_certificate_file",
        ):
            path = getattr(self, name)
            if path is not None and not path.is_absolute():
                setattr(self, name, directory / path)


class Config(BaseModel):
    app: ConfigApp
    logging: ConfigLogging = Field(default_factory=ConfigLogging)
    uvicorn: ConfigUvicorn
    saml: ConfigSaml = Field(default_factory=ConfigSaml)


def read_ini_file(path: str) -> Any:
    ini_data = configparser.ConfigParser()
    ini_data.read(path)

    ret = {}
    for section in ini_data.sections():
        ret[section] = dict(ini_data[section])
        remove_empty_values(ret[section])
    return ret


def remove_empty_values(section: dict[str, Any]) -> None:
    for key in list(section.keys()):
        if section[key] == "":
            del section[key]


def reset_config() -> None:
    global _CONFIG
    _CONFIG = None


def set_config(config: Config) -> None:
    global _CONFIG
    _CONFIG = config


def get_config(path: str | None = None) -> Config:
    global _CONFIG

    if _CONFIG is not None:
        return _CONFIG

    if path is None:
        path = os.environ.get(_ENVIRONMENT_CONFIG_PATH_NAME) or _PATH

    # To be inline with other python code, we use INI-type files for configuration. Since this isn't
    # a standard format for pydantic, we need to do some manual parsing first.
    ini_data = read_ini_file(path)

    _CONFIG = Config.model_validate(ini_data)
    _CONFIG.saml.resolve_paths(Path(path).resolve().parent)

    return _CONFIG
