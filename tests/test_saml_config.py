from pathlib import Path

import pytest
from pydantic import ValidationError

from app.config import Config, ConfigSaml, get_config, reset_config


def test_saml_is_disabled_without_configuration() -> None:
    assert not ConfigSaml().enabled


def test_obsolete_identifier_types_setting_is_ignored() -> None:
    config = ConfigSaml.model_validate(
        {"accepted_identifier_types": "urn:test:unsupported"}
    )
    assert "accepted_identifier_types" not in config.model_dump()


def test_enabled_saml_requires_integration_settings() -> None:
    with pytest.raises(ValidationError):
        ConfigSaml(enabled=True)


def test_audience_is_separate_from_decryption_recipient() -> None:
    config = ConfigSaml(
        enabled=True,
        idp_metadata_file=Path("metadata.xml"),
        entity_id="decryption-recipient",
        audience="expected-audience",
        acs_url="https://consumer.example.nl/acs",
        service_uuid="00000000-0000-0000-0000-000000000001",
        decryption_key_file=Path("decrypt.key"),
        decryption_certificate_file=Path("decrypt.crt"),
    )
    assert config.audience == "expected-audience"
    assert config.entity_id == "decryption-recipient"


def test_saml_paths_resolve_during_validation(tmp_path: Path) -> None:
    config = Config.model_validate(
        {
            "app": {},
            "uvicorn": {},
            "saml": {
                "enabled": True,
                "entity_id": "decryption-recipient",
                "audience": "expected-audience",
                "acs_url": "https://consumer.example.nl/acs",
                "service_uuid": "00000000-0000-0000-0000-000000000001",
                "idp_metadata_file": "trust/metadata.xml",
                "decryption_key_file": "keys/decrypt.key",
                "decryption_certificate_file": "keys/decrypt.crt",
            },
        },
        context={"ini_dir": tmp_path},
    )

    assert config.saml.idp_metadata_file == tmp_path / "trust/metadata.xml"
    assert config.saml.decryption_key_file == tmp_path / "keys/decrypt.key"
    assert config.saml.decryption_certificate_file == tmp_path / "keys/decrypt.crt"


def test_saml_validation_preserves_absolute_and_missing_paths(tmp_path: Path) -> None:
    absolute = tmp_path / "other" / "decrypt.key"
    config = ConfigSaml.model_validate(
        {"decryption_key_file": absolute},
        context={"ini_dir": tmp_path / "config"},
    )

    assert config.decryption_key_file == absolute
    assert config.idp_metadata_file is None
    assert config.decryption_certificate_file is None


def test_saml_paths_remain_relative_without_ini_context() -> None:
    path = Path("keys/decrypt.key")
    assert ConfigSaml(decryption_key_file=path).decryption_key_file == path


def test_saml_paths_are_relative_to_ini_file(tmp_path: Path) -> None:
    ini = tmp_path / "app.conf"
    ini.write_text(
        "[app]\n[uvicorn]\n[saml]\n"
        "idp_metadata_file=secrets/metadata.xml\n"
        "decryption_key_file=secrets/decrypt.key\n"
        "decryption_certificate_file=secrets/decrypt.crt\n"
    )
    reset_config()
    try:
        config = get_config(str(ini))
        assert config.saml.decryption_key_file == tmp_path / "secrets/decrypt.key"
        assert config.saml.idp_metadata_file == tmp_path / "secrets/metadata.xml"
        assert (
            config.saml.decryption_certificate_file == tmp_path / "secrets/decrypt.crt"
        )
    finally:
        reset_config()


def test_saml_clock_skew_cannot_be_negative() -> None:
    with pytest.raises(ValidationError):
        ConfigSaml(clock_skew_seconds=-1)


def test_saml_clock_skew_cannot_disable_time_checks() -> None:
    with pytest.raises(ValidationError):
        ConfigSaml(clock_skew_seconds=86400)
