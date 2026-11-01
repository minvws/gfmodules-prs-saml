from pathlib import Path

import pytest
from pydantic import ValidationError

from app.config import ConfigSaml, get_config, reset_config


def test_saml_is_disabled_without_configuration() -> None:
    assert not ConfigSaml().enabled


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
    finally:
        reset_config()


@pytest.mark.parametrize("field", ["clock_skew_seconds", "max_xml_bytes"])
def test_saml_limits_are_bounded(field: str) -> None:
    with pytest.raises(ValidationError):
        ConfigSaml.model_validate({field: -1})


def test_saml_clock_skew_cannot_disable_time_checks() -> None:
    with pytest.raises(ValidationError):
        ConfigSaml(clock_skew_seconds=86400)
