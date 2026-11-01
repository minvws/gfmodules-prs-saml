from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from lxml import etree

from app.saml.trust import load_material
from app.saml.xml import NS
from tests.saml_helpers import ISSUER, instant, make_bundle


def test_loads_local_key_and_trusted_metadata(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    material = load_material(bundle.config)
    assert material.issuer == ISSUER
    assert (
        material.key_name
        == bundle.decrypt_certificate.fingerprint(hashes.SHA256()).hex()
    )
    assert set(material.certificates) == {"test-signer"}
    assert (
        material.private_key.public_key().public_numbers()
        == bundle.decrypt_key.public_key().public_numbers()
    )


@pytest.mark.parametrize(
    "change", ["expired", "missing_expiry", "no_signing_key", "duplicate_name"]
)
def test_rejects_invalid_trusted_metadata(tmp_path: Path, change: str) -> None:
    bundle = make_bundle(tmp_path)
    assert bundle.config.idp_metadata_file is not None
    root = etree.parse(bundle.config.idp_metadata_file).getroot()
    if change == "expired":
        root.set("validUntil", instant(-1))
    elif change == "missing_expiry":
        del root.attrib["validUntil"]
    elif change == "no_signing_key":
        root.find(".//md:KeyDescriptor", NS).set("use", "encryption")
    else:
        descriptor = root.find("./md:IDPSSODescriptor", NS)
        descriptor.append(etree.fromstring(etree.tostring(descriptor[0])))
    bundle.config.idp_metadata_file.write_bytes(etree.tostring(root))
    with pytest.raises(ValueError):
        load_material(bundle.config)


def test_rejects_key_and_certificate_mismatch(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    other = make_bundle(tmp_path / "other")
    bundle.config.decryption_key_file = other.config.decryption_key_file
    with pytest.raises(ValueError):
        load_material(bundle.config)


def test_rejects_expired_idp_role_even_when_entity_is_current(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    assert bundle.config.idp_metadata_file is not None
    root = etree.parse(bundle.config.idp_metadata_file).getroot()
    root.find("./md:IDPSSODescriptor", NS).set("validUntil", instant(-1))
    bundle.config.idp_metadata_file.write_bytes(etree.tostring(root))
    with pytest.raises(ValueError):
        load_material(bundle.config)
