from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from lxml import etree

from app.saml.signatures import verify_signature
from app.saml.trust import load_material
from app.saml.xml import NS
from tests.saml_helpers import ISSUER, instant, make_bundle, sign, signed_artifact


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
    "field", ["decryption_key_file", "decryption_certificate_file"]
)
@pytest.mark.parametrize("exists", [False, True], ids=["missing", "malformed"])
def test_unreadable_or_malformed_pem_keeps_generic_error(
    tmp_path: Path, field: str, exists: bool
) -> None:
    bundle = make_bundle(tmp_path)
    bad_pem = tmp_path / "invalid.pem"
    if exists:
        bad_pem.write_bytes(b"synthetic non-PEM input")
    config = bundle.config.model_copy(update={field: bad_pem})

    with pytest.raises(
        ValueError, match="^Invalid SAML key or metadata configuration$"
    ) as error:
        load_material(config)

    assert error.type is ValueError
    assert error.value.__context__ is None
    assert error.value.__cause__ is None


@pytest.mark.parametrize(
    "layout", ["name_first", "certificate_first", "extra_first", "extra_last"]
)
@pytest.mark.parametrize("with_valid_key", [False, True])
def test_rejects_usable_signing_descriptor_with_multiple_keyinfos(
    tmp_path: Path, layout: str, with_valid_key: bool
) -> None:
    bundle = make_bundle(tmp_path)
    metadata_file = bundle.config.idp_metadata_file
    assert metadata_file is not None
    metadata = etree.parse(metadata_file).getroot()
    descriptor = metadata.find("./md:IDPSSODescriptor", NS)
    key = descriptor.find("./md:KeyDescriptor", NS)
    if with_valid_key:
        valid = deepcopy(key)
        valid.find("./ds:KeyInfo/ds:KeyName", NS).text = "standby"
        descriptor.append(valid)
    info = key.find("./ds:KeyInfo", NS)
    extra = etree.Element(etree.QName(NS["ds"], "KeyInfo"))
    if layout == "name_first":
        extra.append(info.find("./ds:X509Data", NS))
        key.append(extra)
    elif layout == "certificate_first":
        extra.append(info.find("./ds:KeyName", NS))
        key.append(extra)
    elif layout == "extra_first":
        key.insert(0, extra)
    else:
        key.append(extra)
    metadata_file.write_bytes(etree.tostring(metadata))

    with pytest.raises(
        ValueError, match="^Invalid SAML key or metadata configuration$"
    ):
        load_material(bundle.config)


@pytest.mark.parametrize(
    "layout", ["no_keyinfo", "two_without_names", "blank_name", "two_blank_names"]
)
def test_ignores_unusable_unnamed_signing_descriptors(
    tmp_path: Path, layout: str
) -> None:
    bundle = make_bundle(tmp_path)
    metadata_file = bundle.config.idp_metadata_file
    assert metadata_file is not None
    metadata = etree.parse(metadata_file).getroot()
    descriptor = metadata.find("./md:IDPSSODescriptor", NS)
    unnamed = deepcopy(descriptor.find("./md:KeyDescriptor", NS))
    info = unnamed.find("./ds:KeyInfo", NS)
    name = info.find("./ds:KeyName", NS)
    if layout == "no_keyinfo":
        unnamed.remove(info)
    else:
        if layout == "two_without_names":
            info.remove(name)
        else:
            name.text = " \t "
        extra = etree.SubElement(unnamed, etree.QName(NS["ds"], "KeyInfo"))
        if layout == "two_blank_names":
            etree.SubElement(extra, etree.QName(NS["ds"], "KeyName")).text = " "
    descriptor.append(unnamed)
    metadata_file.write_bytes(etree.tostring(metadata))

    material = load_material(bundle.config)
    assert set(material.active_certificates(datetime.now(UTC))) == {"test-signer"}


def test_loads_distinct_named_signing_keys_for_rollover(tmp_path: Path) -> None:
    current = make_bundle(tmp_path / "current")
    replacement = make_bundle(tmp_path / "replacement")
    current_file = current.config.idp_metadata_file
    replacement_file = replacement.config.idp_metadata_file
    assert current_file is not None and replacement_file is not None
    metadata = etree.parse(current_file).getroot()
    replacement_metadata = etree.parse(replacement_file).getroot()
    replacement_key = replacement_metadata.find(
        "./md:IDPSSODescriptor/md:KeyDescriptor", NS
    )
    replacement_key.find("./ds:KeyInfo/ds:KeyName", NS).text = "next-signer"
    metadata.find("./md:IDPSSODescriptor", NS).append(replacement_key)
    current_file.write_bytes(etree.tostring(metadata))

    material = load_material(current.config)
    active = material.active_certificates(datetime.now(UTC))
    assert active == {
        "test-signer": current.signing_certificate.public_bytes(
            serialization.Encoding.PEM
        ),
        "next-signer": replacement.signing_certificate.public_bytes(
            serialization.Encoding.PEM
        ),
    }
    assert (
        material.key_name
        == current.decrypt_certificate.fingerprint(hashes.SHA256()).hex()
    )

    for bundle, name in ((current, "test-signer"), (replacement, "next-signer")):
        artifact = signed_artifact(bundle)
        assertion = artifact.find("./samlp:Response/saml:Assertion", NS)
        assertion.find("./ds:Signature/ds:KeyInfo/ds:KeyName", NS).text = name
        artifact.remove(artifact.find("./ds:Signature", NS))
        sign(artifact, bundle)
        artifact = etree.fromstring(etree.tostring(artifact))
        artifact.find("./ds:Signature/ds:KeyInfo/ds:KeyName", NS).text = name
        verify_signature(artifact, active)
        verify_signature(artifact.find("./samlp:Response/saml:Assertion", NS), active)


def test_large_local_metadata_is_not_rejected_by_application_limit(
    tmp_path: Path,
) -> None:
    bundle = make_bundle(tmp_path)
    metadata_file = bundle.config.idp_metadata_file
    assert metadata_file is not None
    comment = b"<!--" + b"x" * 1024 + b"-->"
    with metadata_file.open("ab") as metadata:
        metadata.write(comment * 10_241)
    assert metadata_file.stat().st_size > 10_485_760
    assert load_material(bundle.config).issuer == ISSUER


def test_cache_duration_only_metadata_remains_unsupported(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    metadata_file = bundle.config.idp_metadata_file
    assert metadata_file is not None
    root = etree.parse(metadata_file).getroot()
    del root.attrib["validUntil"]
    root.set("cacheDuration", "PT24H")
    metadata_file.write_bytes(etree.tostring(root))
    with pytest.raises(
        ValueError, match="^Invalid SAML key or metadata configuration$"
    ):
        load_material(bundle.config)


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
