"""Synthetic end-to-end SAML processing without Python file writes."""

import os
import sys
from typing import Any


def _reject_write_opens(event: str, args: tuple[Any, ...]) -> None:
    if event != "open":
        return
    _, mode, flags = args
    write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
    temporary_file = getattr(os, "O_TMPFILE", 0)
    if (
        (isinstance(mode, str) and any(char in mode for char in "wax+"))
        or (isinstance(flags, int) and bool(flags & write_flags))
        or (
            temporary_file
            and isinstance(flags, int)
            and flags & temporary_file == temporary_file
        )
    ):
        raise PermissionError("Probe forbids write-capable opens")


# Install before importing the service, crypto libraries and test fixtures.
sys.addaudithook(_reject_write_opens)

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import xmlsec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree

from app.config import ConfigSaml
from app.saml.decryption import _name_id
from app.saml.errors import SamlFailureReason, SamlRejected
from app.saml.service import SamlService
from app.saml.signatures import verify_signature
from app.saml.trust import SamlMaterial
from app.saml.xml import NS
from tests.saml_helpers import (
    ACS,
    AUDIENCE,
    BSN,
    ENTITY,
    ISSUER,
    LOA,
    NAMEID,
    SERVICE,
    Bundle,
    certificate,
    encrypted_identifier,
    message,
    signed_artifact,
    soap_message,
)


def _require(condition: bool) -> None:
    """Keep probe checks active even when Python optimization is enabled."""
    if not condition:
        raise AssertionError("In-memory probe check failed")


def _in_memory_bundle() -> tuple[Bundle, SamlMaterial]:
    signer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    decrypt_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sign_cert = certificate(signer)
    decrypt_cert = certificate(decrypt_key)
    # Paths satisfy configuration validation; load_material is replaced below
    # and no key, certificate or metadata is written to or loaded from them.
    config = ConfigSaml(
        enabled=True,
        idp_metadata_file=Path("in-memory-metadata"),
        entity_id=ENTITY,
        audience=AUDIENCE,
        acs_url=ACS,
        service_uuid=SERVICE,
        decryption_key_file=Path("in-memory-key"),
        decryption_certificate_file=Path("in-memory-certificate"),
        clock_skew_seconds=0,
    )
    material = SamlMaterial(
        issuer=ISSUER,
        certificates={
            "test-signer": sign_cert.public_bytes(serialization.Encoding.PEM)
        },
        signing_certificates={"test-signer": sign_cert},
        private_key=decrypt_key,
        decryption_certificate=decrypt_cert,
        key_name=decrypt_cert.fingerprint(hashes.SHA256()).hex(),
        valid_until=datetime.now(UTC) + timedelta(hours=1),
    )
    return Bundle(config, signer, sign_cert, decrypt_key, decrypt_cert), material


def _encrypted_message(
    bundle: Bundle, material: SamlMaterial, key: rsa.RSAPrivateKey, plaintext: bytes
) -> str:
    def replace_identifier(root: etree._Element) -> None:
        value = root.find(
            "./samlp:Response/saml:Assertion/saml:AttributeStatement/"
            "saml:Attribute[@Name='urn:nl-eid-gdi:1.0:ActingSubjectID']/"
            "saml:AttributeValue",
            NS,
        )
        if value is None:
            raise ValueError("Invalid synthetic fixture")
        original = value.find("./saml:EncryptedID", NS)
        if original is None:
            raise ValueError("Invalid synthetic fixture")
        value.replace(
            original,
            encrypted_identifier(
                key, plaintext=plaintext, recipient=ENTITY, key_name=material.key_name
            ),
        )

    return message(bundle, replace_identifier)


def _expect_rejected(
    service: SamlService, encoded: str, reason: SamlFailureReason
) -> None:
    try:
        service.decrypt(encoded)
    except SamlRejected as error:
        _require(error.reason is reason)
        _require(str(error) == "Invalid SAML response")
        _require(error.__cause__ is None and error.__context__ is None)
    else:
        raise AssertionError("Expected rejection")


def main() -> None:
    bundle, material = _in_memory_bundle()
    with patch("app.saml.service.load_material", return_value=material):
        service = SamlService(bundle.config)

    result = service.decrypt(message(bundle))
    _require(
        result.model_dump(exclude_none=True)
        == {"personalId": "NL:bsn:" + BSN, "authnContextClassRef": LOA}
    )

    malformed = _encrypted_message(
        bundle, material, bundle.decrypt_key, b"<NameID>synthetic-invalid<"
    )
    with patch("app.saml.decryption._name_id", wraps=_name_id) as parse_plaintext:
        _expect_rejected(service, malformed, SamlFailureReason.DECRYPTION_FAILED)
    _require(parse_plaintext.call_count == 1)

    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_key_message = _encrypted_message(bundle, material, wrong_key, NAMEID)
    with patch(
        "app.saml.decryption.xmlsec.EncryptionContext",
        wraps=xmlsec.EncryptionContext,
    ) as encryption_context:
        _expect_rejected(
            service, wrong_key_message, SamlFailureReason.DECRYPTION_FAILED
        )
    _require(encryption_context.call_count == 1)

    artifact = signed_artifact(bundle)
    issuer = artifact.find("./saml:Issuer", NS)
    if issuer is None:
        raise ValueError("Invalid synthetic fixture")
    issuer.text = "urn:test:tampered"
    with patch("app.saml.service.verify_signature", wraps=verify_signature) as verify:
        _expect_rejected(
            service,
            soap_message(artifact),
            SamlFailureReason.SIGNATURE_FAILED,
        )
    _require(verify.call_count == 1)

    print("probe-ok")


if __name__ == "__main__":
    try:
        main()
    except BaseException:  # noqa: BLE001 - keep probe failures free of sensitive data
        # Do not print input, keys, library errors or traceback locals on failure.
        raise SystemExit("probe-failed") from None
