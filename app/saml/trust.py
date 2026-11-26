"""Read operator-provisioned metadata and local decryption material."""

import base64
import binascii
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.config import ConfigSaml
from app.saml.errors import debug_active_exception, raise_sanitized
from app.saml.xml import NS, one, parse_xml, qualified_tag, text


def utc_time(value: str | None) -> datetime:
    if not value:
        raise ValueError("Invalid SAML time")
    try:
        result = datetime.fromisoformat(value)
        if result.tzinfo is None or result.utcoffset() is None:
            raise ValueError
        return result.astimezone(UTC)
    except (ValueError, OverflowError):
        debug_active_exception()
        raise ValueError("Invalid SAML time") from None


def certificate_is_current(cert: x509.Certificate, now: datetime) -> bool:
    return cert.not_valid_before_utc <= now < cert.not_valid_after_utc


def check_rsa_certificate(cert: x509.Certificate) -> None:
    public_key = cert.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 2048:
        raise ValueError("Invalid SAML certificate")


@dataclass(frozen=True)
class SamlMaterial:
    issuer: str
    certificates: dict[str, bytes]
    signing_certificates: dict[str, x509.Certificate]
    private_key: rsa.RSAPrivateKey
    decryption_certificate: x509.Certificate
    key_name: str
    valid_until: datetime

    def active_certificates(self, now: datetime) -> dict[str, bytes]:
        if now >= self.valid_until or not certificate_is_current(
            self.decryption_certificate, now
        ):
            raise ValueError("Expired SAML configuration")
        active = {
            name: self.certificates[name]
            for name, cert in self.signing_certificates.items()
            if certificate_is_current(cert, now)
        }
        if not active:
            raise ValueError("Expired SAML configuration")
        return active


def _read_rsa_private_key(path: Path) -> rsa.RSAPrivateKey:
    private_key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size < 2048:
        raise ValueError("Invalid SAML key")
    return private_key


def load_material(config: ConfigSaml) -> SamlMaterial:
    try:
        return _load_material(config)
    except (OSError, ValueError, TypeError, binascii.Error):
        raise_sanitized(ValueError("Invalid SAML key or metadata configuration"))


def _load_material(config: ConfigSaml) -> SamlMaterial:
    key_path = config.decryption_key_file
    cert_path = config.decryption_certificate_file
    if (
        config.idp_metadata_file is None
        or not isinstance(key_path, Path)
        or not isinstance(cert_path, Path)
    ):
        raise ValueError("Missing SAML configuration")
    private_key = _read_rsa_private_key(key_path)
    decrypt_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    check_rsa_certificate(decrypt_cert)
    if private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) != decrypt_cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ):
        raise ValueError("Mismatched SAML key")

    metadata = parse_xml(config.idp_metadata_file.read_bytes())
    if metadata.tag == qualified_tag("md:EntityDescriptor"):
        entity = metadata
    elif metadata.tag == qualified_tag("md:EntitiesDescriptor"):
        entities = metadata.findall("./md:EntityDescriptor[md:IDPSSODescriptor]", NS)
        if len(entities) != 1:
            raise ValueError("Ambiguous SAML metadata")
        entity = entities[0]
    else:
        raise ValueError("Invalid SAML metadata")
    issuer = entity.get("entityID")
    if not issuer or not issuer.strip():
        raise ValueError("Invalid SAML metadata")
    descriptor = one(entity, "./md:IDPSSODescriptor")
    validity = [
        utc_time(node.get("validUntil"))
        for node in (metadata, entity, descriptor)
        if node.get("validUntil") is not None
    ]
    if not validity:
        raise ValueError("Invalid SAML metadata")
    certificates: dict[str, bytes] = {}
    signing_certificates: dict[str, x509.Certificate] = {}
    for key in descriptor.findall("./md:KeyDescriptor", NS):
        if key.get("use") not in (None, "signing"):
            continue
        names = key.findall("./ds:KeyInfo/ds:KeyName", NS)
        if not any("".join(name.itertext()).strip() for name in names):
            continue
        info = one(key, "./ds:KeyInfo")
        names = info.findall("./ds:KeyName", NS)
        if len(names) != 1 or names[0].xpath("*"):
            raise ValueError("Ambiguous SAML key name")
        # XML comments split .text; preserve the complete KeyName string.
        name = "".join(names[0].itertext())
        if name in certificates:
            raise ValueError("Ambiguous SAML key name")
        encoded = text(info, "./ds:X509Data/ds:X509Certificate")
        certificate = x509.load_der_x509_certificate(
            base64.b64decode("".join(encoded.split()), validate=True)
        )
        check_rsa_certificate(certificate)
        try:
            usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
            if not usage.digital_signature:
                raise ValueError("Invalid SAML signing certificate")
        except x509.ExtensionNotFound:
            pass
        certificates[name] = certificate.public_bytes(serialization.Encoding.PEM)
        signing_certificates[name] = certificate
    material = SamlMaterial(
        issuer=issuer,
        certificates=certificates,
        signing_certificates=signing_certificates,
        private_key=private_key,
        decryption_certificate=decrypt_cert,
        key_name=config.decryption_key_name
        or decrypt_cert.fingerprint(hashes.SHA256()).hex(),
        valid_until=min(validity),
    )
    material.active_certificates(datetime.now(UTC))
    return material
