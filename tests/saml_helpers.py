"""Generated test material; no operational keys or personal data."""

import base64
import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import xmlsec
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID
from lxml import etree

from app.config import ConfigSaml
from app.saml.xml import NS

ISSUER = "urn:test:tvs"
ENTITY = "urn:test:prs"
AUDIENCE = "urn:test:audience"
ACS = "https://consumer.example.nl/acs"
SERVICE = "00000000-0000-0000-0000-000000000001"
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
LOA = "http://eidas.europa.eu/LoA/high"
BSN = "950000012"
SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/"
SOAP12 = "http://www.w3.org/2003/05/soap-envelope"

RECIPIENT = "urn:test:recipient"
KEY_NAME = "test-certificate-fingerprint"
NAMEID = (
    b'<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
    b'Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" '
    b'NameQualifier="urn:nl-eid-gdi:1.0:id:legacy-BSN">950000012</saml:NameID>'
)
OAEP = NS["xenc"] + "rsa-oaep-mgf1p"
OAEP11 = NS["xenc11"] + "rsa-oaep"
DIGESTS = {
    "sha1": NS["ds"] + "sha1",
    "sha256": NS["xenc"] + "sha256",
    "sha384": "http://www.w3.org/2001/04/xmldsig-more#sha384",
    "sha512": NS["xenc"] + "sha512",
}
HASHES: dict[str, Callable[[], hashes.HashAlgorithm]] = {
    "sha1": hashes.SHA1,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


def instant(offset: int = 0) -> str:
    return (datetime.now(UTC) + timedelta(seconds=offset)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def certificate(key: rsa.RSAPrivateKey) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ephemeral-test")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


def pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


@dataclass
class Bundle:
    config: ConfigSaml
    signer: rsa.RSAPrivateKey
    signing_certificate: x509.Certificate
    decrypt_key: rsa.RSAPrivateKey
    decrypt_certificate: x509.Certificate


def make_bundle(directory: Path) -> Bundle:
    directory.mkdir(parents=True, exist_ok=True)
    signer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    decrypt_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sign_cert, decrypt_cert = certificate(signer), certificate(decrypt_key)
    key_file, cert_file, metadata_file = (
        directory / "decrypt.key",
        directory / "decrypt.crt",
        directory / "metadata.xml",
    )
    key_file.write_bytes(pem(decrypt_key))
    cert_file.write_bytes(decrypt_cert.public_bytes(serialization.Encoding.PEM))
    metadata = etree.Element(
        etree.QName(NS["md"], "EntityDescriptor"),
        entityID=ISSUER,
        validUntil=instant(86400),
        nsmap=NS,
    )
    descriptor = etree.SubElement(metadata, etree.QName(NS["md"], "IDPSSODescriptor"))
    key_descriptor = etree.SubElement(
        descriptor, etree.QName(NS["md"], "KeyDescriptor"), use="signing"
    )
    info = etree.SubElement(key_descriptor, etree.QName(NS["ds"], "KeyInfo"))
    etree.SubElement(info, etree.QName(NS["ds"], "KeyName")).text = "test-signer"
    cert_data = etree.SubElement(info, etree.QName(NS["ds"], "X509Data"))
    etree.SubElement(
        cert_data, etree.QName(NS["ds"], "X509Certificate")
    ).text = base64.b64encode(
        sign_cert.public_bytes(serialization.Encoding.DER)
    ).decode()
    metadata_file.write_bytes(etree.tostring(metadata))
    config = ConfigSaml(
        enabled=True,
        idp_metadata_file=metadata_file,
        entity_id=ENTITY,
        audience=AUDIENCE,
        acs_url=ACS,
        service_uuid=SERVICE,
        decryption_key_file=key_file,
        decryption_certificate_file=cert_file,
        clock_skew_seconds=0,
    )
    return Bundle(config, signer, sign_cert, decrypt_key, decrypt_cert)


def sign(element: etree._Element, bundle: Bundle) -> None:
    signature = xmlsec.template.create(
        element,
        xmlsec.constants.TransformExclC14N,
        xmlsec.constants.TransformRsaSha256,
        ns="ds",
    )
    element.insert(1, signature)
    reference = xmlsec.template.add_reference(
        signature, xmlsec.constants.TransformSha256, uri="#" + element.attrib["ID"]
    )
    xmlsec.template.add_transform(reference, xmlsec.constants.TransformEnveloped)
    xmlsec.template.add_transform(reference, xmlsec.constants.TransformExclC14N)
    key_info = xmlsec.template.ensure_key_info(signature)
    xmlsec.template.add_key_name(key_info).text = "test-signer"
    xmlsec.tree.add_ids(element, ["ID"])
    context = xmlsec.SignatureContext()
    context.key = xmlsec.Key.from_memory(
        pem(bundle.signer), xmlsec.constants.KeyDataFormatPem
    )
    context.sign(signature)


def sub(parent: Any, prefix: str, name: str, **attributes: str) -> Any:
    return etree.SubElement(parent, etree.QName(NS[prefix], name), **attributes)


def encrypted_identifier(
    private_key: rsa.RSAPrivateKey,
    *,
    plaintext: bytes = NAMEID,
    transport: str = OAEP,
    digest: str | None = "sha256",
    mgf: str | None = None,
    label: bytes | None = None,
    content_key: bytes | None = None,
    padding_byte: int | None = None,
    recipient: str = RECIPIENT,
    key_name: str = KEY_NAME,
    data_id: str = "data-1",
    key_id: str | None = "key-1",
    random_padding: bool = False,
) -> Any:
    """Build ciphertext independently from the decryption implementation."""
    identifier = etree.Element(etree.QName(NS["saml"], "EncryptedID"), nsmap=NS)
    data = sub(
        identifier, "xenc", "EncryptedData", Id=data_id, Type=NS["xenc"] + "Element"
    )
    sub(data, "xenc", "EncryptionMethod", Algorithm=NS["xenc"] + "aes256-cbc")
    data_cipher = sub(data, "xenc", "CipherData")
    key = os.urandom(32) if content_key is None else content_key
    iv = os.urandom(16)
    padding_length = 16 - len(plaintext) % 16
    # XMLENC permits arbitrary pad bytes; only the final byte encodes length.
    filler_size = padding_length - 1
    filler = os.urandom(filler_size) if random_padding else b"\xa5" * filler_size
    padded = plaintext + filler
    padded += bytes([padding_length if padding_byte is None else padding_byte])
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = iv + encryptor.update(padded) + encryptor.finalize()
    sub(data_cipher, "xenc", "CipherValue").text = base64.b64encode(ciphertext).decode()

    encrypted_key = sub(identifier, "xenc", "EncryptedKey", Recipient=recipient)
    if key_id is not None:
        encrypted_key.set("Id", key_id)
    method = sub(encrypted_key, "xenc", "EncryptionMethod", Algorithm=transport)
    if label is not None:
        sub(method, "xenc", "OAEPparams").text = base64.b64encode(label).decode()
    if digest is not None:
        sub(method, "ds", "DigestMethod", Algorithm=DIGESTS[digest])
    if mgf is not None:
        sub(method, "xenc11", "MGF", Algorithm=NS["xenc11"] + "mgf1" + mgf)
    sub(sub(encrypted_key, "ds", "KeyInfo"), "ds", "KeyName").text = key_name
    key_cipher = sub(encrypted_key, "xenc", "CipherData")
    wrapped = private_key.public_key().encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(HASHES[mgf or "sha1"]()),
            algorithm=HASHES[digest or "sha1"](),
            label=label,
        ),
    )
    sub(key_cipher, "xenc", "CipherValue").text = base64.b64encode(wrapped).decode()
    return identifier


def signed_artifact(
    bundle: Bundle, mutate: Callable[[etree._Element], None] | None = None
) -> etree._Element:
    root = etree.fromstring(
        f'''<samlp:ArtifactResponse xmlns:samlp="{NS["samlp"]}" xmlns:saml="{NS["saml"]}" ID="_artifact" Version="2.0" IssueInstant="{instant()}" InResponseTo="_resolve">
      <saml:Issuer>{ISSUER}</saml:Issuer>
      <samlp:Status><samlp:StatusCode Value="{SUCCESS}"/></samlp:Status>
      <samlp:Response ID="_response" Version="2.0" IssueInstant="{instant()}" InResponseTo="_authn" Destination="{ACS}">
        <saml:Issuer>{ISSUER}</saml:Issuer>
        <samlp:Status><samlp:StatusCode Value="{SUCCESS}"/></samlp:Status>
        <saml:Assertion ID="_assertion" Version="2.0" IssueInstant="{instant()}">
          <saml:Issuer>{ISSUER}</saml:Issuer>
          <saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_transient</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="{ACS}" InResponseTo="_authn" NotOnOrAfter="{instant(120)}"/></saml:SubjectConfirmation></saml:Subject>
          <saml:Conditions NotBefore="{instant(-10)}" NotOnOrAfter="{instant(120)}"><saml:AudienceRestriction><saml:Audience>{AUDIENCE}</saml:Audience></saml:AudienceRestriction></saml:Conditions>
          <saml:Advice/>
          <saml:AuthnStatement AuthnInstant="{instant()}"><saml:AuthnContext><saml:AuthnContextClassRef>{LOA}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>
          <saml:AttributeStatement><saml:Attribute Name="urn:nl-eid-gdi:1.0:ServiceUUID"><saml:AttributeValue>{SERVICE}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="urn:nl-eid-gdi:1.0:ActingSubjectID"><saml:AttributeValue/></saml:Attribute></saml:AttributeStatement>
        </saml:Assertion>
      </samlp:Response>
    </samlp:ArtifactResponse>'''.encode()
    )
    assertion = root.find("./samlp:Response/saml:Assertion", NS)
    assert assertion is not None
    attribute = assertion.find(
        "./saml:AttributeStatement/saml:Attribute[@Name='urn:nl-eid-gdi:1.0:ActingSubjectID']/saml:AttributeValue",
        NS,
    )
    assert attribute is not None
    attribute.append(
        encrypted_identifier(
            bundle.decrypt_key,
            digest=None,
            recipient=ENTITY,
            key_name=bundle.decrypt_certificate.fingerprint(hashes.SHA256()).hex(),
            data_id="_encrypted",
            key_id=None,
            random_padding=True,
        )
    )
    if mutate is not None:
        mutate(root)
    sign(assertion, bundle)
    sign(root, bundle)
    # Tests verify parsed XML, not the native tree used to build the signatures.
    return etree.fromstring(etree.tostring(root))


def soap_message(
    artifact: etree._Element, namespace: str = SOAP11, *, xml_declaration: bool = False
) -> str:
    """Place a synthetic artifact in a SOAP envelope and encode the request."""
    envelope = etree.Element(
        etree.QName(namespace, "Envelope"), nsmap={"soap": namespace}
    )
    etree.SubElement(envelope, etree.QName(namespace, "Body")).append(artifact)
    return base64.b64encode(
        etree.tostring(envelope, encoding="UTF-8", xml_declaration=xml_declaration)
    ).decode()


def message(
    bundle: Bundle,
    mutate: Callable[[etree._Element], None] | None = None,
) -> str:
    return soap_message(signed_artifact(bundle, mutate))


def artifact_from_message(encoded: str) -> etree._Element:
    """Inspect the artifact of a test message without running the receiver."""
    envelope = etree.fromstring(base64.b64decode(encoded))
    namespace = etree.QName(envelope).namespace
    artifact = envelope.find(f"./{{{namespace}}}Body/samlp:ArtifactResponse", NS)
    assert artifact is not None
    return artifact
