"""Generated test material; no operational keys or personal data."""

import base64
import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

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


def message(
    bundle: Bundle, mutate: Callable[[etree._Element], None] | None = None
) -> str:
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
          <saml:AuthnStatement AuthnInstant="{instant()}"><saml:AuthnContext><saml:AuthnContextClassRef>{LOA}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>
          <saml:AttributeStatement><saml:Attribute Name="urn:nl-eid-gdi:1.0:ServiceUUID"><saml:AttributeValue>{SERVICE}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="urn:nl-eid-gdi:1.0:ActingSubjectID"><saml:AttributeValue/></saml:Attribute></saml:AttributeStatement>
          <saml:Advice/>
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
    encrypted = etree.SubElement(
        attribute, etree.QName(NS["saml"], "EncryptedID"), nsmap=NS
    )
    data = etree.SubElement(
        encrypted,
        etree.QName(NS["xenc"], "EncryptedData"),
        Id="_encrypted",
        Type="http://www.w3.org/2001/04/xmlenc#Element",
    )
    etree.SubElement(
        data,
        etree.QName(NS["xenc"], "EncryptionMethod"),
        Algorithm=NS["xenc"] + "aes256-cbc",
    )
    content = f'<saml:NameID xmlns:saml="{NS["saml"]}" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" NameQualifier="urn:nl-eid-gdi:1.0:id:legacy-BSN">{BSN}</saml:NameID>'.encode()
    padding_length = 16 - len(content) % 16
    content += os.urandom(padding_length - 1) + bytes([padding_length])
    aes_key, iv = os.urandom(32), os.urandom(16)
    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    cipher_data = etree.SubElement(data, etree.QName(NS["xenc"], "CipherData"))
    etree.SubElement(
        cipher_data, etree.QName(NS["xenc"], "CipherValue")
    ).text = base64.b64encode(
        iv + encryptor.update(content) + encryptor.finalize()
    ).decode()
    key = etree.SubElement(
        encrypted, etree.QName(NS["xenc"], "EncryptedKey"), Recipient=ENTITY
    )
    etree.SubElement(
        key,
        etree.QName(NS["xenc"], "EncryptionMethod"),
        Algorithm=NS["xenc"] + "rsa-oaep-mgf1p",
    )
    info = etree.SubElement(key, etree.QName(NS["ds"], "KeyInfo"))
    etree.SubElement(
        info, etree.QName(NS["ds"], "KeyName")
    ).text = bundle.decrypt_certificate.fingerprint(hashes.SHA256()).hex()
    wrapped = bundle.decrypt_key.public_key().encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None
        ),
    )
    cipher_data = etree.SubElement(key, etree.QName(NS["xenc"], "CipherData"))
    etree.SubElement(
        cipher_data, etree.QName(NS["xenc"], "CipherValue")
    ).text = base64.b64encode(wrapped).decode()
    if mutate is not None:
        mutate(root)
    sign(assertion, bundle)
    sign(root, bundle)
    return base64.b64encode(etree.tostring(root)).decode()
