"""Verify signed SAML elements using real ephemeral signing keys."""

import base64
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import xmlsec
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree

from app.saml.signatures import verify_signature as verify

NS = {
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


def make_signing_material() -> tuple[bytes, bytes, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ephemeral-idp")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .sign(private_key, hashes.SHA256())
    )
    return (
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        certificate.public_bytes(serialization.Encoding.PEM),
        certificate.public_bytes(serialization.Encoding.DER),
    )


@pytest.fixture(scope="module")
def signing_material() -> tuple[bytes, bytes, bytes]:
    return make_signing_material()


@pytest.fixture(scope="module")
def other_signing_material() -> tuple[bytes, bytes, bytes]:
    return make_signing_material()


def signed_element(
    material: tuple[bytes, bytes, bytes],
    *,
    tag: str = "Assertion",
    selector: str = "name",
    signature_method: Any = xmlsec.constants.TransformRsaSha256,
    digest_method: Any = xmlsec.constants.TransformSha256,
    c14n_method: Any = xmlsec.constants.TransformExclC14N,
    reference_count: int = 1,
    reference_id: str = "_signed",
    extra_transform: Any = xmlsec.constants.TransformExclC14N,
) -> etree._Element:
    namespace = NS["saml"] if tag == "Assertion" else NS["samlp"]
    element = etree.Element(f"{{{namespace}}}{tag}", nsmap=NS, ID="_signed")
    etree.SubElement(element, f"{{{NS['saml']}}}Issuer").text = "https://idp.example"
    if reference_id != "_signed":
        etree.SubElement(
            element, f"{{{NS['saml']}}}Advice", ID=reference_id
        ).text = "signed child"
    signature = xmlsec.template.create(element, c14n_method, signature_method, ns="ds")
    element.insert(1, signature)
    for _ in range(reference_count):
        reference = xmlsec.template.add_reference(
            signature, digest_method, uri=f"#{reference_id}"
        )
        xmlsec.template.add_transform(reference, xmlsec.constants.TransformEnveloped)
        if extra_transform is not None:
            transform = xmlsec.template.add_transform(reference, extra_transform)
            if extra_transform == xmlsec.constants.TransformXPath:
                etree.SubElement(transform, f"{{{NS['ds']}}}XPath").text = "true()"
    key_info = xmlsec.template.ensure_key_info(signature)
    if selector == "name":
        xmlsec.template.add_key_name(key_info, "idp-signing")
    elif selector == "certificate":
        data = xmlsec.template.add_x509_data(key_info)
        xmlsec.template.x509_data_add_certificate(data).text = base64.b64encode(
            material[2]
        ).decode()
    elif selector == "keyvalue":
        xmlsec.template.add_key_value(key_info)
    else:
        raise AssertionError("Unknown test key selector")
    context = xmlsec.SignatureContext()
    context.key = xmlsec.Key.from_memory(material[0], xmlsec.constants.KeyDataFormatPem)
    context.key.load_cert_from_memory(material[1], xmlsec.constants.KeyDataFormatPem)
    xmlsec.tree.add_ids(element, ["ID"])
    context.sign(signature)
    # Exercise verification on a fresh parsed tree, as the receiver will.
    return etree.fromstring(etree.tostring(element))


@pytest.mark.parametrize("tag", ["Assertion", "Response", "ArtifactResponse"])
def test_accepts_valid_signature_on_expected_parent(
    signing_material: tuple[bytes, bytes, bytes], tag: str
) -> None:
    element = signed_element(signing_material, tag=tag)
    verify(element, {"idp-signing": signing_material[1]})


def test_requires_explicit_exclusive_reference_canonicalization(
    signing_material: tuple[bytes, bytes, bytes],
) -> None:
    element = signed_element(signing_material, extra_transform=None)
    with pytest.raises(ValueError, match="^Invalid SAML signature$"):
        verify(element, {"idp-signing": signing_material[1]})


def test_accepts_embedded_certificate_only_when_exactly_trusted(
    signing_material: tuple[bytes, bytes, bytes],
) -> None:
    element = signed_element(signing_material, selector="certificate")
    verify(element, {"metadata-key": signing_material[1]})


@pytest.mark.parametrize(
    "signature_method,digest_method",
    [
        (xmlsec.constants.TransformRsaSha384, xmlsec.constants.TransformSha384),
        (xmlsec.constants.TransformRsaSha512, xmlsec.constants.TransformSha512),
    ],
)
def test_accepts_strong_rsa_algorithms(
    signing_material: tuple[bytes, bytes, bytes],
    signature_method: Any,
    digest_method: Any,
) -> None:
    element = signed_element(
        signing_material, signature_method=signature_method, digest_method=digest_method
    )
    verify(element, {"idp-signing": signing_material[1]})


def test_rejects_tampered_signed_content(
    signing_material: tuple[bytes, bytes, bytes],
) -> None:
    element = signed_element(signing_material)
    element.find("saml:Issuer", NS).text = "https://attacker.example"
    with pytest.raises(ValueError, match="^Invalid SAML signature$"):
        verify(element, {"idp-signing": signing_material[1]})


@pytest.mark.parametrize(
    "reference_id,reference_count", [("_child", 1), ("_signed", 2)]
)
def test_rejects_valid_crypto_for_wrong_or_multiple_references(
    signing_material: tuple[bytes, bytes, bytes],
    reference_id: str,
    reference_count: int,
) -> None:
    element = signed_element(
        signing_material, reference_id=reference_id, reference_count=reference_count
    )
    with pytest.raises(ValueError, match="^Invalid SAML signature$"):
        verify(element, {"idp-signing": signing_material[1]})


@pytest.mark.parametrize(
    "uri",
    ["", "https://attacker.example/reference", "file:///etc/passwd", "#xpointer(/)"],
)
def test_rejects_nonlocal_or_nonspecific_reference(
    signing_material: tuple[bytes, bytes, bytes], uri: str
) -> None:
    element = signed_element(signing_material)
    element.find("ds:Signature/ds:SignedInfo/ds:Reference", NS).set("URI", uri)
    with pytest.raises(ValueError, match="^Invalid SAML signature$"):
        verify(element, {"idp-signing": signing_material[1]})


@pytest.mark.parametrize(
    "change", ["missing", "nested", "duplicate", "missing-id", "duplicate-id"]
)
def test_rejects_ambiguous_signature_or_identity(
    signing_material: tuple[bytes, bytes, bytes], change: str
) -> None:
    element = signed_element(signing_material)
    signature = element.find("ds:Signature", NS)
    if change == "missing":
        element.remove(signature)
    elif change == "nested":
        etree.SubElement(element, f"{{{NS['saml']}}}Advice").append(signature)
    elif change == "duplicate":
        element.append(deepcopy(signature))
    elif change == "missing-id":
        del element.attrib["ID"]
    else:
        wrapper = etree.Element("wrapper")
        wrapper.append(element)
        etree.SubElement(wrapper, "other", ID="_signed")
    with pytest.raises(ValueError, match="^Invalid SAML signature$"):
        verify(element, {"idp-signing": signing_material[1]})


@pytest.mark.parametrize("selector", ["name", "certificate", "keyvalue"])
def test_rejects_untrusted_key_material(
    signing_material: tuple[bytes, bytes, bytes], selector: str
) -> None:
    element = signed_element(signing_material, selector=selector)
    with pytest.raises(ValueError, match="^Invalid SAML signature$"):
        verify(element, {})


def test_rejects_unknown_key_name_even_if_another_name_trusts_same_key(
    signing_material: tuple[bytes, bytes, bytes],
) -> None:
    element = signed_element(signing_material)
    with pytest.raises(ValueError, match="^Invalid SAML signature$"):
        verify(element, {"different-metadata-key": signing_material[1]})


@pytest.mark.parametrize("selector", ["name", "certificate"])
def test_rejects_valid_signature_from_another_key(
    signing_material: tuple[bytes, bytes, bytes],
    other_signing_material: tuple[bytes, bytes, bytes],
    selector: str,
) -> None:
    element = signed_element(other_signing_material, selector=selector)
    with pytest.raises(ValueError, match="^Invalid SAML signature$"):
        verify(element, {"idp-signing": signing_material[1]})


def test_rejects_conflicting_key_name_and_embedded_certificate(
    signing_material: tuple[bytes, bytes, bytes],
    other_signing_material: tuple[bytes, bytes, bytes],
) -> None:
    element = signed_element(signing_material)
    key_info = element.find("ds:Signature/ds:KeyInfo", NS)
    data = xmlsec.template.add_x509_data(key_info)
    xmlsec.template.x509_data_add_certificate(data).text = base64.b64encode(
        other_signing_material[2]
    ).decode()
    with pytest.raises(ValueError, match="^Invalid SAML signature$"):
        verify(
            element,
            {"idp-signing": signing_material[1], "other": other_signing_material[1]},
        )


@pytest.mark.parametrize(
    "change", ["missing-keyinfo", "empty-keyinfo", "duplicate-name", "keyvalue"]
)
def test_rejects_missing_or_ambiguous_trusted_selector(
    signing_material: tuple[bytes, bytes, bytes], change: str
) -> None:
    element = signed_element(
        signing_material, selector="keyvalue" if change == "keyvalue" else "name"
    )
    signature = element.find("ds:Signature", NS)
    key_info = signature.find("ds:KeyInfo", NS)
    if change == "missing-keyinfo":
        signature.remove(key_info)
    elif change == "empty-keyinfo":
        key_info.clear()
    elif change == "duplicate-name":
        xmlsec.template.add_key_name(key_info, "idp-signing")
    with pytest.raises(ValueError, match="^Invalid SAML signature$"):
        verify(element, {"idp-signing": signing_material[1]})


def test_rejects_cryptographically_valid_xpath_transform(
    signing_material: tuple[bytes, bytes, bytes],
) -> None:
    element = signed_element(
        signing_material, extra_transform=xmlsec.constants.TransformXPath
    )
    with pytest.raises(ValueError, match="^Invalid SAML signature$"):
        verify(element, {"idp-signing": signing_material[1]})


@pytest.mark.parametrize(
    "signature_method,digest_method",
    [
        (xmlsec.constants.TransformRsaSha1, xmlsec.constants.TransformSha256),
        (xmlsec.constants.TransformRsaSha256, xmlsec.constants.TransformSha1),
    ],
)
def test_rejects_cryptographically_valid_sha1_signatures(
    signing_material: tuple[bytes, bytes, bytes],
    signature_method: Any,
    digest_method: Any,
) -> None:
    element = signed_element(
        signing_material, signature_method=signature_method, digest_method=digest_method
    )
    with pytest.raises(ValueError, match="^Invalid SAML signature$"):
        verify(element, {"idp-signing": signing_material[1]})


@pytest.mark.parametrize(
    "path,algorithm",
    [
        (
            "ds:Signature/ds:SignedInfo/ds:SignatureMethod",
            "http://www.w3.org/2000/09/xmldsig#hmac-sha1",
        ),
        ("ds:Signature/ds:SignedInfo/ds:CanonicalizationMethod", "urn:unsafe:c14n"),
        (
            "ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform",
            "http://www.w3.org/TR/1999/REC-xslt-19991116",
        ),
    ],
)
def test_rejects_unsafe_algorithms(
    signing_material: tuple[bytes, bytes, bytes], path: str, algorithm: str
) -> None:
    element = signed_element(signing_material)
    element.find(path, NS).set("Algorithm", algorithm)
    with pytest.raises(ValueError, match="^Invalid SAML signature$"):
        verify(element, {"idp-signing": signing_material[1]})


def test_rejects_missing_enveloped_transform(
    signing_material: tuple[bytes, bytes, bytes],
) -> None:
    element = signed_element(signing_material)
    transforms = element.find(
        "ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms", NS
    )
    transforms.remove(transforms[0])
    with pytest.raises(ValueError, match="^Invalid SAML signature$"):
        verify(element, {"idp-signing": signing_material[1]})


def test_rejects_remote_key_retrieval(
    signing_material: tuple[bytes, bytes, bytes],
) -> None:
    element = signed_element(signing_material)
    key_info = element.find("ds:Signature/ds:KeyInfo", NS)
    key_info.clear()
    etree.SubElement(
        key_info, f"{{{NS['ds']}}}RetrievalMethod", URI="https://attacker.example/key"
    )
    with pytest.raises(ValueError, match="^Invalid SAML signature$"):
        verify(element, {"idp-signing": signing_material[1]})
