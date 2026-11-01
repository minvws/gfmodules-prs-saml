"""Verify the SAML enveloped-signature profile against pinned metadata keys."""

import base64
import re

import xmlsec
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree

from app.saml.xml import NS

_ERROR = "Invalid SAML signature"
_DS = NS["ds"]
_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
_ENVELOPED = f"{_DS}enveloped-signature"
_RSA_METHODS = {
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": xmlsec.constants.TransformRsaSha256,
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": xmlsec.constants.TransformRsaSha384,
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": xmlsec.constants.TransformRsaSha512,
}
_DIGEST_METHODS = {
    "http://www.w3.org/2001/04/xmlenc#sha256": xmlsec.constants.TransformSha256,
    "http://www.w3.org/2001/04/xmldsig-more#sha384": xmlsec.constants.TransformSha384,
    "http://www.w3.org/2001/04/xmlenc#sha512": xmlsec.constants.TransformSha512,
}
_ID = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*\Z")


def _children(element: etree._Element) -> list[etree._Element]:
    return [child for child in element if isinstance(child.tag, str)]


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError(_ERROR)


def _c14n(element: etree._Element) -> None:
    _require(element.get("Algorithm") == _C14N)
    children = _children(element)
    if children:
        _require(len(children) == 1)
        prefixes = children[0]
        _require(prefixes.tag == f"{{{_C14N}}}InclusiveNamespaces")
        _require(set(prefixes.attrib) == {"PrefixList"} and not _children(prefixes))


def _select_certificate(
    key_info: etree._Element, certificates: dict[str, bytes]
) -> bytes:
    children = _children(key_info)
    names = key_info.findall("ds:KeyName", NS)
    data = key_info.findall("ds:X509Data", NS)
    _require(bool(children) and len(names) <= 1 and len(data) <= 1)
    _require(len(children) == len(names) + len(data))

    selected: bytes | None = None
    if names:
        _require(not _children(names[0]))
        name = names[0].text or ""
        _require(name in certificates)
        selected = certificates[name]

    if data:
        embedded = _children(data[0])
        _require(len(embedded) == 1 and embedded[0].tag == f"{{{_DS}}}X509Certificate")
        _require(not _children(embedded[0]))
        encoded = "".join((embedded[0].text or "").split())
        der = base64.b64decode(encoded, validate=True)
        trusted = [selected] if selected is not None else list(certificates.values())
        selected = next(
            (
                pem
                for pem in trusted
                if x509.load_pem_x509_certificate(pem).public_bytes(
                    serialization.Encoding.DER
                )
                == der
            ),
            None,
        )
        _require(selected is not None)

    _require(selected is not None)
    assert selected is not None
    _require(
        isinstance(
            x509.load_pem_x509_certificate(selected).public_key(), rsa.RSAPublicKey
        )
    )
    return selected


def verify_signature(element: etree._Element, certificates: dict[str, bytes]) -> None:
    """Require one trusted signature covering this exact containing element.

    KeyInfo only selects a certificate already supplied by trusted metadata.
    No embedded key, remote key lookup, or certificate-chain trust is used.
    """
    try:
        element_id = element.get("ID", "")
        _require(_ID.fullmatch(element_id) is not None)
        # Inspect the complete owning document, including siblings/ancestors of
        # an Assertion, before marking this one specific attribute as an ID.
        identities = [
            node
            for node in element.getroottree().getroot().iter()
            for name, value in node.attrib.items()
            if name.rsplit("}", 1)[-1].lower() == "id" and value == element_id
        ]
        _require(len(identities) == 1 and identities[0] is element)

        signatures = element.findall("ds:Signature", NS)
        _require(len(signatures) == 1)
        signature = signatures[0]
        signature_children = _children(signature)
        _require(
            [child.tag for child in signature_children]
            == [
                f"{{{_DS}}}SignedInfo",
                f"{{{_DS}}}SignatureValue",
                f"{{{_DS}}}KeyInfo",
            ]
        )
        signed_info, signature_value, key_info = signature_children
        _require(not _children(signature_value))
        signed_children = _children(signed_info)
        _require(
            [child.tag for child in signed_children]
            == [
                f"{{{_DS}}}CanonicalizationMethod",
                f"{{{_DS}}}SignatureMethod",
                f"{{{_DS}}}Reference",
            ]
        )
        canonicalization, signature_method, reference = signed_children
        _c14n(canonicalization)
        _require(
            signature_method.get("Algorithm") in _RSA_METHODS
            and not _children(signature_method)
        )
        _require(reference.get("URI") == f"#{element_id}")
        _require(len(signature.findall(".//ds:Reference", NS)) == 1)
        reference_children = _children(reference)
        _require(
            [child.tag for child in reference_children]
            == [
                f"{{{_DS}}}Transforms",
                f"{{{_DS}}}DigestMethod",
                f"{{{_DS}}}DigestValue",
            ]
        )
        transforms, digest_method, digest_value = reference_children
        _require(
            digest_method.get("Algorithm") in _DIGEST_METHODS
            and not _children(digest_method)
        )
        _require(not _children(digest_value))
        transform_children = _children(transforms)
        _require(len(transform_children) == 2)
        _require(
            all(child.tag == f"{{{_DS}}}Transform" for child in transform_children)
        )
        _require(transform_children[0].get("Algorithm") == _ENVELOPED)
        _require(not _children(transform_children[0]))
        _c14n(transform_children[1])

        certificate = _select_certificate(key_info, certificates)
        context = xmlsec.SignatureContext()
        context.key = xmlsec.Key.from_memory(
            certificate, xmlsec.constants.KeyDataFormatCertPem
        )
        context.register_id(element, "ID")
        for method in _RSA_METHODS.values():
            context.enable_signature_transform(method)
        context.enable_signature_transform(xmlsec.constants.TransformExclC14N)
        for method in _DIGEST_METHODS.values():
            context.enable_reference_transform(method)
        context.enable_reference_transform(xmlsec.constants.TransformEnveloped)
        context.enable_reference_transform(xmlsec.constants.TransformExclC14N)
        context.verify(signature)
    except (ValueError, TypeError, xmlsec.Error, etree.LxmlError):
        raise ValueError(_ERROR) from None
