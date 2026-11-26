"""Verify the SAML enveloped-signature profile against pinned metadata keys."""

import base64
from typing import Any

import xmlsec
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from lxml import etree
from saml2 import create_class_from_xml_string, saml, samlp
from saml2.xml.schema import validate as validate_schema

from app.saml.errors import (
    SamlUnavailable,
    raise_sanitized,
    raise_sanitized_unavailable,
)
from app.saml.native import saml_validation, xmlsec_operation
from app.saml.xml import NS, child_elements

_ERROR = "Invalid SAML signature"
_DS = NS["ds"]
_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
_ENVELOPED = f"{_DS}enveloped-signature"
_RSA_METHODS = (
    xmlsec.constants.TransformRsaSha256,
    xmlsec.constants.TransformRsaSha384,
    xmlsec.constants.TransformRsaSha512,
)
_DIGEST_METHODS = (
    xmlsec.constants.TransformSha256,
    xmlsec.constants.TransformSha384,
    xmlsec.constants.TransformSha512,
)


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError(_ERROR)


def _select_certificate(
    key_info: etree._Element, certificates: dict[str, bytes]
) -> bytes:
    children = child_elements(key_info)
    names = key_info.findall("ds:KeyName", NS)
    data = key_info.findall("ds:X509Data", NS)
    _require(len(names) == 1 and len(data) <= 1)
    _require(len(children) == len(names) + len(data))

    # XML comments can split .text from a tail without failing XSD validation.
    _require(len(names[0]) == 0)
    name = names[0].text or ""
    _require(name in certificates)
    selected = certificates[name]

    if data:
        embedded = child_elements(data[0])
        _require(len(embedded) == 1 and embedded[0].tag == f"{{{_DS}}}X509Certificate")
        _require(len(embedded[0]) == 0)
        encoded = "".join((embedded[0].text or "").split())
        _require(
            x509.load_pem_x509_certificate(selected).public_bytes(
                serialization.Encoding.DER
            )
            == base64.b64decode(encoded, validate=True)
        )

    return selected


def _check_profile(signature: etree._Element, element_id: str) -> None:
    """Validate the TVS enveloped-signature profile after source XSD validation."""
    references = signature.findall("./ds:SignedInfo/ds:Reference", NS)
    _require(len(references) == 1 and references[0].get("URI") == f"#{element_id}")
    _require(not signature.findall("./ds:Object", NS))
    canonicalization = signature.find("./ds:SignedInfo/ds:CanonicalizationMethod", NS)
    _require(
        canonicalization is not None and canonicalization.get("Algorithm") == _C14N
    )
    transforms = references[0].findall("./ds:Transforms/ds:Transform", NS)
    _require([node.get("Algorithm") for node in transforms] == [_ENVELOPED, _C14N])


def _verify_native(
    element: etree._Element, signature: etree._Element, certificate: bytes
) -> None:
    with xmlsec_operation():
        context = xmlsec.SignatureContext()
        try:
            context.enabled_reference_uris = (
                xmlsec.constants.TransformUriTypeSameDocument
            )
            context.key = xmlsec.Key.from_memory(
                certificate, xmlsec.constants.KeyDataFormatCertPem
            )
            context.register_id(element, "ID")
            for method in _RSA_METHODS:
                context.enable_signature_transform(method)
            context.enable_signature_transform(xmlsec.constants.TransformExclC14N)
            for method in _DIGEST_METHODS:
                context.enable_reference_transform(method)
            context.enable_reference_transform(xmlsec.constants.TransformEnveloped)
            context.enable_reference_transform(xmlsec.constants.TransformExclC14N)
            context.verify(signature)
        finally:
            del context


def verify_signature(element: etree._Element, certificates: dict[str, bytes]) -> Any:
    """Check the original SAML XML and verify it in memory, without an adapter."""
    try:
        element_id = element.get("ID", "")
        _require(bool(element_id))
        identities = [
            node
            for node in element.getroottree().getroot().iter()
            for name, value in node.attrib.items()
            if name.rsplit("}", 1)[-1].lower() == "id" and value == element_id
        ]
        _require(len(identities) == 1 and identities[0] is element)
        document = etree.tostring(element, encoding="unicode", with_tail=False)
        signatures = element.findall("./ds:Signature", NS)
        _require(len(signatures) == 1)
        signature = signatures[0]
        key_info = signature.find("./ds:KeyInfo", NS)
        _require(key_info is not None)
        assert key_info is not None
        certificate = _select_certificate(key_info, certificates)
        classes = {
            f"{{{NS['samlp']}}}ArtifactResponse": samlp.ArtifactResponse,
            f"{{{NS['samlp']}}}Response": samlp.Response,
            f"{{{NS['saml']}}}Assertion": saml.Assertion,
        }
        _require(element.tag in classes)
    except SamlUnavailable:
        raise_sanitized_unavailable()
    except (ValueError, TypeError, etree.LxmlError):
        raise_sanitized(ValueError(_ERROR))

    try:
        with saml_validation():
            validate_schema(document)
            _check_profile(signature, element_id)
            model_type = classes[element.tag]
            model = create_class_from_xml_string(model_type, document)
            _require(
                isinstance(model, model_type)
                and model.issuer is not None
                and isinstance(model.issuer.text, str)
                and model.signature is not None
            )
            _verify_native(element, signature, certificate)
        return model
    except SamlUnavailable:
        raise_sanitized_unavailable()
    except Exception:  # noqa: BLE001 - library exceptions may contain the XML
        raise_sanitized(ValueError(_ERROR))
