"""Local XML Encryption for the signed TVS ActingSubjectID profile."""

import copy
import traceback

import xmlsec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree
from saml2 import saml

from app.saml.errors import (
    SamlUnavailable,
    raise_sanitized,
    raise_sanitized_unavailable,
)
from app.saml.native import xmlsec_operation
from app.saml.xml import NS, one, optional, parse_xml, qualified_tag

_ERROR = "Invalid encrypted identifier"
_AES256_CBC = NS["xenc"] + "aes256-cbc"
_OAEP = NS["xenc"] + "rsa-oaep-mgf1p"
_OAEP11 = NS["xenc11"] + "rsa-oaep"
_HASHES = {
    NS["ds"] + "sha1",
    NS["xenc"] + "sha256",
    "http://www.w3.org/2001/04/xmldsig-more#sha384",
    NS["xenc"] + "sha512",
}
_MGFS = {
    NS["xenc11"] + "mgf1sha1",
    NS["xenc11"] + "mgf1sha256",
    NS["xenc11"] + "mgf1sha384",
    NS["xenc11"] + "mgf1sha512",
}


def _structure(element: etree._Element, allowed: set[str]) -> None:
    """Check direct children; descendants cannot substitute required nodes."""
    tags = {qualified_tag(name) for name in allowed}
    if element.text and element.text.strip():
        raise ValueError(_ERROR)
    for child in element:
        if child.tag not in tags or (child.tail and child.tail.strip()):
            raise ValueError(_ERROR)


def _leaf_text(element: etree._Element) -> str:
    """Return full text; the source XSD has already ruled out element children."""
    return "".join(element.itertext())


def _validate_transport(method: etree._Element) -> None:
    _structure(method, {"ds:DigestMethod", "xenc11:MGF", "xenc:OAEPparams"})
    transport = method.get("Algorithm")
    if transport not in (_OAEP, _OAEP11):
        raise ValueError(_ERROR)
    digest = optional(method, "ds:DigestMethod")
    mgf = optional(method, "xenc11:MGF")
    if digest is not None:
        _structure(digest, set())
        if digest.get("Algorithm") not in _HASHES:
            raise ValueError(_ERROR)
    if mgf is not None:
        _structure(mgf, set())
        if mgf.get("Algorithm") not in _MGFS:
            raise ValueError(_ERROR)
    # rsa-oaep-mgf1p fixes MGF1-SHA1, even with a different DigestMethod.
    if transport == _OAEP and mgf is not None:
        raise ValueError(_ERROR)


def _associations(data: etree._Element, key: etree._Element) -> None:
    references = optional(key, "xenc:ReferenceList")
    if references is not None:
        _structure(references, {"xenc:DataReference"})
        reference = one(references, "xenc:DataReference")
        _structure(reference, set())
        if not data.get("Id") or reference.get("URI") != "#" + data.get("Id", ""):
            raise ValueError(_ERROR)

    data_info = optional(data, "ds:KeyInfo")
    carried = optional(key, "xenc:CarriedKeyName")
    data_name = None
    if data_info is not None:
        _structure(data_info, {"ds:KeyName", "ds:RetrievalMethod"})
        data_name = optional(data_info, "ds:KeyName")
        retrieval = optional(data_info, "ds:RetrievalMethod")
        if retrieval is not None:
            _structure(retrieval, set())
            if (
                not key.get("Id")
                or retrieval.get("URI") != "#" + key.get("Id", "")
                or retrieval.get("Type", NS["xenc"] + "EncryptedKey")
                != NS["xenc"] + "EncryptedKey"
            ):
                raise ValueError(_ERROR)
    if (carried is not None or data_name is not None) and (
        carried is None
        or data_name is None
        or not _leaf_text(carried)
        or _leaf_text(carried) != _leaf_text(data_name)
    ):
        raise ValueError(_ERROR)


def _name_id(plaintext: bytes) -> etree._Element:
    result = parse_xml(plaintext)
    if (
        result.tag != qualified_tag("saml:NameID")
        or len(result)
        or set(result.attrib) != {"Format", "NameQualifier"}
        or result.get("Format") != saml.NAMEID_FORMAT_PERSISTENT
        or result.get("NameQualifier") != "urn:nl-eid-gdi:1.0:id:legacy-BSN"
        or not result.text
        or result.text != result.text.strip()
    ):
        raise ValueError(_ERROR)
    return result


def decrypt_identifier(
    encrypted_id: etree._Element,
    private_key: rsa.RSAPrivateKey,
    recipient: str,
    key_name: str,
) -> etree._Element:
    """Decrypt an EncryptedID from an XSD-checked, verified assertion.

    The configured recipient and certificate KeyName select exactly one direct
    sibling EncryptedKey. Received key material and external references never
    influence the private-key operation.
    """
    key_pem = None
    xmlsec_key = None
    manager = None
    content_key = None
    data_context = None
    plaintext = None
    try:
        if (
            not isinstance(private_key, rsa.RSAPrivateKey)
            or private_key.key_size < 2048
            or not recipient
            or not key_name
            or encrypted_id.tag != qualified_tag("saml:EncryptedID")
        ):
            raise ValueError(_ERROR)
        data = one(encrypted_id, "xenc:EncryptedData")
        _structure(data, {"xenc:EncryptionMethod", "ds:KeyInfo", "xenc:CipherData"})
        if data.get("Type", NS["xenc"] + "Element") != NS["xenc"] + "Element":
            raise ValueError(_ERROR)
        method = one(data, "xenc:EncryptionMethod")
        _structure(method, set())
        if method.get("Algorithm") != _AES256_CBC:
            raise ValueError(_ERROR)

        matches = []
        for key in encrypted_id.findall("xenc:EncryptedKey", NS):
            if key.get("Recipient") == recipient:
                info = one(key, "ds:KeyInfo")
                name = _leaf_text(one(info, "ds:KeyName"))
                if not name:
                    raise ValueError(_ERROR)
                if name == key_name:
                    _structure(info, {"ds:KeyName"})
                    matches.append(key)
        if len(matches) != 1:
            raise ValueError(_ERROR)
        key = matches[0]
        # Source XSD permits CipherReference instead of CipherValue. Other
        # references are governed by the selected structures and associations.
        for node in (data, key):
            if next(node.iter(qualified_tag("xenc:CipherReference")), None) is not None:
                raise ValueError(_ERROR)

        _structure(
            key,
            {
                "xenc:EncryptionMethod",
                "ds:KeyInfo",
                "xenc:CipherData",
                "xenc:ReferenceList",
                "xenc:CarriedKeyName",
            },
        )
        _associations(data, key)
        _validate_transport(one(key, "xenc:EncryptionMethod"))
        # Only detached copies are handed to xmlsec; the verified tree is intact.
        data = copy.deepcopy(data)
        key = copy.deepcopy(key)
        data.attrib.pop("Type", None)
        key.attrib.pop("Type", None)
        original_info = optional(data, "ds:KeyInfo")
        if original_info is not None:
            data.remove(original_info)

        try:
            with xmlsec_operation():
                try:
                    key_pem = private_key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                    xmlsec_key = xmlsec.Key.from_memory(
                        key_pem, xmlsec.constants.KeyDataFormatPem, None
                    )
                    key_pem = None
                    xmlsec_key.name = key_name
                    manager = xmlsec.KeysManager()
                    manager.add_key(xmlsec_key)
                    xmlsec_key = None

                    # xmlsec can truncate longer AES keys. Check the exact
                    # length before importing the key into the data context.
                    content_key = xmlsec.EncryptionContext(manager).decrypt(key)
                    manager = None
                    if not isinstance(content_key, bytes):
                        raise TypeError(_ERROR)
                    if len(content_key) != 32:
                        raise ValueError(_ERROR)
                    data_context = xmlsec.EncryptionContext()
                    data_context.key = xmlsec.Key.from_binary_data(
                        xmlsec.constants.KeyDataAes, content_key
                    )
                    content_key = None
                    plaintext = data_context.decrypt(data)
                finally:
                    # Drop app-owned native references inside the lock; other
                    # references may keep native wrappers alive after lock exit.
                    key_pem = None
                    xmlsec_key = None
                    manager = None
                    content_key = None
                    data_context = None
            if not isinstance(plaintext, bytes):
                raise TypeError(_ERROR)
            return _name_id(plaintext)
        except SamlUnavailable:
            raise_sanitized_unavailable()
        except Exception:  # noqa: BLE001 - native and parser errors may contain secrets
            raise_sanitized(ValueError(_ERROR))
    except SamlUnavailable:
        raise
    except (ValueError, TypeError, AttributeError, etree.LxmlError):
        raise_sanitized(ValueError(_ERROR))
    except (KeyboardInterrupt, SystemExit) as interruption:
        # Child parser frames can retain plaintext; keep the original
        # interruption and clear frames that are no longer executing.
        traceback.clear_frames(interruption.__traceback__)
        interruption.__cause__ = None
        try:
            raise
        finally:
            interruption.__context__ = None
    finally:
        # Drop references from any retained traceback; this is not zeroization.
        key_pem = None
        xmlsec_key = None
        manager = None
        content_key = None
        data_context = None
        plaintext = None
        del private_key
