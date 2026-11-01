"""Local XML Encryption for the signed TVS ActingSubjectID profile."""

import base64
import binascii

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from lxml import etree

from app.saml.xml import NS, parse_xml

_ERROR = "Invalid encrypted identifier"
_AES256_CBC = NS["xenc"] + "aes256-cbc"
_OAEP = NS["xenc"] + "rsa-oaep-mgf1p"
_OAEP11 = NS["xenc11"] + "rsa-oaep"
_HASHES: dict[str, type[hashes.HashAlgorithm]] = {
    NS["ds"] + "sha1": hashes.SHA1,
    NS["xenc"] + "sha256": hashes.SHA256,
    "http://www.w3.org/2001/04/xmldsig-more#sha384": hashes.SHA384,
    NS["xenc"] + "sha512": hashes.SHA512,
}
_MGFS: dict[str, type[hashes.HashAlgorithm]] = {
    NS["xenc11"] + "mgf1sha1": hashes.SHA1,
    NS["xenc11"] + "mgf1sha256": hashes.SHA256,
    NS["xenc11"] + "mgf1sha384": hashes.SHA384,
    NS["xenc11"] + "mgf1sha512": hashes.SHA512,
}


def _tag(name: str) -> str:
    prefix, local_name = name.split(":", 1)
    return "{" + NS[prefix] + "}" + local_name


def _structure(element: etree._Element, allowed: set[str]) -> None:
    """Check direct children; descendants cannot substitute required nodes."""
    tags = {_tag(name) for name in allowed}
    if element.text and element.text.strip():
        raise ValueError(_ERROR)
    for child in element:
        if child.tag not in tags or (child.tail and child.tail.strip()):
            raise ValueError(_ERROR)


def _one(element: etree._Element, path: str) -> etree._Element:
    matches = element.findall(path, NS)
    if len(matches) != 1:
        raise ValueError(_ERROR)
    return matches[0]


def _optional(element: etree._Element, path: str) -> etree._Element | None:
    matches = element.findall(path, NS)
    if len(matches) > 1:
        raise ValueError(_ERROR)
    return matches[0] if matches else None


def _leaf_text(element: etree._Element) -> str:
    if len(element):
        raise ValueError(_ERROR)
    return element.text or ""


def _base64(element: etree._Element) -> bytes:
    value = _leaf_text(element)
    # XML Schema base64Binary permits exactly these whitespace characters.
    compact = value.translate(str.maketrans("", "", " \t\r\n"))
    return base64.b64decode(compact.encode("ascii"), validate=True)


def _ciphertext(element: etree._Element) -> bytes:
    cipher_data = _one(element, "xenc:CipherData")
    _structure(cipher_data, {"xenc:CipherValue"})
    return _base64(_one(cipher_data, "xenc:CipherValue"))


def _transport_padding(method: etree._Element) -> padding.OAEP:
    _structure(method, {"ds:DigestMethod", "xenc11:MGF", "xenc:OAEPparams"})
    transport = method.get("Algorithm")
    if transport not in (_OAEP, _OAEP11):
        raise ValueError(_ERROR)
    digest = _optional(method, "ds:DigestMethod")
    mgf = _optional(method, "xenc11:MGF")
    label = _optional(method, "xenc:OAEPparams")
    digest_class = (
        hashes.SHA1 if digest is None else _HASHES.get(digest.get("Algorithm", ""))
    )
    if digest is not None:
        _structure(digest, set())
    if mgf is not None:
        _structure(mgf, set())
    # rsa-oaep-mgf1p fixes MGF1-SHA1, even with a different DigestMethod.
    if transport == _OAEP and mgf is not None:
        raise ValueError(_ERROR)
    mgf_class = hashes.SHA1 if mgf is None else _MGFS.get(mgf.get("Algorithm", ""))
    if digest_class is None or mgf_class is None:
        raise ValueError(_ERROR)
    return padding.OAEP(
        mgf=padding.MGF1(mgf_class()),
        algorithm=digest_class(),
        label=None if label is None else _base64(label),
    )


def _associations(data: etree._Element, key: etree._Element) -> None:
    references = _optional(key, "xenc:ReferenceList")
    if references is not None:
        _structure(references, {"xenc:DataReference"})
        reference = _one(references, "xenc:DataReference")
        _structure(reference, set())
        if not data.get("Id") or reference.get("URI") != "#" + data.get("Id", ""):
            raise ValueError(_ERROR)

    data_info = _optional(data, "ds:KeyInfo")
    carried = _optional(key, "xenc:CarriedKeyName")
    data_name = None
    if data_info is not None:
        _structure(data_info, {"ds:KeyName", "ds:RetrievalMethod"})
        data_name = _optional(data_info, "ds:KeyName")
        retrieval = _optional(data_info, "ds:RetrievalMethod")
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


def _name_id(plaintext: bytes, max_xml_bytes: int) -> etree._Element:
    result = parse_xml(plaintext, max_xml_bytes)
    if (
        result.tag != _tag("saml:NameID")
        or len(result)
        or set(result.attrib) != {"Format", "NameQualifier"}
        or result.get("Format")
        != "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
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
    max_xml_bytes: int,
) -> etree._Element:
    """Decrypt one EncryptedID after its containing assertion was verified.

    The configured recipient and certificate KeyName select exactly one direct
    sibling EncryptedKey. Received key material and external references never
    influence the private-key operation.
    """
    try:
        if (
            not isinstance(private_key, rsa.RSAPrivateKey)
            or private_key.key_size < 2048
            or not recipient
            or not key_name
            or max_xml_bytes <= 0
            or encrypted_id.tag != _tag("saml:EncryptedID")
            or len(etree.tostring(encrypted_id)) > max_xml_bytes
        ):
            raise ValueError(_ERROR)
        _structure(encrypted_id, {"xenc:EncryptedData", "xenc:EncryptedKey"})
        # Inspect references even in keys for other recipients without using
        # their ciphertext or transport settings to select our identity.
        for element in encrypted_id.iter():
            if element.tag == _tag("xenc:CipherReference"):
                raise ValueError(_ERROR)
            if element.tag in {
                _tag("ds:RetrievalMethod"),
                _tag("xenc:DataReference"),
                _tag("xenc:KeyReference"),
            }:
                uri = element.get("URI", "")
                if not uri.startswith("#") or len(uri) == 1:
                    raise ValueError(_ERROR)

        data = _one(encrypted_id, "xenc:EncryptedData")
        _structure(data, {"xenc:EncryptionMethod", "ds:KeyInfo", "xenc:CipherData"})
        if data.get("Type", NS["xenc"] + "Element") != NS["xenc"] + "Element":
            raise ValueError(_ERROR)
        method = _one(data, "xenc:EncryptionMethod")
        _structure(method, set())
        if method.get("Algorithm") != _AES256_CBC:
            raise ValueError(_ERROR)

        matches = []
        for key in encrypted_id.findall("xenc:EncryptedKey", NS):
            if key.get("Recipient") == recipient:
                info = _one(key, "ds:KeyInfo")
                _structure(info, {"ds:KeyName"})
                if _leaf_text(_one(info, "ds:KeyName")) == key_name:
                    matches.append(key)
        if len(matches) != 1:
            raise ValueError(_ERROR)
        key = matches[0]
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
        oaep = _transport_padding(_one(key, "xenc:EncryptionMethod"))
        wrapped_key = _ciphertext(key)
        if len(wrapped_key) != (private_key.key_size + 7) // 8:
            raise ValueError(_ERROR)
        content_key = private_key.decrypt(wrapped_key, oaep)
        if len(content_key) != 32:
            raise ValueError(_ERROR)

        ciphertext = _ciphertext(data)
        # XMLENC CBC prefixes the ciphertext with one complete IV block.
        if len(ciphertext) < 32 or len(ciphertext) % 16:
            raise ValueError(_ERROR)
        decryptor = Cipher(
            algorithms.AES(content_key), modes.CBC(ciphertext[:16])
        ).decryptor()
        padded = decryptor.update(ciphertext[16:]) + decryptor.finalize()
        padding_length = padded[-1]
        if not 1 <= padding_length <= 16:
            raise ValueError(_ERROR)
        # Other XMLENC padding bytes are random, unlike PKCS#7.
        return _name_id(padded[:-padding_length], max_xml_bytes)
    except (
        ValueError,
        TypeError,
        AttributeError,
        UnicodeError,
        binascii.Error,
        etree.LxmlError,
    ):
        raise ValueError(_ERROR) from None
