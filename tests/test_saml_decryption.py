"""Real local XML Encryption fixtures; no production keys or crypto mocks."""

import base64
import copy
import importlib
import os
from collections.abc import Callable
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from lxml import etree

NS = {
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xenc": "http://www.w3.org/2001/04/xmlenc#",
    "xenc11": "http://www.w3.org/2009/xmlenc11#",
}
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


def sub(parent: Any, prefix: str, name: str, **attributes: str) -> Any:
    return etree.SubElement(parent, "{" + NS[prefix] + "}" + name, **attributes)


@pytest.fixture(scope="module")
def private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


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
) -> Any:
    """Build ciphertext independently from the decryption implementation."""
    identifier = etree.Element("{" + NS["saml"] + "}EncryptedID", nsmap=NS)
    data = sub(
        identifier, "xenc", "EncryptedData", Id="data-1", Type=NS["xenc"] + "Element"
    )
    sub(data, "xenc", "EncryptionMethod", Algorithm=NS["xenc"] + "aes256-cbc")
    data_cipher = sub(data, "xenc", "CipherData")
    key = os.urandom(32) if content_key is None else content_key
    iv = os.urandom(16)
    padding_length = 16 - len(plaintext) % 16
    # XMLENC permits arbitrary pad bytes; only the final byte encodes length.
    padded = plaintext + b"\xa5" * (padding_length - 1)
    padded += bytes([padding_length if padding_byte is None else padding_byte])
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = iv + encryptor.update(padded) + encryptor.finalize()
    sub(data_cipher, "xenc", "CipherValue").text = base64.b64encode(ciphertext).decode()

    encrypted_key = sub(
        identifier, "xenc", "EncryptedKey", Id="key-1", Recipient=RECIPIENT
    )
    method = sub(encrypted_key, "xenc", "EncryptionMethod", Algorithm=transport)
    if digest is not None:
        sub(method, "ds", "DigestMethod", Algorithm=DIGESTS[digest])
    if mgf is not None:
        sub(method, "xenc11", "MGF", Algorithm=NS["xenc11"] + "mgf1" + mgf)
    if label is not None:
        sub(method, "xenc", "OAEPparams").text = base64.b64encode(label).decode()
    sub(sub(encrypted_key, "ds", "KeyInfo"), "ds", "KeyName").text = KEY_NAME
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


def decrypt(identifier: Any, private_key: rsa.RSAPrivateKey, **kwargs: Any) -> Any:
    module = importlib.import_module("app.saml.decryption")
    return module.decrypt_identifier(
        identifier,
        private_key,
        kwargs.get("recipient", RECIPIENT),
        kwargs.get("key_name", KEY_NAME),
        kwargs.get("max_xml_bytes", 65536),
    )


def test_decrypts_real_aes256_with_random_xmlenc_padding(
    private_key: rsa.RSAPrivateKey,
) -> None:
    result = decrypt(encrypted_identifier(private_key), private_key)
    assert result.tag == "{" + NS["saml"] + "}NameID"
    assert result.text == "950000012"
    assert result.get("NameQualifier") == "urn:nl-eid-gdi:1.0:id:legacy-BSN"


@pytest.mark.parametrize(
    ("transport", "digest", "mgf", "label"),
    [
        (OAEP, None, None, None),
        (OAEP, "sha1", None, None),
        (OAEP, "sha256", None, b"test OAEP label\x00"),
        (OAEP11, None, None, None),
        (OAEP11, "sha256", None, b""),
        (OAEP11, "sha1", "sha256", None),
        (OAEP11, "sha256", "sha256", b"label"),
        (OAEP11, "sha384", "sha384", None),
        (OAEP11, "sha512", "sha512", None),
    ],
)
def test_oaep_digest_mgf_and_label_are_independent(
    private_key: rsa.RSAPrivateKey,
    transport: str,
    digest: str | None,
    mgf: str | None,
    label: bytes | None,
) -> None:
    identifier = encrypted_identifier(
        private_key, transport=transport, digest=digest, mgf=mgf, label=label
    )
    assert decrypt(identifier, private_key).text == "950000012"


def test_ignores_sibling_keys_for_other_recipients(
    private_key: rsa.RSAPrivateKey,
) -> None:
    identifier = encrypted_identifier(private_key)
    other = copy.deepcopy(identifier[1])
    other.set("Id", "other-key")
    other.set("Recipient", "urn:other:recipient")
    other.find("xenc:CipherData/xenc:CipherValue", NS).text = "not a key"
    identifier.insert(1, other)
    assert decrypt(identifier, private_key).text == "950000012"


@pytest.mark.parametrize(
    ("recipient", "key_name"), [("urn:wrong", KEY_NAME), (RECIPIENT, "wrong")]
)
def test_rejects_missing_matching_local_key(
    private_key: rsa.RSAPrivateKey,
    recipient: str,
    key_name: str,
) -> None:
    with pytest.raises(ValueError):
        decrypt(
            encrypted_identifier(private_key),
            private_key,
            recipient=recipient,
            key_name=key_name,
        )


def test_rejects_ambiguous_matching_keys(private_key: rsa.RSAPrivateKey) -> None:
    identifier = encrypted_identifier(private_key)
    other = copy.deepcopy(identifier[1])
    other.set("Id", "second-key")
    identifier.append(other)
    with pytest.raises(ValueError):
        decrypt(identifier, private_key)


def test_rejects_nested_key_instead_of_sibling(private_key: rsa.RSAPrivateKey) -> None:
    identifier = encrypted_identifier(private_key)
    key = identifier[1]
    identifier.remove(key)
    sub(identifier[0], "ds", "KeyInfo").append(key)
    with pytest.raises(ValueError):
        decrypt(identifier, private_key)


@pytest.mark.parametrize(
    "reference", ["#data-1", "#wrong", "https://attacker.invalid/data"]
)
def test_reference_list_must_bind_selected_data(
    private_key: rsa.RSAPrivateKey, reference: str
) -> None:
    identifier = encrypted_identifier(private_key)
    sub(
        sub(identifier[1], "xenc", "ReferenceList"),
        "xenc",
        "DataReference",
        URI=reference,
    )
    if reference == "#data-1":
        assert decrypt(identifier, private_key).text == "950000012"
    else:
        with pytest.raises(ValueError):
            decrypt(identifier, private_key)


@pytest.mark.parametrize("carried", ["content-key", "wrong-key"])
def test_carried_key_name_must_match_data_key_info(
    private_key: rsa.RSAPrivateKey, carried: str
) -> None:
    identifier = encrypted_identifier(private_key)
    sub(sub(identifier[0], "ds", "KeyInfo"), "ds", "KeyName").text = "content-key"
    sub(identifier[1], "xenc", "CarriedKeyName").text = carried
    if carried == "content-key":
        assert decrypt(identifier, private_key).text == "950000012"
    else:
        with pytest.raises(ValueError):
            decrypt(identifier, private_key)


@pytest.mark.parametrize(
    "reference", ["#key-1", "#wrong", "https://attacker.invalid/key"]
)
def test_retrieval_method_only_references_selected_local_key(
    private_key: rsa.RSAPrivateKey,
    reference: str,
) -> None:
    identifier = encrypted_identifier(private_key)
    sub(sub(identifier[0], "ds", "KeyInfo"), "ds", "RetrievalMethod", URI=reference)
    if reference == "#key-1":
        assert decrypt(identifier, private_key).text == "950000012"
    else:
        with pytest.raises(ValueError):
            decrypt(identifier, private_key)


def test_cipher_reference_is_never_allowed(private_key: rsa.RSAPrivateKey) -> None:
    identifier = encrypted_identifier(private_key)
    sub(
        identifier[0].find("xenc:CipherData", NS),
        "xenc",
        "CipherReference",
        URI="file:///etc/passwd",
    )
    with pytest.raises(ValueError):
        decrypt(identifier, private_key)


def test_accepts_xml_whitespace_in_base64_cipher_values(
    private_key: rsa.RSAPrivateKey,
) -> None:
    identifier = encrypted_identifier(private_key)
    for value in identifier.findall(".//xenc:CipherValue", NS):
        value.text = (
            " \n"
            + "\r\n".join(
                value.text[index : index + 40]
                for index in range(0, len(value.text), 40)
            )
            + "\t"
        )
    assert decrypt(identifier, private_key).text == "950000012"


def test_forbids_external_references_even_on_other_recipient_keys(
    private_key: rsa.RSAPrivateKey,
) -> None:
    identifier = encrypted_identifier(private_key)
    other = copy.deepcopy(identifier[1])
    other.set("Id", "other-key")
    other.set("Recipient", "urn:other:recipient")
    sub(
        other.find("ds:KeyInfo", NS),
        "ds",
        "RetrievalMethod",
        URI="https://attacker.invalid/key",
    )
    identifier.append(other)
    with pytest.raises(ValueError):
        decrypt(identifier, private_key)


def test_rejects_wrong_rsa_ciphertext_length(private_key: rsa.RSAPrivateKey) -> None:
    identifier = encrypted_identifier(private_key)
    identifier.find(
        "xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue", NS
    ).text = base64.b64encode(b"x" * 255).decode()
    with pytest.raises(ValueError):
        decrypt(identifier, private_key)


def test_rejects_malformed_oaep_label(private_key: rsa.RSAPrivateKey) -> None:
    identifier = encrypted_identifier(private_key, label=b"label")
    identifier.find(
        "xenc:EncryptedKey/xenc:EncryptionMethod/xenc:OAEPparams", NS
    ).text = "%%%"
    with pytest.raises(ValueError):
        decrypt(identifier, private_key)


@pytest.mark.parametrize("target", ["data", "transport", "digest", "mgf"])
def test_rejects_unknown_algorithms(
    private_key: rsa.RSAPrivateKey, target: str
) -> None:
    identifier = encrypted_identifier(private_key, transport=OAEP11, mgf="sha256")
    paths = {
        "data": "xenc:EncryptedData/xenc:EncryptionMethod",
        "transport": "xenc:EncryptedKey/xenc:EncryptionMethod",
        "digest": "xenc:EncryptedKey/xenc:EncryptionMethod/ds:DigestMethod",
        "mgf": "xenc:EncryptedKey/xenc:EncryptionMethod/xenc11:MGF",
    }
    identifier.find(paths[target], NS).set("Algorithm", "urn:unsupported")
    with pytest.raises(ValueError):
        decrypt(identifier, private_key)


def test_legacy_oaep_forbids_overriding_mgf(private_key: rsa.RSAPrivateKey) -> None:
    identifier = encrypted_identifier(private_key, mgf="sha256")
    with pytest.raises(ValueError):
        decrypt(identifier, private_key)


@pytest.mark.parametrize("padding_byte", [0, 17, 255])
def test_rejects_invalid_xmlenc_padding_length(
    private_key: rsa.RSAPrivateKey, padding_byte: int
) -> None:
    with pytest.raises(ValueError):
        decrypt(
            encrypted_identifier(private_key, padding_byte=padding_byte), private_key
        )


@pytest.mark.parametrize("size", [16, 24])
def test_unwrapped_key_must_be_256_bits(
    private_key: rsa.RSAPrivateKey, size: int
) -> None:
    with pytest.raises(ValueError):
        decrypt(
            encrypted_identifier(private_key, content_key=os.urandom(size)), private_key
        )


@pytest.mark.parametrize(
    "value",
    [
        "%%%",
        "",
        "YWJj",
        base64.b64encode(b"x" * 16).decode(),
        base64.b64encode(b"x" * 33).decode(),
    ],
)
def test_rejects_invalid_content_ciphertext(
    private_key: rsa.RSAPrivateKey, value: str
) -> None:
    identifier = encrypted_identifier(private_key)
    identifier.find(
        "xenc:EncryptedData/xenc:CipherData/xenc:CipherValue", NS
    ).text = value
    with pytest.raises(ValueError):
        decrypt(identifier, private_key)


@pytest.mark.parametrize(
    "plaintext",
    [
        NAMEID.replace(b"persistent", b"transient"),
        NAMEID.replace(b"legacy-BSN", b"other-ID"),
        NAMEID.replace(
            b' Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"', b""
        ),
        NAMEID.replace(b' NameQualifier="urn:nl-eid-gdi:1.0:id:legacy-BSN"', b""),
        NAMEID.replace(b"950000012", b""),
        NAMEID.replace(b">950000012", b' SPNameQualifier="other">950000012'),
        NAMEID.replace(b">950000012", b' SPProvidedID="other">950000012'),
        NAMEID.replace(b">950000012", b' unexpected="other">950000012'),
        NAMEID.replace(b"950000012", b"<saml:NameID/>"),
        NAMEID.replace(b"saml:NameID", b"saml:Attribute"),
        NAMEID + NAMEID,
        b'<!DOCTYPE x [<!ENTITY secret "950000012">]>'
        + NAMEID.replace(b"950000012", b"&secret;"),
    ],
)
def test_rejects_invalid_decrypted_nameid(
    private_key: rsa.RSAPrivateKey, plaintext: bytes
) -> None:
    with pytest.raises(ValueError):
        decrypt(encrypted_identifier(private_key, plaintext=plaintext), private_key)


def test_decrypted_plaintext_is_bounded(private_key: rsa.RSAPrivateKey) -> None:
    with pytest.raises(ValueError):
        decrypt(encrypted_identifier(private_key), private_key, max_xml_bytes=100)


def test_error_does_not_expose_crypto_or_plaintext_details(
    private_key: rsa.RSAPrivateKey,
) -> None:
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    errors = []
    for identifier, key in [
        (encrypted_identifier(private_key), wrong_key),
        (
            encrypted_identifier(
                private_key, plaintext=b"sensitive invalid XML 950000012"
            ),
            private_key,
        ),
    ]:
        with pytest.raises(ValueError) as caught:
            decrypt(identifier, key)
        errors.append(str(caught.value))
    assert errors[0] == errors[1]
    assert "950000012" not in errors[0]
    assert "sensitive" not in errors[0]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda node: node.append(copy.deepcopy(node[0])),
        lambda node: node[0].append(copy.deepcopy(node[0][0])),
        lambda node: (
            node[1]
            .find("ds:KeyInfo", NS)
            .append(copy.deepcopy(node[1].find("ds:KeyInfo/ds:KeyName", NS)))
        ),
        lambda node: (
            node[1]
            .find("xenc:EncryptionMethod", NS)
            .append(
                copy.deepcopy(node[1].find("xenc:EncryptionMethod/ds:DigestMethod", NS))
            )
        ),
        lambda node: (
            node[0]
            .find("xenc:CipherData", NS)
            .append(copy.deepcopy(node[0].find("xenc:CipherData/xenc:CipherValue", NS)))
        ),
        lambda node: node.remove(node[0]),
        lambda node: node[0].remove(node[0].find("xenc:EncryptionMethod", NS)),
        lambda node: node[1].remove(node[1].find("xenc:EncryptionMethod", NS)),
    ],
)
def test_rejects_ambiguous_encryption_structure(
    private_key: rsa.RSAPrivateKey,
    mutate: Callable[[Any], Any],
) -> None:
    identifier = encrypted_identifier(private_key)
    mutate(identifier)
    with pytest.raises(ValueError):
        decrypt(identifier, private_key)
