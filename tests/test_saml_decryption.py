"""Real local XML Encryption fixtures; no production keys or crypto mocks."""

import base64
import copy
import importlib
import itertools
import os
import sys
import traceback
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import xmlsec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from lxml import etree
from saml2.xml.schema import XMLSchemaError, validate

from tests.saml_helpers import (
    HASHES,
    KEY_NAME,
    NAMEID,
    OAEP,
    OAEP11,
    RECIPIENT,
    encrypted_identifier,
    sub,
)

NS = {
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xenc": "http://www.w3.org/2001/04/xmlenc#",
    "xenc11": "http://www.w3.org/2009/xmlenc11#",
}


@pytest.fixture(scope="module")
def private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def decrypt(identifier: Any, private_key: rsa.RSAPrivateKey, **kwargs: Any) -> Any:
    module = importlib.import_module("app.saml.decryption")
    document = etree.tostring(identifier, encoding="unicode")
    try:
        validate(document)
    except XMLSchemaError:
        raise ValueError("Invalid encrypted identifier") from None
    return module.decrypt_identifier(
        identifier,
        private_key,
        kwargs.get("recipient", RECIPIENT),
        kwargs.get("key_name", KEY_NAME),
    )


def test_data_decryption_uses_checked_unwrapped_aes_key(
    private_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = importlib.import_module("app.saml.decryption")
    content_key = os.urandom(32)
    identifier = encrypted_identifier(private_key, content_key=content_key)
    original_data = identifier.find("./xenc:EncryptedData", NS)
    original_xml = etree.tostring(identifier)
    unwrapped: list[bytes] = []
    imported_keys: list[xmlsec.Key] = []
    checked_key_imports: list[bool] = []
    assigned_keys: list[bool] = []
    data_calls: list[tuple[str | None, int, bool]] = []

    class ObservedKey:
        @staticmethod
        def from_memory(
            data: bytes, key_format: int, password: str | None
        ) -> xmlsec.Key:
            return xmlsec.Key.from_memory(data, key_format, password)

        @staticmethod
        def from_binary_data(klass: Any, data: bytes) -> xmlsec.Key:
            checked_key_imports.append(
                klass == xmlsec.constants.KeyDataAes
                and len(unwrapped) == 1
                and len(data) == 32
                and data == unwrapped[0] == content_key
            )
            imported = xmlsec.Key.from_binary_data(klass, data)
            imported_keys.append(imported)
            return imported

    def context(manager: xmlsec.KeysManager | None = None) -> object:
        inner = xmlsec.EncryptionContext(manager)

        class Observed:
            @property
            def key(self) -> xmlsec.Key | None:
                return inner.key

            @key.setter
            def key(self, value: xmlsec.Key) -> None:
                assigned_keys.append(bool(imported_keys and value is imported_keys[0]))
                inner.key = value

            def decrypt(self, node: etree._Element) -> bytes | etree._Element:
                is_key = node.tag == "{" + NS["xenc"] + "}EncryptedKey"
                if not is_key:
                    data_calls.append(
                        (
                            node.get("Type"),
                            len(node.findall(".//xenc:EncryptedKey", NS)),
                            node is original_data,
                        )
                    )
                result = inner.decrypt(node)
                if is_key and isinstance(result, bytes):
                    unwrapped.append(result)
                return result

        return Observed()

    assert hasattr(module, "xmlsec"), "decryptor must use the in-memory xmlsec binding"
    observed_xmlsec = SimpleNamespace(
        EncryptionContext=context,
        Key=ObservedKey,
        KeysManager=xmlsec.KeysManager,
        constants=xmlsec.constants,
    )
    monkeypatch.setattr(module, "xmlsec", observed_xmlsec)
    assert decrypt(identifier, private_key).text == "950000012"
    assert checked_key_imports == [True]
    assert assigned_keys == [True]
    assert data_calls == [(None, 0, False)]
    assert len(unwrapped) == 1
    assert etree.tostring(identifier) == original_xml


def test_xmlsec_decrypts_copy_as_bytes(
    private_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = importlib.import_module("app.saml.decryption")
    identifier = encrypted_identifier(private_key)
    original_data = identifier.find("./xenc:EncryptedData", NS)
    original_key = identifier.find("./xenc:EncryptedKey", NS)
    original_xml = etree.tostring(identifier)
    calls: list[tuple[str | None, bool, type[object]]] = []
    key_calls: list[tuple[str | None, bool, type[object]]] = []
    real_context = xmlsec.EncryptionContext

    def context(manager: xmlsec.KeysManager | None = None) -> object:
        inner = real_context(manager)

        class Observed:
            @property
            def key(self) -> xmlsec.Key | None:
                return inner.key

            @key.setter
            def key(self, value: xmlsec.Key) -> None:
                inner.key = value

            def decrypt(self, node: etree._Element) -> bytes | etree._Element:
                result = inner.decrypt(node)
                if node.tag == "{" + NS["xenc"] + "}EncryptedKey":
                    key_calls.append(
                        (node.get("Type"), node is original_key, type(result))
                    )
                else:
                    calls.append(
                        (node.get("Type"), node is original_data, type(result))
                    )
                return result

        return Observed()

    assert hasattr(module, "xmlsec"), "decryptor must use the in-memory xmlsec binding"
    monkeypatch.setattr(module.xmlsec, "EncryptionContext", context)
    assert decrypt(identifier, private_key).text == "950000012"
    assert key_calls == [(None, False, bytes)]
    assert calls == [(None, False, bytes)]
    assert etree.tostring(identifier) == original_xml


def _exception_graph_contains(error: BaseException, secret: str) -> bool:
    pending = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if secret in str(current) or secret in "".join(
            traceback.format_exception(current)
        ):
            return True
        if current.__context__ is not None:
            pending.append(current.__context__)
        if current.__cause__ is not None:
            pending.append(current.__cause__)
    return False


@pytest.mark.parametrize("failure", ["malformed_xml", "external_doctype", "wrong_key"])
def test_decryption_failures_are_private_and_leave_original_unchanged(
    private_key: rsa.RSAPrivateKey,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    failure: str,
) -> None:
    caplog.set_level("INFO")
    secret = "PRIVATE-SENTINEL-950000012"
    if failure == "malformed_xml":
        plaintext = ("<NameID>" + secret + "<invalid").encode()
    elif failure == "external_doctype":
        plaintext = (
            '<!DOCTYPE NameID [<!ENTITY xxe SYSTEM "file:///'
            + secret
            + '">]><NameID>&xxe;</NameID>'
        ).encode()
    else:
        plaintext = NAMEID.replace(b"950000012", secret.encode())

    identifier = encrypted_identifier(private_key, plaintext=plaintext)
    original_xml = etree.tostring(identifier)
    key = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if failure == "wrong_key"
        else private_key
    )
    capfd.readouterr()
    with pytest.raises(ValueError, match="^Invalid encrypted identifier$") as caught:
        decrypt(identifier, key)

    captured = capfd.readouterr()
    assert not _exception_graph_contains(caught.value, secret)
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None
    assert captured.out == captured.err == caplog.text == ""
    assert etree.tostring(identifier) == original_xml


@pytest.mark.parametrize(
    "failure", ["padding_zero", "padding_long", "aes128", "aes192"]
)
def test_invalid_content_crypto_is_private_and_leaves_original_unchanged(
    private_key: rsa.RSAPrivateKey,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    failure: str,
) -> None:
    caplog.set_level("INFO")
    secret = "PRIVATE-SENTINEL-950000012"
    options: dict[str, Any] = {
        "plaintext": NAMEID.replace(b"950000012", secret.encode())
    }
    if failure == "padding_zero":
        options["padding_byte"] = 0
    elif failure == "padding_long":
        options["padding_byte"] = 17
    else:
        options["content_key"] = os.urandom(16 if failure == "aes128" else 24)
    identifier = encrypted_identifier(private_key, **options)
    original_xml = etree.tostring(identifier)

    capfd.readouterr()
    with pytest.raises(ValueError, match="^Invalid encrypted identifier$") as caught:
        decrypt(identifier, private_key)
    captured = capfd.readouterr()
    assert not _exception_graph_contains(caught.value, secret)
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None
    assert captured.out == captured.err == caplog.text == ""
    assert etree.tostring(identifier) == original_xml


@pytest.mark.parametrize("ambient_exception", [False, True])
def test_decryption_detaches_parser_exception_graph(
    private_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    ambient_exception: bool,
) -> None:
    module = importlib.import_module("app.saml.decryption")
    identifier = encrypted_identifier(private_key)
    original_xml = etree.tostring(identifier)
    secret = "sensitive-parser-and-ambient-error"
    parser_called = False

    def fail_parser(data: bytes) -> etree._Element:
        nonlocal parser_called
        del data
        parser_called = True
        try:
            raise RuntimeError(secret)
        except RuntimeError as cause:
            raise ValueError("parser failed") from cause

    monkeypatch.setattr(module, "parse_xml", fail_parser)

    def capture_error() -> ValueError:
        with pytest.raises(ValueError, match="^Invalid encrypted identifier$") as error:
            decrypt(identifier, private_key)
        return error.value

    capfd.readouterr()
    if ambient_exception:
        try:
            raise RuntimeError(secret)
        except RuntimeError:
            error = capture_error()
    else:
        error = capture_error()

    captured = capfd.readouterr()
    assert parser_called
    assert not _exception_graph_contains(error, secret)
    assert error.__context__ is None
    assert error.__cause__ is None
    assert captured.out == captured.err == caplog.text == ""
    assert etree.tostring(identifier) == original_xml


@pytest.mark.parametrize("result", ["element", "exception"])
@pytest.mark.parametrize("stage", ["key", "data"])
def test_xmlsec_result_and_errors_are_sanitized(
    private_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    result: str,
    stage: str,
) -> None:
    module = importlib.import_module("app.saml.decryption")
    identifier = encrypted_identifier(private_key)
    original_xml = etree.tostring(identifier)
    secret = "sensitive-xmlsec-library-detail"

    real_context = xmlsec.EncryptionContext
    calls: list[bool] = []

    def context(manager: xmlsec.KeysManager | None = None) -> object:
        inner = real_context(manager)

        class BadContext:
            @property
            def key(self) -> xmlsec.Key | None:
                return inner.key

            @key.setter
            def key(self, value: xmlsec.Key) -> None:
                inner.key = value

            def decrypt(self, node: etree._Element) -> bytes | etree._Element:
                is_key = node.tag == "{" + NS["xenc"] + "}EncryptedKey"
                if is_key != (stage == "key"):
                    return inner.decrypt(node)
                calls.append(True)
                if result == "exception":
                    try:
                        raise RuntimeError(secret)
                    except RuntimeError as cause:
                        raise xmlsec.Error("decryption failed") from cause
                return node

        return BadContext()

    assert hasattr(module, "xmlsec"), "decryptor must use the in-memory xmlsec binding"
    monkeypatch.setattr(module.xmlsec, "EncryptionContext", context)
    capfd.readouterr()
    with pytest.raises(ValueError, match="^Invalid encrypted identifier$") as caught:
        decrypt(identifier, private_key)
    captured = capfd.readouterr()
    assert calls == [True]
    assert not _exception_graph_contains(caught.value, secret)
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None
    assert captured.out == captured.err == caplog.text == ""
    assert etree.tostring(identifier) == original_xml


@pytest.mark.parametrize("ambient_exception", [False, True])
def test_xmlsec_aes_key_import_errors_are_sanitized(
    private_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    ambient_exception: bool,
) -> None:
    module = importlib.import_module("app.saml.decryption")
    identifier = encrypted_identifier(private_key)
    original_xml = etree.tostring(identifier)
    secret = "sensitive-aes-key-import-error"
    calls: list[bool] = []

    class FailingKey:
        @staticmethod
        def from_memory(
            data: bytes, key_format: int, password: str | None
        ) -> xmlsec.Key:
            return xmlsec.Key.from_memory(data, key_format, password)

        @staticmethod
        def from_binary_data(klass: Any, data: bytes) -> xmlsec.Key:
            del klass, data
            calls.append(True)
            try:
                raise RuntimeError(secret)
            except RuntimeError as cause:
                raise xmlsec.Error("key import failed") from cause

    assert hasattr(module, "xmlsec")
    observed_xmlsec = SimpleNamespace(
        EncryptionContext=xmlsec.EncryptionContext,
        Key=FailingKey,
        KeysManager=xmlsec.KeysManager,
        constants=xmlsec.constants,
    )
    monkeypatch.setattr(module, "xmlsec", observed_xmlsec)

    def capture_error() -> ValueError:
        with pytest.raises(ValueError, match="^Invalid encrypted identifier$") as error:
            decrypt(identifier, private_key)
        return error.value

    caplog.set_level("INFO")
    capfd.readouterr()
    if ambient_exception:
        try:
            raise RuntimeError(secret)
        except RuntimeError:
            error = capture_error()
    else:
        error = capture_error()
    captured = capfd.readouterr()

    assert calls == [True]
    assert not _exception_graph_contains(error, secret)
    assert error.__context__ is None
    assert error.__cause__ is None
    assert captured.out == captured.err == caplog.text == ""
    assert etree.tostring(identifier) == original_xml


@pytest.mark.parametrize("ambient_exception", [False, True])
@pytest.mark.parametrize(
    "stage", ["private_import", "rsa_unwrap", "aes_import", "data_decrypt", "xml"]
)
def test_failed_decryption_traceback_has_no_sensitive_locals(
    private_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    ambient_exception: bool,
    stage: str,
) -> None:
    module = importlib.import_module("app.saml.decryption")
    content_key = os.urandom(32)
    secret = "TRACEBACK-PLAINTEXT-SENTINEL-950000012"
    plaintext = ("<NameID>" + secret + "<invalid").encode()
    identifier = encrypted_identifier(
        private_key,
        content_key=content_key,
        plaintext=plaintext,
        padding_byte=0 if stage == "data_decrypt" else None,
    )
    selected_key = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if stage == "rsa_unwrap"
        else private_key
    )
    private_pem = selected_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    original_xml = etree.tostring(identifier)
    events: list[str] = []
    real_parse = module.parse_xml

    class ObservedKey:
        @staticmethod
        def from_memory(
            data: bytes, key_format: int, password: str | None
        ) -> xmlsec.Key:
            events.append("private_import")
            if stage == "private_import":
                raise xmlsec.Error("synthetic key import failure")
            return xmlsec.Key.from_memory(data, key_format, password)

        @staticmethod
        def from_binary_data(klass: Any, data: bytes) -> xmlsec.Key:
            events.append("aes_import")
            if stage == "aes_import":
                raise xmlsec.Error("synthetic AES import failure")
            return xmlsec.Key.from_binary_data(klass, data)

    def context(manager: xmlsec.KeysManager | None = None) -> object:
        inner = xmlsec.EncryptionContext(manager)

        class Observed:
            @property
            def key(self) -> xmlsec.Key | None:
                return inner.key

            @key.setter
            def key(self, value: xmlsec.Key) -> None:
                inner.key = value

            def decrypt(self, node: etree._Element) -> bytes | etree._Element:
                events.append(
                    "rsa_unwrap"
                    if node.tag == "{" + NS["xenc"] + "}EncryptedKey"
                    else "data_decrypt"
                )
                return inner.decrypt(node)

        return Observed()

    def parse(data: bytes) -> etree._Element:
        events.append("xml")
        return real_parse(data)

    assert hasattr(module, "xmlsec")
    monkeypatch.setattr(
        module,
        "xmlsec",
        SimpleNamespace(
            EncryptionContext=context,
            Key=ObservedKey,
            KeysManager=xmlsec.KeysManager,
            constants=xmlsec.constants,
        ),
    )
    monkeypatch.setattr(module, "parse_xml", parse)

    def capture_error() -> ValueError:
        with pytest.raises(ValueError, match="^Invalid encrypted identifier$") as error:
            decrypt(identifier, selected_key)
        return error.value

    caplog.set_level("INFO")
    capfd.readouterr()
    if ambient_exception:
        try:
            raise RuntimeError("synthetic ambient exception")
        except RuntimeError:
            error = capture_error()
    else:
        error = capture_error()
    captured = capfd.readouterr()

    stages = ["private_import", "rsa_unwrap", "aes_import", "data_decrypt", "xml"]
    assert events == stages[: stages.index(stage) + 1]
    assert error.__cause__ is None and error.__context__ is None
    assert captured.out == captured.err == caplog.text == ""
    assert etree.tostring(identifier) == original_xml

    report = traceback.TracebackException.from_exception(error, capture_locals=True)
    app_dir = Path(__file__).resolve().parents[1] / "app"
    app_frames = [
        frame
        for frame in report.stack
        if Path(frame.filename).resolve().is_relative_to(app_dir)
    ]
    assert any(frame.name == "decrypt_identifier" for frame in app_frames)
    local_values = [
        value for frame in app_frames for value in (frame.locals or {}).values()
    ]
    if any(
        marker in value
        for marker in (repr(private_pem), repr(content_key), secret)
        for value in local_values
    ):
        pytest.fail("Sensitive material remained in application traceback locals")

    tb = error.__traceback__
    while tb is not None:
        frame = tb.tb_frame
        if frame.f_code.co_name == "decrypt_identifier" and Path(
            frame.f_code.co_filename
        ).resolve().is_relative_to(app_dir):
            for name in (
                "private_key",
                "key_pem",
                "xmlsec_key",
                "manager",
                "content_key",
                "data_context",
                "plaintext",
            ):
                if frame.f_locals.get(name) is not None:
                    pytest.fail(f"Sensitive local {name} was not cleared")
        tb = tb.tb_next


def test_unexpected_validation_programming_error_is_not_swallowed(
    private_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = importlib.import_module("app.saml.decryption")
    identifier = encrypted_identifier(private_key)

    def bug(method: etree._Element) -> None:
        del method
        raise RuntimeError("synthetic programming error")

    monkeypatch.setattr(module, "_validate_transport", bug)
    with pytest.raises(RuntimeError, match="^synthetic programming error$"):
        decrypt(identifier, private_key)


@pytest.mark.parametrize("interrupt_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("target", ["name_id", "parse_xml"])
@pytest.mark.parametrize("ambient_exception", [False, True])
def test_interrupted_decryption_preserves_interrupt_without_plaintext_locals(
    private_key: rsa.RSAPrivateKey,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    interrupt_type: type[BaseException],
    target: str,
    ambient_exception: bool,
) -> None:
    module = importlib.import_module("app.saml.decryption")
    secret = "INTERRUPTED-PLAINTEXT-SENTINEL-950000012"
    plaintext = NAMEID.replace(b"950000012", secret.encode())
    identifier = encrypted_identifier(private_key, plaintext=plaintext)
    original_xml = etree.tostring(identifier)
    expected = interrupt_type(23) if interrupt_type is SystemExit else interrupt_type()
    code = (
        module._name_id.__code__ if target == "name_id" else module.parse_xml.__code__
    )
    seen: list[bool] = []

    def interrupt(frame: Any, event: str, arg: Any) -> Any:
        del arg
        if event == "line" and frame.f_code is code:
            seen.append(True)
            sys.settrace(None)
            raise expected
        return interrupt

    caplog.set_level("DEBUG")
    capfd.readouterr()

    def capture_error() -> BaseException:
        previous_trace = sys.gettrace()
        try:
            sys.settrace(interrupt)
            with pytest.raises(interrupt_type) as caught:
                decrypt(identifier, private_key)
        finally:
            sys.settrace(previous_trace)
        return caught.value

    if ambient_exception:
        try:
            raise RuntimeError("synthetic ambient context")
        except RuntimeError:
            error = capture_error()
    else:
        error = capture_error()
    captured = capfd.readouterr()

    assert error is expected
    assert seen == [True]
    if isinstance(error, SystemExit):
        assert error.code == 23
    if error.__context__ is not None or error.__cause__ is not None:
        pytest.fail("Interruption retained an exception context")
    assert etree.tostring(identifier) == original_xml
    assert captured.out == captured.err == caplog.text == ""
    report = traceback.TracebackException.from_exception(error, capture_locals=True)
    app_dir = Path(__file__).resolve().parents[1] / "app"
    app_frames = [
        frame
        for frame in report.stack
        if Path(frame.filename).resolve().is_relative_to(app_dir)
    ]
    assert any(frame.name == "decrypt_identifier" for frame in app_frames)
    assert any(frame.name == "_name_id" for frame in app_frames)
    if target == "parse_xml":
        assert any(frame.name == "parse_xml" for frame in app_frames)
    if any(
        secret in value
        for frame in app_frames
        for value in (frame.locals or {}).values()
    ):
        pytest.fail("Interrupted traceback retained plaintext in an application frame")


@pytest.mark.parametrize(
    "invalid",
    [
        "type",
        "data_base64",
        "key_base64",
        "transport",
        "oaep_label",
        "recipient",
        "association",
    ],
)
def test_original_is_validated_before_xmlsec(
    private_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
    invalid: str,
) -> None:
    module = importlib.import_module("app.saml.decryption")
    identifier = encrypted_identifier(private_key, label=b"label")
    data, key = identifier
    if invalid == "type":
        data.set("Type", NS["xenc"] + "Content")
    elif invalid == "data_base64":
        data.find("./xenc:CipherData/xenc:CipherValue", NS).text = "%%%"
    elif invalid == "key_base64":
        key.find("./xenc:CipherData/xenc:CipherValue", NS).text = "%%%"
    elif invalid == "transport":
        key.find("./xenc:EncryptionMethod", NS).set("Algorithm", "urn:unsupported")
    elif invalid == "oaep_label":
        key.find("./xenc:EncryptionMethod/xenc:OAEPparams", NS).text = "%%%"
    elif invalid == "recipient":
        key.set("Recipient", "urn:wrong:recipient")
    elif invalid == "association":
        info = etree.Element("{" + NS["ds"] + "}KeyInfo")
        sub(info, "ds", "RetrievalMethod", URI="#wrong")
        data.insert(1, info)
    original_xml = etree.tostring(identifier)
    calls: list[bool] = []
    real_context = xmlsec.EncryptionContext

    def context(manager: xmlsec.KeysManager) -> xmlsec.EncryptionContext:
        calls.append(True)
        return real_context(manager)

    assert hasattr(module, "xmlsec"), "decryptor must use the in-memory xmlsec binding"
    monkeypatch.setattr(module.xmlsec, "EncryptionContext", context)
    with pytest.raises(ValueError, match="^Invalid encrypted identifier$"):
        decrypt(identifier, private_key)
    assert calls == []
    assert etree.tostring(identifier) == original_xml


@pytest.mark.parametrize("type_present", [False, True])
def test_accepts_original_element_type_or_default_without_mutating_it(
    private_key: rsa.RSAPrivateKey, type_present: bool
) -> None:
    identifier = encrypted_identifier(private_key)
    if not type_present:
        identifier[0].attrib.pop("Type")
    original_xml = etree.tostring(identifier)
    assert decrypt(identifier, private_key).text == "950000012"
    assert etree.tostring(identifier) == original_xml


@pytest.mark.parametrize("element", ["data", "key"])
def test_source_schema_rejects_out_of_order_encryption_children(
    private_key: rsa.RSAPrivateKey, element: str
) -> None:
    identifier = encrypted_identifier(private_key, label=b"label")
    data, key = identifier
    info = etree.Element("{" + NS["ds"] + "}KeyInfo")
    sub(info, "ds", "RetrievalMethod", URI="#key-1")
    data.insert(1, info)
    sub(sub(key, "xenc", "ReferenceList"), "xenc", "DataReference", URI="#data-1")
    node = data if element == "data" else key
    node[:] = list(reversed(node[:]))
    original_xml = etree.tostring(identifier)

    with pytest.raises(ValueError):
        decrypt(identifier, private_key)
    assert etree.tostring(identifier) == original_xml


@pytest.mark.parametrize("order", list(itertools.permutations(range(3))))
def test_oaep_parameter_order_obeys_source_schema(
    private_key: rsa.RSAPrivateKey, order: tuple[int, int, int]
) -> None:
    identifier = encrypted_identifier(
        private_key, transport=OAEP11, digest="sha256", mgf="sha256", label=b"label"
    )
    method = identifier.find("./xenc:EncryptedKey/xenc:EncryptionMethod", NS)
    children = list(method)
    method[:] = [children[index] for index in order]
    original_xml = etree.tostring(identifier)

    if order[0] == 0:  # OAEPparams precedes extension-namespace parameters.
        assert decrypt(identifier, private_key).text == "950000012"
    else:
        with pytest.raises(ValueError):
            decrypt(identifier, private_key)
    assert etree.tostring(identifier) == original_xml


@pytest.mark.parametrize("digest", list(HASHES))
@pytest.mark.parametrize("mgf", list(HASHES))
def test_accepts_every_oaep11_digest_and_mgf_combination(
    private_key: rsa.RSAPrivateKey, digest: str, mgf: str
) -> None:
    identifier = encrypted_identifier(
        private_key, transport=OAEP11, digest=digest, mgf=mgf, label=b"\x00label"
    )
    assert decrypt(identifier, private_key).text == "950000012"


@pytest.mark.parametrize("digest", list(HASHES))
def test_accepts_every_legacy_oaep_digest(
    private_key: rsa.RSAPrivateKey, digest: str
) -> None:
    identifier = encrypted_identifier(private_key, digest=digest, label=b"\x00label")
    assert decrypt(identifier, private_key).text == "950000012"


@pytest.mark.parametrize("key_name", [" test-key ", "\tkey name\n", "key-\u00e9"])
def test_accepts_exact_configured_key_name(
    private_key: rsa.RSAPrivateKey, key_name: str
) -> None:
    identifier = encrypted_identifier(private_key)
    identifier.find("./xenc:EncryptedKey/ds:KeyInfo/ds:KeyName", NS).text = key_name
    assert decrypt(identifier, private_key, key_name=key_name).text == "950000012"


@pytest.mark.parametrize(
    ("element", "attribute"),
    [
        ("data", "MimeType"),
        ("data", "Encoding"),
        ("key", "Type"),
        ("key", "MimeType"),
        ("key", "Encoding"),
    ],
)
def test_accepts_unconsumed_encryption_attributes(
    private_key: rsa.RSAPrivateKey, element: str, attribute: str
) -> None:
    identifier = encrypted_identifier(private_key)
    node = identifier[0] if element == "data" else identifier[1]
    node.set(attribute, "urn:test:unconsumed")
    original_xml = etree.tostring(identifier)
    assert decrypt(identifier, private_key).text == "950000012"
    assert etree.tostring(identifier) == original_xml


@pytest.mark.parametrize("type_value", [NS["xenc"] + "Element", NS["xenc"] + "Content"])
def test_accepts_unconsumed_encrypted_key_type(
    private_key: rsa.RSAPrivateKey, type_value: str
) -> None:
    identifier = encrypted_identifier(private_key)
    identifier[1].set("Type", type_value)
    original_xml = etree.tostring(identifier)
    assert decrypt(identifier, private_key).text == "950000012"
    assert etree.tostring(identifier) == original_xml


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
    other.find("xenc:CipherData/xenc:CipherValue", NS).text = base64.b64encode(
        b"not a key"
    ).decode()
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
    info = etree.Element("{" + NS["ds"] + "}KeyInfo")
    sub(info, "ds", "KeyName").text = "content-key"
    identifier[0].insert(1, info)
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
    info = etree.Element("{" + NS["ds"] + "}KeyInfo")
    sub(info, "ds", "RetrievalMethod", URI=reference)
    identifier[0].insert(1, info)
    if reference == "#key-1":
        assert decrypt(identifier, private_key).text == "950000012"
    else:
        with pytest.raises(ValueError):
            decrypt(identifier, private_key)


def test_selected_data_cipher_reference_is_rejected(
    private_key: rsa.RSAPrivateKey,
) -> None:
    identifier = encrypted_identifier(private_key)
    cipher = identifier[0].find("xenc:CipherData", NS)
    cipher.remove(cipher.find("xenc:CipherValue", NS))
    sub(
        cipher,
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


def test_ignores_external_references_in_unselected_key(
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
    original_xml = etree.tostring(identifier)
    assert decrypt(identifier, private_key).text == "950000012"
    assert etree.tostring(identifier) == original_xml


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


@pytest.mark.parametrize("wrapped_size", [0, 1, 15, 16, 24, 31, 33, 48, 64])
def test_rejects_wrapped_key_not_exactly_256_bits(
    private_key: rsa.RSAPrivateKey,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    wrapped_size: int,
) -> None:
    content_key = os.urandom(32)
    identifier = encrypted_identifier(private_key, content_key=content_key)
    wrapped_content_key = (
        content_key[:wrapped_size]
        if wrapped_size < 32
        else content_key + os.urandom(wrapped_size - 32)
    )
    wrapped = private_key.public_key().encrypt(
        wrapped_content_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA256(), label=None
        ),
    )
    identifier.find(
        "./xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue", NS
    ).text = base64.b64encode(wrapped).decode()
    original_xml = etree.tostring(identifier)

    caplog.set_level("INFO")
    capfd.readouterr()
    with pytest.raises(ValueError, match="^Invalid encrypted identifier$") as caught:
        decrypt(identifier, private_key)
    captured = capfd.readouterr()
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None
    assert captured.out == captured.err == caplog.text == ""
    assert etree.tostring(identifier) == original_xml


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
        NAMEID.replace(b"950000012", b"9500<!--split-->00012"),
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


def test_decrypt_large_plaintext_without_application_size_limit(
    private_key: rsa.RSAPrivateKey,
) -> None:
    plaintext = b" " * 2_097_153 + NAMEID
    identifier = encrypted_identifier(private_key, plaintext=plaintext)
    assert len(etree.tostring(identifier)) > 2_097_152
    result = decrypt(identifier, private_key)
    assert result.text == "950000012"


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
