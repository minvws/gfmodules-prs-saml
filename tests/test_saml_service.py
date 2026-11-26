import base64
import copy
import sys
import traceback
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from functools import wraps
from pathlib import Path
from types import FrameType
from typing import Any, NoReturn, Self, cast

import pytest
import xmlsec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from lxml import etree
from saml2 import create_class_from_xml_string, saml, samlp, time_util
from saml2.response import AuthnResponse, StatusResponse
from saml2.xml.schema import XMLSchemaError
from saml2.xml.schema import validate as validate_schema

import app.saml.decryption as decryption_module
import app.saml.service as service_module
import app.saml.signatures as signatures_module
from app.saml.decryption import decrypt_identifier as actual_decrypt_identifier
from app.saml.errors import SamlFailureReason, SamlRejected
from app.saml.service import SamlService, SamlUnavailable
from app.saml.signatures import verify_signature as actual_verify_signature
from app.saml.xml import NS
from app.saml.xml import parse_xml as actual_parse_xml
from tests.saml_helpers import (
    BSN,
    LOA,
    NAMEID,
    OAEP11,
    SOAP11,
    SOAP12,
    Bundle,
    artifact_from_message,
    encrypted_identifier,
    instant,
    make_bundle,
    message,
    sign,
    signed_artifact,
    soap_message,
)


def _artifact_xml(encoded: str) -> str:
    return cast(
        str,
        etree.tostring(
            artifact_from_message(encoded), encoding="unicode", with_tail=False
        ),
    )


def signed_message_with_key_name(bundle: Bundle, name: str) -> str:
    artifact = signed_artifact(bundle)
    assertion = artifact.find("./samlp:Response/saml:Assertion", NS)
    assertion.find("./ds:Signature/ds:KeyInfo/ds:KeyName", NS).text = name
    artifact.remove(artifact.find("./ds:Signature", NS))
    sign(artifact, bundle)
    artifact = etree.fromstring(etree.tostring(artifact))
    artifact.find("./ds:Signature/ds:KeyInfo/ds:KeyName", NS).text = name
    return soap_message(artifact)


def test_pysaml2_validates_source_schema_and_conditions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real validators must participate, not just project claims to models."""
    condition_ok = AuthnResponse.condition_ok
    validated: set[str] = set()

    def check(document: str) -> None:
        validate_schema(document)
        validated.add("schema")

    def conditions(self: Any, *args: Any, **kwargs: Any) -> Any:
        result = condition_ok(self, *args, **kwargs)
        validated.add("conditions")
        return result

    monkeypatch.setattr(signatures_module, "validate_schema", check)
    monkeypatch.setattr(AuthnResponse, "condition_ok", conditions)
    bundle = make_bundle(tmp_path)
    result = SamlService(bundle.config).decrypt(message(bundle))

    assert result.personalId == "NL:bsn:" + BSN
    assert result.authnContextClassRef == LOA
    assert validated == {"schema", "conditions"}


def test_signed_typed_service_uuid_uses_pysaml_validators(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = make_bundle(tmp_path)

    def typed_service(root: etree._Element) -> None:
        assertion = root.find("./samlp:Response/saml:Assertion", NS)
        advice = assertion.find("./saml:Advice", NS)
        assertion.remove(advice)
        assertion.insert(
            assertion.index(assertion.find("./saml:Conditions", NS)) + 1, advice
        )
        service = assertion.find(
            "./saml:AttributeStatement/saml:Attribute"
            "[@Name='urn:nl-eid-gdi:1.0:ServiceUUID']",
            NS,
        )
        old = service.find("./saml:AttributeValue", NS)
        value = etree.Element(
            etree.QName(NS["saml"], "AttributeValue"),
            nsmap={
                "xsi": "http://www.w3.org/2001/XMLSchema-instance",
                "xs": "http://www.w3.org/2001/XMLSchema",
            },
        )
        value.set("{http://www.w3.org/2001/XMLSchema-instance}type", "xs:string")
        value.text = old.text
        service.replace(old, value)

    artifact = signed_artifact(bundle, typed_service)
    validate_schema(etree.tostring(artifact, encoding="unicode"))
    calls: set[str] = set()
    condition_ok = AuthnResponse.condition_ok

    def check(document: str) -> None:
        validate_schema(document)
        calls.add("schema")

    def conditions(self: Any, *args: Any, **kwargs: Any) -> Any:
        result = condition_ok(self, *args, **kwargs)
        calls.add("conditions")
        return result

    monkeypatch.setattr(signatures_module, "validate_schema", check)
    monkeypatch.setattr(AuthnResponse, "condition_ok", conditions)
    result = SamlService(bundle.config).decrypt(soap_message(artifact))
    assert result.personalId == "NL:bsn:" + BSN
    assert result.authnContextClassRef == LOA
    assert calls == {"schema", "conditions"}


def test_rejects_signed_assertion_with_advice_after_statements(tmp_path: Path) -> None:
    """A reordered model must not make an invalid original document valid."""
    bundle = make_bundle(tmp_path)

    def move_advice(root: etree._Element) -> None:
        assertion = root.find("./samlp:Response/saml:Assertion", NS)
        advice = assertion.find("./saml:Advice", NS)
        assertion.remove(advice)
        assertion.append(advice)

    with pytest.raises(ValueError, match="^Invalid SAML response$"):
        SamlService(bundle.config).decrypt(message(bundle, move_advice))


@pytest.mark.parametrize("expired", [False, True])
def test_pysaml_validation_does_not_log_signed_subject_or_errors(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, expired: bool
) -> None:
    bundle = make_bundle(tmp_path)
    marker = "synthetic-subject-must-not-be-logged"

    def mutate(root: etree._Element) -> None:
        assertion = root.find("./samlp:Response/saml:Assertion", NS)
        assertion.find("./saml:Subject/saml:NameID", NS).text = marker
        if expired:
            assertion.find("./saml:Conditions", NS).set("NotBefore", instant(60))

    caplog.set_level("INFO")
    service = SamlService(bundle.config)
    encoded = message(bundle, mutate)
    if expired:
        with pytest.raises(ValueError, match="^Invalid SAML response$"):
            service.decrypt(encoded)
    else:
        assert service.decrypt(encoded).personalId == "NL:bsn:" + BSN
    assert caplog.text == ""


def exception_graph_contains(error: BaseException, detail: str) -> bool:
    pending = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if detail in str(current) or detail in "".join(
            traceback.format_exception(current)
        ):
            return True
        if current.__context__ is not None:
            pending.append(current.__context__)
        if current.__cause__ is not None:
            pending.append(current.__cause__)
    return False


def app_traceback_contains(error: BaseException, markers: tuple[str, ...]) -> bool:
    """Inspect rendered locals and nested containers/XML without displaying values."""
    app_dir = Path(service_module.__file__).resolve().parents[1]
    report = traceback.TracebackException.from_exception(error, capture_locals=True)
    for summary in report.stack:
        if Path(summary.filename).resolve().is_relative_to(app_dir) and any(
            marker in value
            for value in (summary.locals or {}).values()
            for marker in markers
        ):
            return True

    pending: list[object] = []
    tb = error.__traceback__
    while tb is not None:
        frame = tb.tb_frame
        if Path(frame.f_code.co_filename).resolve().is_relative_to(app_dir):
            pending.extend(frame.f_locals.values())
        tb = tb.tb_next
    seen: set[int] = set()
    while pending:
        value = pending.pop()
        if id(value) in seen:
            continue
        seen.add(id(value))
        if isinstance(value, str):
            if any(marker in value for marker in markers):
                return True
        elif isinstance(value, bytes):
            if any(marker.encode() in value for marker in markers):
                return True
        elif isinstance(value, dict):
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, (list, tuple, set, frozenset)):
            if (
                isinstance(value, (list, tuple))
                and all(isinstance(item, int) and 0 <= item <= 9 for item in value)
                and "".join(str(item) for item in value) in markers
            ):
                return True
            pending.extend(value)
        elif isinstance(value, etree._Element):
            for node in value.iter():
                pending.extend((node.text, node.tail, *node.attrib.values()))
    return False


@pytest.mark.parametrize("failure", ["invalid", "unavailable"])
def test_sanitized_service_traceback_does_not_retain_request(
    tmp_path: Path, failure: str
) -> None:
    bundle = make_bundle(tmp_path)
    service = SamlService(bundle.config)
    expected_type: type[ValueError]
    if failure == "unavailable":
        from dataclasses import replace
        from datetime import UTC, datetime, timedelta

        service.material = replace(
            service.material, valid_until=datetime.now(UTC) - timedelta(seconds=1)
        )
        encoded = message(bundle)
        expected_type = SamlUnavailable
        expected_message = "SAML configuration expired"
    else:
        encoded = base64.b64encode(b"<synthetic-private-input/>").decode()
        expected_type = ValueError
        expected_message = "Invalid SAML response"

    with pytest.raises(expected_type) as caught:
        service.decrypt(encoded)
    error = caught.value
    assert str(error) == expected_message
    assert error.__cause__ is None and error.__context__ is None
    assert any(
        frame.name == "decrypt" for frame in traceback.extract_tb(error.__traceback__)
    )
    if app_traceback_contains(error, (encoded,)):
        pytest.fail("Request remained in application traceback locals", pytrace=False)


@pytest.mark.parametrize("interrupt_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("moment", ["entry", "digits"])
@pytest.mark.parametrize("ambient_exception", [False, True])
def test_interrupt_in_bsn_does_not_retain_request_or_identity(
    tmp_path: Path,
    interrupt_type: type[BaseException],
    moment: str,
    ambient_exception: bool,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    bundle = make_bundle(tmp_path)
    service = SamlService(bundle.config)
    encoded = message(bundle)
    expected = interrupt_type(37) if interrupt_type is SystemExit else interrupt_type()
    seen: list[bool] = []
    code = service_module.SamlService._bsn.__code__

    def trace(frame: FrameType, event: str, arg: Any) -> Any:
        del arg
        if (
            event == "line"
            and frame.f_code is code
            and (moment == "entry" or "digits" in frame.f_locals)
        ):
            seen.append(True)
            sys.settrace(None)
            raise expected
        return trace

    def capture_error() -> BaseException:
        previous_trace = sys.gettrace()
        try:
            sys.settrace(trace)
            with pytest.raises(interrupt_type) as caught:
                service.decrypt(encoded)
        finally:
            sys.settrace(previous_trace)
        return caught.value

    caplog.set_level("DEBUG")
    capfd.readouterr()
    if ambient_exception:
        try:
            raise RuntimeError("synthetic ambient context")
        except RuntimeError:
            error = capture_error()
    else:
        error = capture_error()
    captured = capfd.readouterr()
    assert error is expected and seen == [True]
    if isinstance(error, SystemExit):
        assert error.code == 37
    assert error.__cause__ is None and error.__context__ is None
    assert captured.out == captured.err == caplog.text == ""
    frames = traceback.extract_tb(error.__traceback__)
    assert {"decrypt", "_decrypt", "_identity", "_bsn"} <= {
        frame.name for frame in frames
    }
    request_retained = app_traceback_contains(error, (encoded,))
    identity_retained = app_traceback_contains(error, (BSN,))
    if request_retained or identity_retained:
        pytest.fail(
            "Application traceback retained request="
            f"{request_retained}, identity={identity_retained}",
            pytrace=False,
        )


@pytest.mark.parametrize("scenario", ["multiple_values", "representation"])
@pytest.mark.parametrize("interrupt_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("ambient_exception", [False, True])
def test_interrupted_later_identity_does_not_retain_prior_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    scenario: str,
    interrupt_type: type[BaseException],
    ambient_exception: bool,
) -> None:
    bundle = make_bundle(tmp_path)
    bundle.config.allow_representation = scenario == "representation"

    def add_later_identity(root: etree._Element) -> None:
        attributes = root.find(
            "./samlp:Response/saml:Assertion/saml:AttributeStatement", NS
        )
        acting = attributes.find(
            "./saml:Attribute[@Name='urn:nl-eid-gdi:1.0:ActingSubjectID']", NS
        )
        if scenario == "multiple_values":
            second = copy.deepcopy(acting.find("./saml:AttributeValue", NS))
            acting.append(second)
        else:
            second = copy.deepcopy(acting)
            second.set("Name", "urn:nl-eid-gdi:1.0:LegalSubjectID")
            attributes.append(second)
        second.find(".//xenc:EncryptedData", NS).set("Id", "_second_encrypted")

    encoded = message(bundle, add_later_identity)
    service = SamlService(bundle.config)
    result = service.decrypt(encoded)
    assert result.personalId == "NL:bsn:" + BSN
    assert result.representedPersonalId == (
        "NL:bsn:" + BSN if scenario == "representation" else None
    )
    expected = interrupt_type(37) if interrupt_type is SystemExit else interrupt_type()
    real_decrypt = actual_decrypt_identifier
    prior_nodes: list[etree._Element] = []
    original_roots: list[etree._Element] = []
    original_trees: list[bytes] = []
    calls: list[str] = []
    interrupted: list[bool] = []
    parser_code = actual_parse_xml.__code__

    def observe_source(data: bytes) -> etree._Element:
        root = actual_parse_xml(data)
        original_roots.append(root)
        original_trees.append(etree.tostring(root))
        return root

    def observe_decryption(
        encrypted_id: etree._Element,
        private_key: rsa.RSAPrivateKey,
        recipient: str,
        key_name: str,
    ) -> etree._Element:
        calls.append("decrypt")
        if len(calls) == 1:
            name_id = real_decrypt(encrypted_id, private_key, recipient, key_name)
            prior_nodes.append(name_id)
            return name_id

        def trace(frame: FrameType, event: str, arg: Any) -> Any:
            del arg
            if event == "line" and frame.f_code is parser_code:
                interrupted.append(True)
                sys.settrace(None)
                raise expected
            return trace

        previous_trace = sys.gettrace()
        try:
            sys.settrace(trace)
            return real_decrypt(encrypted_id, private_key, recipient, key_name)
        finally:
            sys.settrace(previous_trace)

    monkeypatch.setattr(service_module, "parse_xml", observe_source)
    monkeypatch.setattr(service_module, "decrypt_identifier", observe_decryption)

    def capture_error() -> BaseException:
        with pytest.raises(interrupt_type) as caught:
            service.decrypt(encoded)
        return caught.value

    caplog.set_level("DEBUG")
    capfd.readouterr()
    if ambient_exception:
        try:
            raise RuntimeError("synthetic ambient context")
        except RuntimeError:
            error = capture_error()
    else:
        error = capture_error()
    captured = capfd.readouterr()

    assert error is expected
    assert calls == ["decrypt", "decrypt"]
    assert interrupted == [True]
    assert len(prior_nodes) == 1 and prior_nodes[0].text == BSN
    if isinstance(error, SystemExit):
        assert error.code == 37
    assert error.__cause__ is None and error.__context__ is None
    assert etree.tostring(original_roots[0]) == original_trees[0]
    assert captured.out == captured.err == caplog.text == ""

    report = traceback.TracebackException.from_exception(error, capture_locals=True)
    service_path = Path(service_module.__file__).resolve()
    report_frames = [
        frame
        for frame in report.stack
        if Path(frame.filename).resolve() == service_path
    ]
    assert any(frame.name == "_identity" for frame in report_frames)
    assert any(frame.name == "_decrypt" for frame in report_frames)
    identifier_retained = any(
        BSN in value
        for frame in report_frames
        for value in (frame.locals or {}).values()
    )

    def contains_prior_name_id(value: object) -> bool:
        pending = [value]
        seen: set[int] = set()
        while pending:
            current = pending.pop()
            if current is prior_nodes[0]:
                return True
            if id(current) in seen:
                continue
            seen.add(id(current))
            if isinstance(current, dict):
                pending.extend(current.keys())
                pending.extend(current.values())
            elif isinstance(current, (list, tuple, set, frozenset)):
                pending.extend(current)
        return False

    prior_name_id_retained = False
    tb = error.__traceback__
    while tb is not None:
        frame = tb.tb_frame
        if Path(frame.f_code.co_filename).resolve() == service_path:
            prior_name_id_retained |= any(
                contains_prior_name_id(value) for value in frame.f_locals.values()
            )
        tb = tb.tb_next
    assert not identifier_retained and not prior_name_id_retained, (
        "Prior identity remained in service traceback locals: "
        f"identifier={identifier_retained}, name_id={prior_name_id_retained}"
    )


@pytest.mark.parametrize("ambient_exception", [False, True])
def test_xmlsec_errors_do_not_escape_service_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    ambient_exception: bool,
) -> None:
    bundle = make_bundle(tmp_path)
    service = SamlService(bundle.config)
    encoded = message(bundle)
    secret = "sensitive-xmlsec-service-error"
    calls: list[bool] = []

    class BadContext:
        def decrypt(self, node: etree._Element) -> bytes:
            del node
            calls.append(True)
            try:
                raise RuntimeError(secret)
            except RuntimeError as cause:
                raise xmlsec.Error("decryption failed") from cause

    def context(manager: xmlsec.KeysManager) -> BadContext:
        del manager
        return BadContext()

    assert hasattr(decryption_module, "xmlsec")
    monkeypatch.setattr(xmlsec, "EncryptionContext", context)

    def capture_error() -> ValueError:
        with pytest.raises(ValueError, match="^Invalid SAML response$") as error:
            service.decrypt(encoded)
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
    assert not exception_graph_contains(error, secret)
    assert error.__context__ is None
    assert error.__cause__ is None
    assert captured.out == captured.err == caplog.text == ""


def test_bad_wrapped_key_is_private_at_service_boundary(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    bundle = make_bundle(tmp_path)

    def corrupt_key(root: etree._Element) -> None:
        value = root.find(".//xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue", NS)
        ciphertext = bytearray(base64.b64decode(value.text))
        ciphertext[0] ^= 1
        value.text = base64.b64encode(ciphertext).decode()

    service = SamlService(bundle.config)
    encoded = message(bundle, corrupt_key)
    caplog.set_level("INFO")
    capfd.readouterr()
    with pytest.raises(ValueError, match="^Invalid SAML response$") as caught:
        service.decrypt(encoded)
    captured = capfd.readouterr()

    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None
    assert captured.out == captured.err == caplog.text == ""


def test_verified_original_encrypted_id_drives_real_decryption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Decrypt the original authenticated element without changing its tree."""
    bundle = make_bundle(tmp_path)
    roots: list[etree._Element] = []
    originals: list[bytes] = []
    verified: list[etree._Element] = []
    seen: list[etree._Element] = []

    def parse(data: bytes) -> etree._Element:
        root = actual_parse_xml(data)
        roots.append(root)
        originals.append(etree.tostring(root))
        return root

    def verify(node: etree._Element, certificates: dict[str, bytes]) -> Any:
        result = actual_verify_signature(node, certificates)
        verified.append(node)
        return result

    def decrypt(
        encrypted_id: etree._Element,
        private_key: rsa.RSAPrivateKey,
        recipient: str,
        key_name: str,
    ) -> etree._Element:
        assert isinstance(encrypted_id, etree._Element)
        assert encrypted_id.getroottree().getroot() is roots[0]
        assert [etree.QName(node).localname for node in verified] == [
            "ArtifactResponse",
            "Assertion",
        ]
        assert all(node.getroottree().getroot() is roots[0] for node in verified)
        assert verified[0] in verified[1].iterancestors()
        assert verified[1] in encrypted_id.iterancestors()
        seen.append(encrypted_id)
        result = actual_decrypt_identifier(
            encrypted_id, private_key, recipient, key_name
        )
        assert etree.tostring(roots[0]) == originals[0]
        return result

    monkeypatch.setattr(service_module, "parse_xml", parse)
    monkeypatch.setattr(service_module, "verify_signature", verify)
    monkeypatch.setattr(service_module, "decrypt_identifier", decrypt)
    encoded = message(bundle)
    result = SamlService(bundle.config).decrypt(encoded)
    assert result.personalId == "NL:bsn:" + BSN
    assert len(seen) == 1
    assert etree.tostring(roots[0]) == originals[0]


@pytest.mark.parametrize(
    "invalid",
    [
        "duplicate_data",
        "duplicate_data_method",
        "duplicate_key_method",
        "duplicate_cipher_value",
        "duplicate_key_info",
        "missing_data",
        "missing_cipher",
        "invalid_data_base64",
        "invalid_key_base64",
        "invalid_oaep_label",
        "out_of_order_data",
        "out_of_order_key",
    ],
)
def test_signed_invalid_encryption_fails_source_schema_before_decryption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid: str
) -> None:
    bundle = make_bundle(tmp_path)

    def invalidate(root: etree._Element) -> None:
        encrypted = root.find(".//saml:EncryptedID", NS)
        data = encrypted.find("./xenc:EncryptedData", NS)
        key = encrypted.find("./xenc:EncryptedKey", NS)
        if invalid == "duplicate_data":
            original = encrypted.find("./xenc:EncryptedData", NS)
            extra = copy.deepcopy(original)
            extra.set("Id", "_duplicate_data")
            original.addnext(extra)
        elif invalid in ("duplicate_data_method", "duplicate_key_method"):
            parent = data if invalid == "duplicate_data_method" else key
            original = parent.find("./xenc:EncryptionMethod", NS)
            original.addnext(copy.deepcopy(original))
        elif invalid == "duplicate_cipher_value":
            original = data.find("./xenc:CipherData/xenc:CipherValue", NS)
            original.addnext(copy.deepcopy(original))
        elif invalid == "duplicate_key_info":
            original = key.find("./ds:KeyInfo", NS)
            original.addnext(copy.deepcopy(original))
        elif invalid == "missing_data":
            encrypted.remove(data)
        elif invalid == "missing_cipher":
            data.remove(data.find("./xenc:CipherData", NS))
        elif invalid in ("invalid_data_base64", "invalid_key_base64"):
            parent = data if invalid == "invalid_data_base64" else key
            parent.find("./xenc:CipherData/xenc:CipherValue", NS).text = "%%%"
        elif invalid == "invalid_oaep_label":
            method = key.find("./xenc:EncryptionMethod", NS)
            etree.SubElement(method, etree.QName(NS["xenc"], "OAEPparams")).text = "%%%"
        else:
            parent = data if invalid == "out_of_order_data" else key
            parent[:] = list(reversed(parent[:]))

    encoded = message(bundle, invalidate)
    with pytest.raises(XMLSchemaError):
        validate_schema(_artifact_xml(encoded))

    checked: list[str] = []
    schema_documents: list[str] = []
    decryptions: list[str] = []

    def validate_document(document: str) -> None:
        schema_documents.append(document)
        validate_schema(document)

    def verify(node: etree._Element, certificates: dict[str, bytes]) -> Any:
        checked.append(etree.QName(node).localname)
        return actual_verify_signature(node, certificates)

    def decrypt(*args: Any, **kwargs: Any) -> Any:
        decryptions.append("decrypt")
        return actual_decrypt_identifier(*args, **kwargs)

    monkeypatch.setattr(service_module, "verify_signature", verify)
    monkeypatch.setattr(service_module, "decrypt_identifier", decrypt)
    monkeypatch.setattr(signatures_module, "validate_schema", validate_document)
    with pytest.raises(ValueError, match="^Invalid SAML response$"):
        SamlService(bundle.config).decrypt(encoded)
    assert checked == ["ArtifactResponse"]
    assert schema_documents == [_artifact_xml(encoded)]
    assert decryptions == []


@contextmanager
def observe_decryption(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[list[tuple[str, bytes]], list[bytes], list[bytes], list[bool]]]:
    inputs: list[tuple[str, bytes]] = []
    matches: list[bytes] = []
    opens: list[bytes] = []
    contexts: list[bool] = []
    original_context = xmlsec.EncryptionContext

    def context(manager: xmlsec.KeysManager | None = None) -> object:
        contexts.append(True)
        inner = original_context(manager)

        class Observed:
            @property
            def key(self) -> xmlsec.Key | None:
                return inner.key

            @key.setter
            def key(self, value: xmlsec.Key) -> None:
                inner.key = value

            def decrypt(self, node: etree._Element) -> bytes | etree._Element:
                inputs.append((etree.QName(node).localname, etree.tostring(node)))
                return inner.decrypt(node)

        return Observed()

    def match(uri: bytes) -> bool:
        matches.append(uri)
        return True

    def open_uri(uri: bytes) -> bytes:
        opens.append(uri)
        return b""

    def read_uri(_: bytes, __: memoryview) -> int:
        return 0

    def close_uri(_: bytes) -> None:
        pass

    with monkeypatch.context() as patch:
        patch.setattr(xmlsec, "EncryptionContext", context)
        xmlsec.cleanup_callbacks()
        try:
            xmlsec.register_callbacks(match, open_uri, read_uri, close_uri)
            yield inputs, matches, opens, contexts
        finally:
            xmlsec.cleanup_callbacks()
            xmlsec.register_default_callbacks()


@contextmanager
def observe_decryption_with_callback_restoration(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[list[tuple[str, bytes]], list[bytes], list[bytes], list[bool]]]:
    callback_events: list[str] = []
    cleanup = xmlsec.cleanup_callbacks
    register_defaults = xmlsec.register_default_callbacks

    def clean() -> None:
        cleanup()
        callback_events.append("cleanup")

    def restore() -> None:
        register_defaults()
        callback_events.append("defaults")

    with monkeypatch.context() as patch:
        patch.setattr(xmlsec, "cleanup_callbacks", clean)
        patch.setattr(xmlsec, "register_default_callbacks", restore)
        try:
            with observe_decryption(patch) as observations:
                yield observations
        finally:
            assert callback_events == ["cleanup", "cleanup", "defaults"]


_NESTED_SIGNATURE_URI = "file:///synthetic-never-opened"


def _signed_nested_signature_artifact(bundle: Bundle, placement: str) -> etree._Element:
    def add_signature(root: etree._Element) -> None:
        attributes = root.find(
            "./samlp:Response/saml:Assertion/saml:AttributeStatement", NS
        )
        if placement == "unused_attribute":
            attribute = etree.SubElement(
                attributes, etree.QName(NS["saml"], "Attribute"), Name="urn:test:unused"
            )
            value = etree.SubElement(
                attribute, etree.QName(NS["saml"], "AttributeValue")
            )
        else:
            assert placement == "acting_value"
            value = attributes.find(
                "./saml:Attribute[@Name='urn:nl-eid-gdi:1.0:ActingSubjectID']/"
                "saml:AttributeValue",
                NS,
            )

        # A schema-valid but independently invalid signature with an untrusted key.
        signature = etree.SubElement(value, etree.QName(NS["ds"], "Signature"))
        signed_info = etree.SubElement(signature, etree.QName(NS["ds"], "SignedInfo"))
        etree.SubElement(
            signed_info,
            etree.QName(NS["ds"], "CanonicalizationMethod"),
            Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
        )
        etree.SubElement(
            signed_info,
            etree.QName(NS["ds"], "SignatureMethod"),
            Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        )
        reference = etree.SubElement(
            signed_info, etree.QName(NS["ds"], "Reference"), URI=_NESTED_SIGNATURE_URI
        )
        etree.SubElement(
            reference,
            etree.QName(NS["ds"], "DigestMethod"),
            Algorithm=NS["xenc"] + "sha256",
        )
        etree.SubElement(
            reference, etree.QName(NS["ds"], "DigestValue")
        ).text = base64.b64encode(b"\0" * 32).decode()
        etree.SubElement(
            signature, etree.QName(NS["ds"], "SignatureValue")
        ).text = base64.b64encode(b"\0" * 256).decode()
        info = etree.SubElement(signature, etree.QName(NS["ds"], "KeyInfo"))
        etree.SubElement(info, etree.QName(NS["ds"], "KeyName")).text = "unused-key"

    return signed_artifact(bundle, add_signature)


def _fail_sanitized(message: str) -> NoReturn:
    try:
        pytest.fail(message, pytrace=False)
    except pytest.fail.Exception as error:
        # Even an already-handled exception in the caller becomes context.
        error.__cause__ = None
        error.__context__ = None
        raise


def _assert_no_decryption_activity(
    inputs: list[tuple[str, bytes]],
    matches: list[bytes],
    opens: list[bytes],
    contexts: list[bool],
) -> None:
    if inputs or matches or opens or contexts:
        # Full tracebacks may render the shared lists in this and caller frames.
        inputs.clear()
        matches.clear()
        opens.clear()
        contexts.clear()
        _fail_sanitized("Unexpected decryption activity")


def _validate_nested_artifact(artifact: etree._Element) -> None:
    failed = False
    try:
        validate_schema(etree.tostring(artifact, encoding="unicode"))
    except Exception:  # noqa: BLE001 - schema errors may include the input
        failed = True
    if failed:
        _fail_sanitized("Signed fixture failed schema validation")


@pytest.mark.parametrize("placement", ["unused_attribute", "acting_value"])
@pytest.mark.parametrize("response_signed", [False, True])
def test_signed_unused_nested_signature_is_inert(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    placement: str,
    response_signed: bool,
) -> None:
    bundle = make_bundle(tmp_path)
    artifact = _signed_nested_signature_artifact(bundle, placement)
    if response_signed:
        artifact.remove(artifact.find("./ds:Signature", NS))
        sign(artifact.find("./samlp:Response", NS), bundle)
        sign(artifact, bundle)
    _validate_nested_artifact(artifact)
    encoded = soap_message(artifact)
    roots: list[etree._Element] = []
    originals: list[bytes] = []
    verified: list[str] = []

    def parse(data: bytes) -> etree._Element:
        root = actual_parse_xml(data)
        roots.append(root)
        originals.append(etree.tostring(root))
        return root

    def verify(node: etree._Element, certificates: dict[str, bytes]) -> Any:
        assert node.getroottree().getroot() is roots[0]
        nested = node.find(".//saml:AttributeValue/ds:Signature", NS)
        assert nested is not None
        if (
            nested.find("./ds:SignedInfo/ds:Reference", NS).get("URI")
            != _NESTED_SIGNATURE_URI
        ):
            _fail_sanitized("Nested signature reference changed")
        result = actual_verify_signature(node, certificates)
        verified.append(etree.QName(node).localname)
        if etree.tostring(roots[0]) != originals[0]:
            _fail_sanitized("Original signed tree changed during verification")
        return result

    monkeypatch.setattr(service_module, "parse_xml", parse)
    monkeypatch.setattr(service_module, "verify_signature", verify)
    expected = ["ArtifactResponse", "Assertion"]
    if response_signed:
        expected.append("Response")
    failed = False
    try:
        with observe_decryption_with_callback_restoration(monkeypatch) as (
            inputs,
            matches,
            opens,
            contexts,
        ):
            result = SamlService(bundle.config).decrypt(encoded)
    except Exception:  # noqa: BLE001 - native errors may contain the input
        failed = True
    if failed:
        _fail_sanitized("Unexpected service exception")

    if result.personalId != "NL:bsn:" + BSN:
        _fail_sanitized("Unexpected decrypted identity")
    assert verified == expected
    assert [name for name, _ in inputs] == ["EncryptedKey", "EncryptedData"]
    if any(_NESTED_SIGNATURE_URI.encode() in node for _, node in inputs):
        _fail_sanitized("Nested signature reached a decryption input")
    if matches or opens:
        _fail_sanitized("Unexpected URI callback")
    assert contexts == [True, True]
    if etree.tostring(roots[0]) != originals[0]:
        _fail_sanitized("Original signed tree changed during decryption")


@pytest.mark.parametrize("placement", ["unused_attribute", "acting_value"])
@pytest.mark.parametrize("resign_artifact", [False, True])
def test_signed_nested_signature_tampering_is_rejected_before_decryption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    placement: str,
    resign_artifact: bool,
) -> None:
    bundle = make_bundle(tmp_path)
    artifact = _signed_nested_signature_artifact(bundle, placement)
    value = artifact.find(".//saml:AttributeValue/ds:Signature/ds:SignatureValue", NS)
    value.text = base64.b64encode(b"\1" * 256).decode()
    if resign_artifact:
        artifact.remove(artifact.find("./ds:Signature", NS))
        sign(artifact, bundle)
    _validate_nested_artifact(artifact)
    encoded = soap_message(artifact)
    attempted: list[str] = []
    verified: list[str] = []

    def verify(node: etree._Element, certificates: dict[str, bytes]) -> Any:
        name = etree.QName(node).localname
        attempted.append(name)
        result = actual_verify_signature(node, certificates)
        verified.append(name)
        return result

    monkeypatch.setattr(service_module, "verify_signature", verify)
    try:
        with observe_decryption_with_callback_restoration(monkeypatch) as (
            inputs,
            matches,
            opens,
            contexts,
        ):
            SamlService(bundle.config).decrypt(encoded)
    except Exception as error:  # noqa: BLE001 - native errors may contain the input
        sanitized = (
            isinstance(error, SamlRejected)
            and error.reason is SamlFailureReason.SIGNATURE_FAILED
            and str(error) == "Invalid SAML response"
            and error.__cause__ is None
            and error.__context__ is None
        )
    else:
        _fail_sanitized("Tampered signed content was accepted")
    if not sanitized:
        _fail_sanitized("Service rejection was not sanitized")
    assert attempted == (
        ["ArtifactResponse", "Assertion"] if resign_artifact else ["ArtifactResponse"]
    )
    assert verified == (["ArtifactResponse"] if resign_artifact else [])
    if inputs or matches or opens or contexts:
        _fail_sanitized("Tampering reached decryption or URI callbacks")


@pytest.mark.parametrize("placement", ["unused_attribute", "acting_value"])
def test_nested_signature_does_not_hide_invalid_present_response_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, placement: str
) -> None:
    bundle = make_bundle(tmp_path)
    artifact = _signed_nested_signature_artifact(bundle, placement)
    artifact.remove(artifact.find("./ds:Signature", NS))
    response = artifact.find("./samlp:Response", NS)
    sign(response, bundle)
    value = response.find("./ds:Signature/ds:SignatureValue", NS)
    signature = bytearray(base64.b64decode(value.text))
    signature[0] ^= 1
    value.text = base64.b64encode(signature).decode()
    sign(artifact, bundle)
    _validate_nested_artifact(artifact)
    encoded = soap_message(artifact)
    attempted: list[str] = []
    verified: list[str] = []

    def verify(node: etree._Element, certificates: dict[str, bytes]) -> Any:
        name = etree.QName(node).localname
        attempted.append(name)
        result = actual_verify_signature(node, certificates)
        verified.append(name)
        return result

    monkeypatch.setattr(service_module, "verify_signature", verify)
    try:
        with observe_decryption_with_callback_restoration(monkeypatch) as (
            inputs,
            matches,
            opens,
            contexts,
        ):
            SamlService(bundle.config).decrypt(encoded)
    except Exception as error:  # noqa: BLE001 - native errors may contain the input
        sanitized = (
            isinstance(error, SamlRejected)
            and error.reason is SamlFailureReason.SIGNATURE_FAILED
            and str(error) == "Invalid SAML response"
            and error.__cause__ is None
            and error.__context__ is None
        )
    else:
        _fail_sanitized("Invalid present Response signature was accepted")
    if not sanitized:
        _fail_sanitized("Service rejection was not sanitized")
    assert attempted == ["ArtifactResponse", "Assertion", "Response"]
    assert verified == ["ArtifactResponse", "Assertion"]
    if inputs or matches or opens or contexts:
        _fail_sanitized("Invalid Response reached decryption or URI callbacks")


def assert_unselected_reference_is_inert(
    service: SamlService,
    encoded: str,
    monkeypatch: pytest.MonkeyPatch,
    reference: str | None,
) -> None:
    with observe_decryption(monkeypatch) as (inputs, matches, opens, contexts):
        result = service.decrypt(encoded)
    assert result.personalId == "NL:bsn:" + BSN
    assert [name for name, _ in inputs] == ["EncryptedKey", "EncryptedData"]
    if reference and reference != "#":
        assert all(reference.encode() not in node for _, node in inputs)
    assert matches == opens == []
    assert contexts == [True, True]


@pytest.mark.parametrize(
    "reference",
    ["cipher", "other_recipient", "other_recipient_cipher", "other_key_reference"],
)
def test_signed_external_encryption_references_follow_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reference: str
) -> None:
    bundle = make_bundle(tmp_path)

    def add_external_reference(root: etree._Element) -> None:
        encrypted = root.find(".//saml:EncryptedID", NS)
        if reference == "cipher":
            cipher = encrypted.find("./xenc:EncryptedData/xenc:CipherData", NS)
            cipher.remove(cipher.find("./xenc:CipherValue", NS))
            etree.SubElement(
                cipher,
                etree.QName(NS["xenc"], "CipherReference"),
                URI="https://attacker.invalid/cipher",
            )
        else:
            other = copy.deepcopy(encrypted.find("./xenc:EncryptedKey", NS))
            other.set("Recipient", "urn:test:other-recipient")
            if reference == "other_recipient":
                etree.SubElement(
                    other.find("./ds:KeyInfo", NS),
                    etree.QName(NS["ds"], "RetrievalMethod"),
                    URI="https://attacker.invalid/key",
                )
            elif reference == "other_recipient_cipher":
                cipher = other.find("./xenc:CipherData", NS)
                cipher.remove(cipher.find("./xenc:CipherValue", NS))
                etree.SubElement(
                    cipher,
                    etree.QName(NS["xenc"], "CipherReference"),
                    URI="https://attacker.invalid/other-cipher",
                )
            else:
                references = etree.SubElement(
                    other, etree.QName(NS["xenc"], "ReferenceList")
                )
                etree.SubElement(
                    references,
                    etree.QName(NS["xenc"], "KeyReference"),
                    URI="https://attacker.invalid/other-key",
                )
            encrypted.append(other)

    encoded = message(bundle, add_external_reference)
    validate_schema(_artifact_xml(encoded))
    service = SamlService(bundle.config)
    artifact = artifact_from_message(encoded)
    actual_verify_signature(artifact, service.material.certificates)
    actual_verify_signature(
        artifact.find("./samlp:Response/saml:Assertion", NS),
        service.material.certificates,
    )
    if reference == "cipher":
        with (
            observe_decryption(monkeypatch) as (inputs, matches, opens, contexts),
            pytest.raises(ValueError, match="^Invalid SAML response$"),
        ):
            service.decrypt(encoded)
        _assert_no_decryption_activity(inputs, matches, opens, contexts)
    else:
        uri = {
            "other_recipient": "https://attacker.invalid/key",
            "other_recipient_cipher": "https://attacker.invalid/other-cipher",
            "other_key_reference": "https://attacker.invalid/other-key",
        }[reference]
        assert_unselected_reference_is_inert(service, encoded, monkeypatch, uri)


@pytest.mark.parametrize(
    "uri",
    [
        "file:///synthetic-never-opened",
        "https://attacker.invalid/key",
        "relative-key.xml",
        "",
        "#",
        None,
    ],
)
def test_signed_nonlocal_key_info_reference_in_sibling_is_inert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, uri: str | None
) -> None:
    bundle = make_bundle(tmp_path)

    def add_reference(root: etree._Element) -> None:
        encrypted = root.find(".//saml:EncryptedID", NS)
        other = copy.deepcopy(encrypted.find("./xenc:EncryptedKey", NS))
        other.set("Recipient", "urn:test:other-recipient")
        node = etree.SubElement(
            other.find("./ds:KeyInfo", NS),
            etree.QName("http://www.w3.org/2009/xmldsig11#", "KeyInfoReference"),
        )
        if uri is not None:
            node.set("URI", uri)
        encrypted.append(other)

    encoded = message(bundle, add_reference)
    validate_schema(_artifact_xml(encoded))
    service = SamlService(bundle.config)
    artifact = artifact_from_message(encoded)
    actual_verify_signature(artifact, service.material.certificates)
    actual_verify_signature(
        artifact.find("./samlp:Response/saml:Assertion", NS),
        service.material.certificates,
    )
    assert_unselected_reference_is_inert(service, encoded, monkeypatch, uri)


def test_signed_local_key_info_reference_in_sibling_is_ignored(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)

    def add_reference(root: etree._Element) -> None:
        encrypted = root.find(".//saml:EncryptedID", NS)
        local_key = encrypted.find("./xenc:EncryptedKey", NS)
        other = copy.deepcopy(local_key)
        other.set("Recipient", "urn:test:other-recipient")
        local_key.find("./ds:KeyInfo", NS).set("Id", "_local_key_info")
        etree.SubElement(
            other.find("./ds:KeyInfo", NS),
            etree.QName("http://www.w3.org/2009/xmldsig11#", "KeyInfoReference"),
            URI="#_local_key_info",
        )
        encrypted.append(other)

    encoded = message(bundle, add_reference)
    validate_schema(_artifact_xml(encoded))
    assert SamlService(bundle.config).decrypt(encoded).personalId == "NL:bsn:" + BSN


@pytest.mark.parametrize("uri", ["file:///synthetic-never-opened", "#_encrypted"])
def test_selected_key_info_reference_is_rejected_even_when_local(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, uri: str
) -> None:
    bundle = make_bundle(tmp_path)

    def add_reference(root: etree._Element) -> None:
        info = root.find(".//xenc:EncryptedKey/ds:KeyInfo", NS)
        etree.SubElement(
            info,
            etree.QName("http://www.w3.org/2009/xmldsig11#", "KeyInfoReference"),
            URI=uri,
        )

    encoded = message(bundle, add_reference)
    validate_schema(_artifact_xml(encoded))
    with (
        observe_decryption(monkeypatch) as (inputs, matches, opens, contexts),
        pytest.raises(ValueError, match="^Invalid SAML response$"),
    ):
        SamlService(bundle.config).decrypt(encoded)
    _assert_no_decryption_activity(inputs, matches, opens, contexts)


@pytest.mark.parametrize("reference", ["signature_reference", "property_target"])
@pytest.mark.parametrize(
    "uri",
    ["file:///synthetic-never-opened", "relative.xml", "", "#", "#_encrypted", None],
)
def test_signed_sibling_references_are_inert_for_all_uris(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reference: str, uri: str | None
) -> None:
    bundle = make_bundle(tmp_path)

    def add_reference(root: etree._Element) -> None:
        encrypted = root.find(".//saml:EncryptedID", NS)
        other = copy.deepcopy(encrypted.find("./xenc:EncryptedKey", NS))
        other.set("Recipient", "urn:test:other-recipient")
        properties = etree.SubElement(
            other, etree.QName(NS["xenc"], "EncryptionProperties")
        )
        prop = etree.SubElement(
            properties, etree.QName(NS["xenc"], "EncryptionProperty")
        )
        if reference == "signature_reference":
            node = etree.SubElement(prop, etree.QName(NS["ds"], "Reference"))
            etree.SubElement(
                node,
                etree.QName(NS["ds"], "DigestMethod"),
                Algorithm=NS["xenc"] + "sha256",
            )
            etree.SubElement(
                node, etree.QName(NS["ds"], "DigestValue")
            ).text = base64.b64encode(b"\0" * 32).decode()
            if uri is not None:
                node.set("URI", uri)
        else:
            etree.SubElement(prop, etree.QName(NS["ds"], "KeyName")).text = "unused"
            if uri is not None:
                prop.set("Target", uri)
        encrypted.append(other)

    encoded = message(bundle, add_reference)
    validate_schema(_artifact_xml(encoded))
    service = SamlService(bundle.config)
    artifact = artifact_from_message(encoded)
    actual_verify_signature(artifact, service.material.certificates)
    actual_verify_signature(
        artifact.find("./samlp:Response/saml:Assertion", NS),
        service.material.certificates,
    )
    assert_unselected_reference_is_inert(service, encoded, monkeypatch, uri)


@pytest.mark.parametrize("uri", ["file:///synthetic-never-opened", "#_encrypted"])
def test_signed_signature_property_target_on_sibling_is_inert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, uri: str
) -> None:
    bundle = make_bundle(tmp_path)

    def add_reference(root: etree._Element) -> None:
        encrypted = root.find(".//saml:EncryptedID", NS)
        other = copy.deepcopy(encrypted.find("./xenc:EncryptedKey", NS))
        other.set("Recipient", "urn:test:other-recipient")
        properties = etree.SubElement(
            other, etree.QName(NS["xenc"], "EncryptionProperties")
        )
        prop = etree.SubElement(
            properties, etree.QName(NS["xenc"], "EncryptionProperty")
        )
        signature_property = etree.SubElement(
            prop, etree.QName(NS["ds"], "SignatureProperty"), Target=uri
        )
        etree.SubElement(
            signature_property, etree.QName("urn:test:extension", "Value")
        ).text = "unused"
        encrypted.append(other)

    encoded = message(bundle, add_reference)
    validate_schema(_artifact_xml(encoded))
    service = SamlService(bundle.config)
    assert_unselected_reference_is_inert(service, encoded, monkeypatch, uri)


def add_encryption_reference(
    key: etree._Element, data: etree._Element, reference: str, uri: str
) -> None:
    if reference in ("retrieval", "key_info_reference"):
        tag = (
            etree.QName(NS["ds"], "RetrievalMethod")
            if reference == "retrieval"
            else etree.QName("http://www.w3.org/2009/xmldsig11#", "KeyInfoReference")
        )
        etree.SubElement(key.find("./ds:KeyInfo", NS), tag, URI=uri)
    elif reference == "key_reference":
        references = etree.SubElement(key, etree.QName(NS["xenc"], "ReferenceList"))
        etree.SubElement(references, etree.QName(NS["xenc"], "KeyReference"), URI=uri)
    elif reference in (
        "signature_reference",
        "property_target",
        "signature_property_target",
    ):
        properties = etree.SubElement(
            key, etree.QName(NS["xenc"], "EncryptionProperties")
        )
        prop = etree.SubElement(
            properties, etree.QName(NS["xenc"], "EncryptionProperty")
        )
        if reference == "signature_reference":
            node = etree.SubElement(prop, etree.QName(NS["ds"], "Reference"), URI=uri)
            etree.SubElement(
                node,
                etree.QName(NS["ds"], "DigestMethod"),
                Algorithm=NS["xenc"] + "sha256",
            )
            etree.SubElement(
                node, etree.QName(NS["ds"], "DigestValue")
            ).text = base64.b64encode(b"\0" * 32).decode()
        elif reference == "property_target":
            prop.set("Target", uri)
            etree.SubElement(prop, etree.QName(NS["ds"], "KeyName")).text = "unused"
        else:
            signature_property = etree.SubElement(
                prop, etree.QName(NS["ds"], "SignatureProperty"), Target=uri
            )
            etree.SubElement(
                signature_property, etree.QName("urn:test:extension", "Value")
            ).text = "unused"
    else:
        assert reference in ("key_cipher", "data_cipher")
        parent = key if reference == "key_cipher" else data
        cipher = parent.find("./xenc:CipherData", NS)
        cipher.remove(cipher.find("./xenc:CipherValue", NS))
        etree.SubElement(cipher, etree.QName(NS["xenc"], "CipherReference"), URI=uri)


@pytest.mark.parametrize(
    "reference",
    [
        "retrieval",
        "key_cipher",
        "key_reference",
        "data_cipher",
        "key_info_reference",
        "signature_reference",
        "property_target",
        "signature_property_target",
    ],
)
@pytest.mark.parametrize("other_first", [False, True])
def test_skipped_other_recipient_reference_never_reaches_xmlsec_or_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reference: str,
    other_first: bool,
) -> None:
    bundle = make_bundle(tmp_path)
    external = "https://attacker.invalid/skipped-reference"

    def add_other_value(root: etree._Element) -> None:
        attribute = root.find(
            "./samlp:Response/saml:Assertion/saml:AttributeStatement/"
            "saml:Attribute[@Name='urn:nl-eid-gdi:1.0:ActingSubjectID']",
            NS,
        )
        other = copy.deepcopy(attribute.find("./saml:AttributeValue", NS))
        encrypted = other.find("./saml:EncryptedID", NS)
        data = encrypted.find("./xenc:EncryptedData", NS)
        data.set("Id", "_other_data")
        key = encrypted.find("./xenc:EncryptedKey", NS)
        key.set("Recipient", "urn:test:other-recipient")
        add_encryption_reference(key, data, reference, external)
        attribute.insert(0 if other_first else len(attribute), other)

    encoded = message(bundle, add_other_value)
    validate_schema(_artifact_xml(encoded))
    service = SamlService(bundle.config)
    selected: list[etree._Element] = []

    def decrypt(
        encrypted_id: etree._Element,
        private_key: rsa.RSAPrivateKey,
        recipient: str,
        key_name: str,
    ) -> etree._Element:
        selected.append(encrypted_id)
        return actual_decrypt_identifier(encrypted_id, private_key, recipient, key_name)

    monkeypatch.setattr(service_module, "decrypt_identifier", decrypt)
    with observe_decryption(monkeypatch) as (inputs, matches, opens, contexts):
        result = service.decrypt(encoded)

    assert result.personalId == "NL:bsn:" + BSN
    assert len(selected) == 1
    assert selected[0].find("./xenc:EncryptedKey", NS).get("Recipient") == (
        bundle.config.entity_id
    )
    assert [name for name, _ in inputs] == ["EncryptedKey", "EncryptedData"]
    assert all(external.encode() not in node for _, node in inputs)
    assert matches == opens == []
    assert contexts == [True, True]


@pytest.mark.parametrize(
    "reference",
    [
        "retrieval",
        "key_info_reference",
        "key_cipher",
        "key_reference",
        "signature_reference",
        "property_target",
        "signature_property_target",
    ],
)
@pytest.mark.parametrize("other_first", [False, True])
@pytest.mark.parametrize("same_recipient", [False, True])
def test_signed_unselected_key_references_are_inert(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reference: str,
    other_first: bool,
    same_recipient: bool,
) -> None:
    bundle = make_bundle(tmp_path)
    external = "https://attacker.invalid/unselected-reference"

    def add_sibling(root: etree._Element) -> None:
        encrypted = root.find(".//saml:EncryptedID", NS)
        data = encrypted.find("./xenc:EncryptedData", NS)
        selected = encrypted.find("./xenc:EncryptedKey", NS)
        other = copy.deepcopy(selected)
        if same_recipient:
            other.find("./ds:KeyInfo/ds:KeyName", NS).text += "-other"
        else:
            other.set("Recipient", "urn:test:other-recipient")
        add_encryption_reference(other, data, reference, external)
        encrypted.insert(
            encrypted.index(selected) if other_first else len(encrypted), other
        )

    encoded = message(bundle, add_sibling)
    validate_schema(_artifact_xml(encoded))
    assert_unselected_reference_is_inert(
        SamlService(bundle.config), encoded, monkeypatch, external
    )


@pytest.mark.parametrize(
    "ambiguity",
    [
        "duplicate_info",
        "selected_multiple_names",
        "other_multiple_names",
        "other_multiple_wrong_names",
        "other_missing_name",
        "other_empty_name",
        "multiple_matching_keys",
    ],
)
def test_signed_ambiguous_key_info_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ambiguity: str
) -> None:
    bundle = make_bundle(tmp_path)

    def add_ambiguity(root: etree._Element) -> None:
        encrypted = root.find(".//saml:EncryptedID", NS)
        selected = encrypted.find("./xenc:EncryptedKey", NS)
        info = selected.find("./ds:KeyInfo", NS)
        if ambiguity == "duplicate_info":
            info.addnext(copy.deepcopy(info))
        elif ambiguity == "selected_multiple_names":
            etree.SubElement(info, etree.QName(NS["ds"], "KeyName")).text = "other"
        else:
            other = copy.deepcopy(selected)
            other_info = other.find("./ds:KeyInfo", NS)
            name = other_info.find("./ds:KeyName", NS)
            if ambiguity != "multiple_matching_keys":
                name.text += "-other"
            if ambiguity == "other_multiple_names":
                other_info.append(copy.deepcopy(info.find("./ds:KeyName", NS)))
            elif ambiguity == "other_multiple_wrong_names":
                etree.SubElement(
                    other_info, etree.QName(NS["ds"], "KeyName")
                ).text = "another-wrong-name"
            elif ambiguity == "other_missing_name":
                other_info.remove(name)
                etree.SubElement(
                    other_info, etree.QName(NS["ds"], "RetrievalMethod"), URI="#unused"
                )
            elif ambiguity == "other_empty_name":
                name.text = ""
            encrypted.append(other)

    encoded = message(bundle, add_ambiguity)
    if ambiguity == "duplicate_info":
        with pytest.raises(XMLSchemaError):
            validate_schema(_artifact_xml(encoded))
    else:
        validate_schema(_artifact_xml(encoded))
    with (
        observe_decryption(monkeypatch) as (inputs, matches, opens, contexts),
        pytest.raises(ValueError, match="^Invalid SAML response$"),
    ):
        SamlService(bundle.config).decrypt(encoded)
    _assert_no_decryption_activity(inputs, matches, opens, contexts)


@pytest.mark.parametrize(
    "location",
    [
        "control",
        "data_method",
        "key_method",
        "key_digest",
        "data_reference",
        "data_info",
    ],
)
def test_signed_selected_wildcard_descendants(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, location: str
) -> None:
    bundle = make_bundle(tmp_path)
    external = "https://attacker.invalid/descendant"

    def add_descendant(root: etree._Element) -> None:
        if location == "control":
            return
        encrypted = root.find(".//saml:EncryptedID", NS)
        data = encrypted.find("./xenc:EncryptedData", NS)
        key = encrypted.find("./xenc:EncryptedKey", NS)
        if location in ("data_method", "key_method"):
            parent = data if location == "data_method" else key
            method = parent.find("./xenc:EncryptionMethod", NS)
            etree.SubElement(
                method, etree.QName(NS["ds"], "RetrievalMethod"), URI=external
            )
        elif location == "key_digest":
            method = key.find("./xenc:EncryptionMethod", NS)
            digest = etree.SubElement(
                method,
                etree.QName(NS["ds"], "DigestMethod"),
                Algorithm=NS["ds"] + "sha1",
            )
            etree.SubElement(
                digest,
                etree.QName("http://www.w3.org/2009/xmldsig11#", "KeyInfoReference"),
                URI=external,
            )
        elif location == "data_reference":
            references = etree.SubElement(key, etree.QName(NS["xenc"], "ReferenceList"))
            reference = etree.SubElement(
                references, etree.QName(NS["xenc"], "DataReference"), URI="#_encrypted"
            )
            child = etree.SubElement(
                reference, etree.QName(NS["ds"], "Reference"), URI=external
            )
            etree.SubElement(
                child,
                etree.QName(NS["ds"], "DigestMethod"),
                Algorithm=NS["xenc"] + "sha256",
            )
            etree.SubElement(
                child, etree.QName(NS["ds"], "DigestValue")
            ).text = base64.b64encode(b"\0" * 32).decode()
        else:
            key.set("Id", "_selected_key")
            info = etree.Element(etree.QName(NS["ds"], "KeyInfo"))
            data.insert(1, info)
            etree.SubElement(
                info, etree.QName(NS["ds"], "RetrievalMethod"), URI="#_selected_key"
            )
            etree.SubElement(
                info,
                etree.QName("http://www.w3.org/2009/xmldsig11#", "KeyInfoReference"),
                URI=external,
            )

    encoded = message(bundle, add_descendant)
    validate_schema(_artifact_xml(encoded))
    with observe_decryption(monkeypatch) as (inputs, matches, opens, contexts):
        if location == "control":
            result = SamlService(bundle.config).decrypt(encoded)
        else:
            with pytest.raises(ValueError, match="^Invalid SAML response$"):
                SamlService(bundle.config).decrypt(encoded)
    if location == "control":
        assert result.personalId == "NL:bsn:" + BSN
        assert [name for name, _ in inputs] == ["EncryptedKey", "EncryptedData"]
        assert matches == opens == []
        assert contexts == [True, True]
    else:
        _assert_no_decryption_activity(inputs, matches, opens, contexts)


@pytest.mark.parametrize("selected", ["key", "data"])
def test_signed_selected_cipher_reference_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, selected: str
) -> None:
    bundle = make_bundle(tmp_path)
    external = "https://attacker.invalid/selected-cipher"

    def replace_cipher_value(root: etree._Element) -> None:
        encrypted = root.find(".//saml:EncryptedID", NS)
        key = encrypted.find("./xenc:EncryptedKey", NS)
        data = encrypted.find("./xenc:EncryptedData", NS)
        add_encryption_reference(key, data, selected + "_cipher", external)

    encoded = message(bundle, replace_cipher_value)
    validate_schema(_artifact_xml(encoded))
    with (
        observe_decryption(monkeypatch) as (inputs, matches, opens, contexts),
        pytest.raises(ValueError, match="^Invalid SAML response$"),
    ):
        SamlService(bundle.config).decrypt(encoded)
    _assert_no_decryption_activity(inputs, matches, opens, contexts)


@pytest.mark.parametrize("uri", ["#_selected_key", "https://attacker.invalid/key"])
def test_signed_selected_key_reference_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, uri: str
) -> None:
    bundle = make_bundle(tmp_path)

    def add_reference(root: etree._Element) -> None:
        encrypted = root.find(".//saml:EncryptedID", NS)
        key = encrypted.find("./xenc:EncryptedKey", NS)
        data = encrypted.find("./xenc:EncryptedData", NS)
        key.set("Id", "_selected_key")
        add_encryption_reference(key, data, "key_reference", uri)
        etree.SubElement(
            key.find("./xenc:ReferenceList", NS),
            etree.QName(NS["xenc"], "DataReference"),
            URI="#_encrypted",
        )

    encoded = message(bundle, add_reference)
    validate_schema(_artifact_xml(encoded))
    with (
        observe_decryption(monkeypatch) as (inputs, matches, opens, contexts),
        pytest.raises(ValueError, match="^Invalid SAML response$"),
    ):
        SamlService(bundle.config).decrypt(encoded)
    _assert_no_decryption_activity(inputs, matches, opens, contexts)


@pytest.mark.parametrize("selected", ["key", "data"])
@pytest.mark.parametrize(
    "reference", ["property_target", "signature_property_target", "signature_reference"]
)
@pytest.mark.parametrize("uri", ["#_encrypted", "https://attacker.invalid/property"])
def test_signed_selected_encryption_properties_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    selected: str,
    reference: str,
    uri: str,
) -> None:
    bundle = make_bundle(tmp_path)

    def add_properties(root: etree._Element) -> None:
        encrypted = root.find(".//saml:EncryptedID", NS)
        data = encrypted.find("./xenc:EncryptedData", NS)
        key = encrypted.find("./xenc:EncryptedKey", NS)
        add_encryption_reference(
            key if selected == "key" else data, data, reference, uri
        )

    encoded = message(bundle, add_properties)
    validate_schema(_artifact_xml(encoded))
    with (
        observe_decryption(monkeypatch) as (inputs, matches, opens, contexts),
        pytest.raises(ValueError, match="^Invalid SAML response$"),
    ):
        SamlService(bundle.config).decrypt(encoded)
    _assert_no_decryption_activity(inputs, matches, opens, contexts)


def test_signed_selected_local_associations_reach_expected_native_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = make_bundle(tmp_path)

    def add_associations(root: etree._Element) -> None:
        encrypted = root.find(".//saml:EncryptedID", NS)
        data = encrypted.find("./xenc:EncryptedData", NS)
        key = encrypted.find("./xenc:EncryptedKey", NS)
        key.set("Id", "_selected_key")
        info = etree.Element(etree.QName(NS["ds"], "KeyInfo"))
        etree.SubElement(
            info, etree.QName(NS["ds"], "RetrievalMethod"), URI="#_selected_key"
        )
        data.insert(1, info)
        references = etree.SubElement(key, etree.QName(NS["xenc"], "ReferenceList"))
        etree.SubElement(
            references, etree.QName(NS["xenc"], "DataReference"), URI="#_encrypted"
        )

    encoded = message(bundle, add_associations)
    validate_schema(_artifact_xml(encoded))
    with observe_decryption(monkeypatch) as (inputs, matches, opens, contexts):
        result = SamlService(bundle.config).decrypt(encoded)
    assert result.personalId == "NL:bsn:" + BSN
    assert [name for name, _ in inputs] == ["EncryptedKey", "EncryptedData"]
    assert b"DataReference" in inputs[0][1]
    assert b"RetrievalMethod" not in inputs[1][1]
    assert matches == opens == []
    assert contexts == [True, True]


@pytest.mark.parametrize(
    "association",
    ["data", "retrieval", "carried", "data_external", "retrieval_external"],
)
def test_signed_selected_key_must_match_local_association(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, association: str
) -> None:
    bundle = make_bundle(tmp_path)

    def mismatched_association(root: etree._Element) -> None:
        encrypted = root.find(".//saml:EncryptedID", NS)
        data = encrypted.find("./xenc:EncryptedData", NS)
        key = encrypted.find("./xenc:EncryptedKey", NS)
        key.set("Id", "_selected_key")
        uri = (
            "https://attacker.invalid/selected"
            if association.endswith("_external")
            else "#_wrong"
        )
        if association.startswith("data"):
            references = etree.SubElement(key, etree.QName(NS["xenc"], "ReferenceList"))
            etree.SubElement(
                references, etree.QName(NS["xenc"], "DataReference"), URI=uri
            )
        else:
            info = etree.Element(etree.QName(NS["ds"], "KeyInfo"))
            data.insert(1, info)
            if association.startswith("retrieval"):
                etree.SubElement(
                    info, etree.QName(NS["ds"], "RetrievalMethod"), URI=uri
                )
            else:
                etree.SubElement(
                    info, etree.QName(NS["ds"], "KeyName")
                ).text = "content-key"
                etree.SubElement(
                    key, etree.QName(NS["xenc"], "CarriedKeyName")
                ).text = "wrong-key"

    encoded = message(bundle, mismatched_association)
    validate_schema(_artifact_xml(encoded))
    with (
        observe_decryption(monkeypatch) as (inputs, matches, opens, contexts),
        pytest.raises(ValueError, match="^Invalid SAML response$"),
    ):
        SamlService(bundle.config).decrypt(encoded)
    _assert_no_decryption_activity(inputs, matches, opens, contexts)


@pytest.mark.parametrize("invalid", ["rsa_1_5", "duplicate_digest", "duplicate_mgf"])
def test_signed_schema_valid_disallowed_key_transport_is_rejected_before_xmlsec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid: str
) -> None:
    bundle = make_bundle(tmp_path)

    def change_transport(root: etree._Element) -> None:
        key = root.find(".//xenc:EncryptedKey", NS)
        method = key.find("./xenc:EncryptionMethod", NS)
        if invalid == "rsa_1_5":
            value = key.find("./xenc:CipherData/xenc:CipherValue", NS)
            content_key = bundle.decrypt_key.decrypt(
                base64.b64decode(value.text),
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None,
                ),
            )
            value.text = base64.b64encode(
                bundle.decrypt_key.public_key().encrypt(content_key, padding.PKCS1v15())
            ).decode()
            method.set("Algorithm", NS["xenc"] + "rsa-1_5")
        else:
            method.set("Algorithm", NS["xenc11"] + "rsa-oaep")
            tag, algorithm = (
                (etree.QName(NS["ds"], "DigestMethod"), NS["ds"] + "sha1")
                if invalid == "duplicate_digest"
                else (etree.QName(NS["xenc11"], "MGF"), NS["xenc11"] + "mgf1sha1")
            )
            etree.SubElement(method, tag, Algorithm=algorithm)
            etree.SubElement(method, tag, Algorithm=algorithm)

    encoded = message(bundle, change_transport)
    validate_schema(_artifact_xml(encoded))
    calls: list[bool] = []
    original_context = xmlsec.EncryptionContext

    def context(*args: Any, **kwargs: Any) -> Any:
        calls.append(True)
        return original_context(*args, **kwargs)

    monkeypatch.setattr(xmlsec, "EncryptionContext", context)
    with pytest.raises(ValueError, match="^Invalid SAML response$"):
        SamlService(bundle.config).decrypt(encoded)
    assert calls == []


@pytest.mark.parametrize("location", ["key_info", "transport"])
def test_signed_mixed_encryption_content_is_not_lost_before_policy(
    tmp_path: Path, location: str
) -> None:
    bundle = make_bundle(tmp_path)

    def add_mixed_content(root: etree._Element) -> None:
        key = root.find(".//xenc:EncryptedKey", NS)
        if location == "key_info":
            child = key.find("./ds:KeyInfo/ds:KeyName", NS)
        else:
            method = key.find("./xenc:EncryptionMethod", NS)
            child = etree.SubElement(
                method,
                etree.QName(NS["ds"], "DigestMethod"),
                Algorithm=NS["ds"] + "sha1",
            )
        child.tail = "unexpected signed text"

    encoded = message(bundle, add_mixed_content)
    validate_schema(_artifact_xml(encoded))
    with pytest.raises(ValueError, match="^Invalid SAML response$"):
        SamlService(bundle.config).decrypt(encoded)


def split_signed_text(name: etree._Element, split: int) -> None:
    complete = name.text
    assert complete is not None and 0 < split < len(complete)
    name.text = complete[:split]
    comment = etree.Comment("inserted after signing")
    comment.tail = complete[split:]
    name.append(comment)
    assert "".join(name.itertext()) == complete


def _sanitize_key_name_diagnostics(test: Callable[..., None]) -> Callable[..., None]:
    @wraps(test)
    def run(*args: Any, **kwargs: Any) -> None:
        try:
            test(*args, **kwargs)
        except pytest.fail.Exception as error:
            # XFailed is a subclass of Failed; preserve it and other subclasses.
            if type(error) is not pytest.fail.Exception:
                raise
            message = (
                "Unexpected decryption or URI callback"
                if str(error) == "Unexpected decryption or URI callback"
                else "Unexpected key-name test failure"
            )
        except Exception:  # noqa: BLE001 - fixture/native errors may contain input
            message = "Unexpected key-name test failure"
        else:
            return
        _fail_sanitized(message)

    return run


@pytest.mark.parametrize("wrong_suffix", [True, False], ids=["wrong-suffix", "correct"])
@_sanitize_key_name_diagnostics
def test_signed_comment_split_encrypted_key_name_matches_full_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, wrong_suffix: bool
) -> None:
    bundle = make_bundle(tmp_path)

    def add_suffix(root: etree._Element) -> None:
        if wrong_suffix:
            root.find(".//xenc:EncryptedKey/ds:KeyInfo/ds:KeyName", NS).text += "-wrong"

    artifact = signed_artifact(bundle, add_suffix)
    name = artifact.find(".//xenc:EncryptedKey/ds:KeyInfo/ds:KeyName", NS)
    complete = name.text
    split = len(complete) - len("-wrong") if wrong_suffix else len(complete) // 2
    split_signed_text(name, split)

    service = SamlService(bundle.config)
    assertion = artifact.find("./samlp:Response/saml:Assertion", NS)
    validate_schema(etree.tostring(artifact, encoding="unicode"))
    actual_verify_signature(artifact, service.material.certificates)
    actual_verify_signature(assertion, service.material.certificates)
    encoded = soap_message(artifact)
    with observe_decryption(monkeypatch) as (inputs, matches, opens, contexts):
        if wrong_suffix:
            with pytest.raises(ValueError, match="^Invalid SAML response$"):
                service.decrypt(encoded)
        else:
            assert service.decrypt(encoded).personalId == "NL:bsn:" + BSN
    if wrong_suffix:
        if inputs or matches or opens or contexts:
            pytest.fail("Unexpected decryption or URI callback", pytrace=False)
    else:
        assert [name for name, _ in inputs] == ["EncryptedKey", "EncryptedData"]
        assert matches == opens == []
        assert contexts == [True, True]


@pytest.mark.parametrize("split_name", ["data", "carried"])
@pytest.mark.parametrize("wrong_suffix", [True, False], ids=["wrong-suffix", "correct"])
@_sanitize_key_name_diagnostics
def test_signed_comment_split_key_names_are_compared_in_full(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    split_name: str,
    wrong_suffix: bool,
) -> None:
    bundle = make_bundle(tmp_path)
    complete = "content-key"

    def add_names(root: etree._Element) -> None:
        encrypted = root.find(".//saml:EncryptedID", NS)
        data = encrypted.find("./xenc:EncryptedData", NS)
        key = encrypted.find("./xenc:EncryptedKey", NS)
        info = etree.Element(etree.QName(NS["ds"], "KeyInfo"))
        data_name = etree.SubElement(info, etree.QName(NS["ds"], "KeyName"))
        data.insert(1, info)
        carried = etree.SubElement(key, etree.QName(NS["xenc"], "CarriedKeyName"))
        data_name.text = complete + (
            "-wrong" if wrong_suffix and split_name == "data" else ""
        )
        carried.text = complete + (
            "-wrong" if wrong_suffix and split_name == "carried" else ""
        )

    artifact = signed_artifact(bundle, add_names)
    path = (
        ".//xenc:EncryptedData/ds:KeyInfo/ds:KeyName"
        if split_name == "data"
        else ".//xenc:EncryptedKey/xenc:CarriedKeyName"
    )
    split_signed_text(
        artifact.find(path, NS), len(complete) if wrong_suffix else len(complete) // 2
    )

    service = SamlService(bundle.config)
    validate_schema(etree.tostring(artifact, encoding="unicode"))
    actual_verify_signature(artifact, service.material.certificates)
    actual_verify_signature(
        artifact.find("./samlp:Response/saml:Assertion", NS),
        service.material.certificates,
    )
    encoded = soap_message(artifact)
    with observe_decryption(monkeypatch) as (inputs, matches, opens, contexts):
        if wrong_suffix:
            with pytest.raises(ValueError, match="^Invalid SAML response$"):
                service.decrypt(encoded)
        else:
            assert service.decrypt(encoded).personalId == "NL:bsn:" + BSN
    if wrong_suffix:
        if inputs or matches or opens or contexts:
            pytest.fail("Unexpected decryption or URI callback", pytrace=False)
    else:
        assert [name for name, _ in inputs] == ["EncryptedKey", "EncryptedData"]
        assert matches == opens == []
        assert contexts == [True, True]


@pytest.mark.parametrize("other_first", [False, True])
@_sanitize_key_name_diagnostics
def test_signed_unselected_comment_split_key_name_is_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, other_first: bool
) -> None:
    bundle = make_bundle(tmp_path)

    def add_other_key(root: etree._Element) -> None:
        encrypted = root.find(".//saml:EncryptedID", NS)
        selected = encrypted.find("./xenc:EncryptedKey", NS)
        other = copy.deepcopy(selected)
        other.find("./ds:KeyInfo/ds:KeyName", NS).text += "-other"
        other.find("./xenc:CipherData/xenc:CipherValue", NS).text = base64.b64encode(
            b"synthetic-unused-cipher"
        ).decode()
        encrypted.insert(
            encrypted.index(selected) if other_first else len(encrypted), other
        )

    artifact = signed_artifact(bundle, add_other_key)
    keys = artifact.findall(".//saml:EncryptedID/xenc:EncryptedKey", NS)
    selected, other = (keys[1], keys[0]) if other_first else (keys[0], keys[1])
    selected_name = selected.find("./ds:KeyInfo/ds:KeyName", NS).text
    other_name = other.find("./ds:KeyInfo/ds:KeyName", NS)
    assert (
        selected.get("Recipient") == other.get("Recipient") == bundle.config.entity_id
    )
    assert other_name.text == selected_name + "-other"
    split_signed_text(other_name, len(selected_name))

    service = SamlService(bundle.config)
    validate_schema(etree.tostring(artifact, encoding="unicode"))
    actual_verify_signature(artifact, service.material.certificates)
    actual_verify_signature(
        artifact.find("./samlp:Response/saml:Assertion", NS),
        service.material.certificates,
    )
    encoded = soap_message(artifact)
    assert_unselected_reference_is_inert(service, encoded, monkeypatch, None)


@pytest.mark.parametrize("field", ["selected", "data", "carried", "unselected"])
@_sanitize_key_name_diagnostics
def test_signed_keyname_element_child_is_schema_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    bundle = make_bundle(tmp_path)

    def add_element_child(root: etree._Element) -> None:
        encrypted = root.find(".//saml:EncryptedID", NS)
        data = encrypted.find("./xenc:EncryptedData", NS)
        key = encrypted.find("./xenc:EncryptedKey", NS)
        info = etree.Element(etree.QName(NS["ds"], "KeyInfo"))
        data_name = etree.SubElement(info, etree.QName(NS["ds"], "KeyName"))
        data_name.text = "content-key"
        data.insert(1, info)
        carried = etree.SubElement(key, etree.QName(NS["xenc"], "CarriedKeyName"))
        carried.text = "content-key"
        if field == "unselected":
            other = copy.deepcopy(key)
            other.find("./ds:KeyInfo/ds:KeyName", NS).text += "-other"
            encrypted.append(other)
            name = other.find("./ds:KeyInfo/ds:KeyName", NS)
        else:
            name = {
                "selected": key.find("./ds:KeyInfo/ds:KeyName", NS),
                "data": data_name,
                "carried": carried,
            }[field]
        etree.SubElement(
            name, etree.QName("urn:test:invalid", "Child")
        ).text = "invalid"

    artifact = signed_artifact(bundle, add_element_child)
    with pytest.raises(XMLSchemaError):
        validate_schema(etree.tostring(artifact, encoding="unicode"))

    # The library's normal verifier requires valid XSD; check the original
    # signatures directly so schema rejection is not confused with tampering.
    certificate = bundle.signing_certificate.public_bytes(serialization.Encoding.PEM)
    for parent in (
        artifact,
        artifact.find("./samlp:Response/saml:Assertion", NS),
    ):
        context = xmlsec.SignatureContext()
        context.key = xmlsec.Key.from_memory(
            certificate, xmlsec.constants.KeyDataFormatCertPem
        )
        context.register_id(parent, "ID")
        context.verify(parent.find("./ds:Signature", NS))

    attempted: list[bool] = []

    def decrypt(*args: Any, **kwargs: Any) -> etree._Element:
        attempted.append(True)
        return actual_decrypt_identifier(*args, **kwargs)

    monkeypatch.setattr(service_module, "decrypt_identifier", decrypt)
    encoded = soap_message(artifact)
    with (
        observe_decryption(monkeypatch) as (inputs, matches, opens, contexts),
        pytest.raises(ValueError, match="^Invalid SAML response$"),
    ):
        SamlService(bundle.config).decrypt(encoded)
    if attempted or inputs or matches or opens or contexts:
        pytest.fail("Unexpected decryption or URI callback", pytrace=False)


@pytest.mark.parametrize("field", ["key_name", "carried_key_name"])
def test_signed_carriage_return_is_not_normalized_into_matching_key_name(
    tmp_path: Path, field: str
) -> None:
    bundle = make_bundle(tmp_path)
    if field == "key_name":
        bundle.config.decryption_key_name = "test\nkey"

    def mismatched_names(root: etree._Element) -> None:
        encrypted = root.find(".//saml:EncryptedID", NS)
        key = encrypted.find("./xenc:EncryptedKey", NS)
        if field == "key_name":
            key.find("./ds:KeyInfo/ds:KeyName", NS).text = "test\rkey"
        else:
            data = encrypted.find("./xenc:EncryptedData", NS)
            info = etree.Element(etree.QName(NS["ds"], "KeyInfo"))
            etree.SubElement(
                info, etree.QName(NS["ds"], "KeyName")
            ).text = "content\rkey"
            data.insert(1, info)
            etree.SubElement(
                key, etree.QName(NS["xenc"], "CarriedKeyName")
            ).text = "content\nkey"

    encoded = message(bundle, mismatched_names)
    validate_schema(_artifact_xml(encoded))
    service = SamlService(bundle.config)
    artifact = artifact_from_message(encoded)
    actual_verify_signature(artifact, service.material.certificates)
    actual_verify_signature(
        artifact.find("./samlp:Response/saml:Assertion", NS),
        service.material.certificates,
    )
    with pytest.raises(ValueError, match="^Invalid SAML response$"):
        service.decrypt(encoded)


@pytest.mark.parametrize("field", ["key_name", "carried_key_name"])
@pytest.mark.parametrize("separator", ["\n", "\r"])
def test_signed_key_names_preserve_matching_carriage_returns(
    tmp_path: Path, field: str, separator: str
) -> None:
    bundle = make_bundle(tmp_path)
    name = "test" + separator + "key"
    if field == "key_name":
        bundle.config.decryption_key_name = name

    def matching_names(root: etree._Element) -> None:
        encrypted = root.find(".//saml:EncryptedID", NS)
        key = encrypted.find("./xenc:EncryptedKey", NS)
        if field == "key_name":
            key.find("./ds:KeyInfo/ds:KeyName", NS).text = name
        else:
            data = encrypted.find("./xenc:EncryptedData", NS)
            info = etree.Element(etree.QName(NS["ds"], "KeyInfo"))
            etree.SubElement(info, etree.QName(NS["ds"], "KeyName")).text = name
            data.insert(1, info)
            etree.SubElement(key, etree.QName(NS["xenc"], "CarriedKeyName")).text = name

    encoded = message(bundle, matching_names)
    validate_schema(_artifact_xml(encoded))
    service = SamlService(bundle.config)
    assert service.decrypt(encoded).personalId == "NL:bsn:" + BSN


def test_comment_split_cipher_value_uses_complete_signed_ciphertext(
    tmp_path: Path,
) -> None:
    bundle = make_bundle(tmp_path)
    artifact = signed_artifact(bundle)
    value = artifact.find(".//xenc:EncryptedData/xenc:CipherData/xenc:CipherValue", NS)
    complete = value.text
    value.text = complete[:40]
    comment = etree.Comment("inserted after signing")
    comment.tail = complete[40:]
    value.append(comment)

    service = SamlService(bundle.config)
    actual_verify_signature(artifact, service.material.certificates)
    actual_verify_signature(
        artifact.find("./samlp:Response/saml:Assertion", NS),
        service.material.certificates,
    )
    assert service.decrypt(soap_message(artifact)).personalId == ("NL:bsn:" + BSN)


@pytest.mark.parametrize("field", ["ciphertext", "oaep_label"])
@pytest.mark.parametrize("wrong_suffix", [False, True], ids=["correct", "wrong-suffix"])
@pytest.mark.parametrize("insert_comment", [False, True], ids=["plain", "comment"])
def test_signed_crypto_values_consume_complete_text(
    tmp_path: Path, field: str, wrong_suffix: bool, insert_comment: bool
) -> None:
    bundle = make_bundle(tmp_path)
    service = SamlService(bundle.config)
    content_key = b"\x42" * 32
    label = b"test-oaep-01"  # Three-byte aligned, so its base64 has no padding.
    plaintext = NAMEID
    # Include the IV and XML Encryption padding when aligning the ciphertext.
    while (16 * (len(plaintext) // 16 + 2)) % 3:
        plaintext += b" "
    encrypted = encrypted_identifier(
        bundle.decrypt_key,
        plaintext=plaintext,
        transport=OAEP11,
        digest="sha256",
        mgf="sha512",
        label=label,
        content_key=content_key,
    )
    key = encrypted.find("./xenc:EncryptedKey", NS)
    key.set("Recipient", bundle.config.entity_id)
    key.find(
        "./ds:KeyInfo/ds:KeyName", NS
    ).text = bundle.decrypt_certificate.fingerprint(hashes.SHA256()).hex()
    paths = {
        "ciphertext": ".//xenc:EncryptedData/xenc:CipherData/xenc:CipherValue",
        "oaep_label": ".//xenc:EncryptedKey/xenc:EncryptionMethod/xenc:OAEPparams",
    }
    target = encrypted.find(paths[field], NS)
    correct = target.text
    assert correct and not correct.endswith("=")

    if wrong_suffix:
        # Show that truncating at the future comment would actually succeed.
        assert (
            actual_decrypt_identifier(
                copy.deepcopy(encrypted),
                service.material.private_key,
                service.config.entity_id or "",
                service.material.key_name,
            ).text
            == BSN
        )
        original = base64.b64decode(correct)
        if field == "ciphertext":
            # CBC-decrypting this extra block produces 16 zero bytes, including
            # an invalid XML Encryption padding length of zero, deterministically.
            encryptor = Cipher(algorithms.AES(content_key), modes.ECB()).encryptor()
            suffix = encryptor.update(original[-16:]) + encryptor.finalize()
        else:
            suffix = b"-wrong"
        target.text = base64.b64encode(original + suffix).decode()
        assert target.text.startswith(correct)

    def replace_encryption(root: etree._Element) -> None:
        value = root.find(
            "./samlp:Response/saml:Assertion/saml:AttributeStatement/"
            "saml:Attribute[@Name='urn:nl-eid-gdi:1.0:ActingSubjectID']/"
            "saml:AttributeValue",
            NS,
        )
        value.replace(value.find("./saml:EncryptedID", NS), copy.deepcopy(encrypted))

    artifact = signed_artifact(bundle, replace_encryption)
    value = artifact.find(paths[field], NS)
    complete = value.text
    if insert_comment:
        split = len(correct) if wrong_suffix else len(correct) // 2
        value.text = complete[:split]
        comment = etree.Comment("inserted after signing")
        comment.tail = complete[split:]
        value.append(comment)
        assert "".join(value.itertext()) == complete

    validate_schema(etree.tostring(artifact, encoding="unicode"))
    actual_verify_signature(artifact, service.material.certificates)
    actual_verify_signature(
        artifact.find("./samlp:Response/saml:Assertion", NS),
        service.material.certificates,
    )
    encoded = soap_message(artifact)
    if wrong_suffix:
        with pytest.raises(ValueError, match="^Invalid SAML response$"):
            service.decrypt(encoded)
    else:
        assert service.decrypt(encoded).personalId == "NL:bsn:" + BSN


@pytest.mark.parametrize("location", ["identifier", "key_info", "method"])
def test_post_signature_comments_follow_encryption_structure_policy(
    tmp_path: Path, location: str
) -> None:
    bundle = make_bundle(tmp_path)
    artifact = signed_artifact(bundle)
    paths = {
        "identifier": ".//saml:EncryptedID",
        "key_info": ".//xenc:EncryptedKey/ds:KeyInfo",
        "method": ".//xenc:EncryptedKey/xenc:EncryptionMethod",
    }
    artifact.find(paths[location], NS).insert(
        0, etree.Comment("inserted after signing")
    )
    service = SamlService(bundle.config)
    actual_verify_signature(artifact, service.material.certificates)
    actual_verify_signature(
        artifact.find("./samlp:Response/saml:Assertion", NS),
        service.material.certificates,
    )
    encoded = soap_message(artifact)
    if location == "identifier":
        assert service.decrypt(encoded).personalId == "NL:bsn:" + BSN
    else:
        with pytest.raises(ValueError, match="^Invalid SAML response$"):
            service.decrypt(encoded)


@pytest.mark.parametrize("has_named_key", [False, True])
@pytest.mark.parametrize("missing_name", ["absent", "empty", "whitespace"])
def test_signing_fingerprint_is_not_a_missing_metadata_key_name(
    tmp_path: Path, has_named_key: bool, missing_name: str
) -> None:
    bundle = make_bundle(tmp_path)
    metadata_file = bundle.config.idp_metadata_file
    assert metadata_file is not None
    metadata = etree.parse(metadata_file).getroot()
    descriptor = metadata.find("./md:IDPSSODescriptor", NS)
    key = descriptor.find("./md:KeyDescriptor", NS)
    if has_named_key:
        key = copy.deepcopy(key)
        descriptor.append(key)
    name = key.find("./ds:KeyInfo/ds:KeyName", NS)
    if missing_name == "absent":
        name.getparent().remove(name)
    else:
        name.text = "" if missing_name == "empty" else " \t "
    metadata_file.write_bytes(etree.tostring(metadata))

    fingerprint = bundle.signing_certificate.fingerprint(hashes.SHA256()).hex()
    encoded = signed_message_with_key_name(bundle, fingerprint)
    if not has_named_key:
        with pytest.raises(
            ValueError, match="^Invalid SAML key or metadata configuration$"
        ):
            SamlService(bundle.config).decrypt(encoded)
        return

    service = SamlService(bundle.config)
    assert service.decrypt(message(bundle)).personalId == "NL:bsn:" + BSN
    with pytest.raises(ValueError, match="^Invalid SAML response$"):
        service.decrypt(encoded)


def test_signing_fingerprint_is_accepted_when_named_in_metadata(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    metadata_file = bundle.config.idp_metadata_file
    assert metadata_file is not None
    metadata = etree.parse(metadata_file).getroot()
    fingerprint = bundle.signing_certificate.fingerprint(hashes.SHA256()).hex()
    metadata.find(".//md:KeyDescriptor/ds:KeyInfo/ds:KeyName", NS).text = fingerprint
    metadata_file.write_bytes(etree.tostring(metadata))

    encoded = signed_message_with_key_name(bundle, fingerprint)
    assert SamlService(bundle.config).decrypt(encoded).personalId == "NL:bsn:" + BSN


@pytest.mark.parametrize("metadata_name", ["comment_split", "surrounding_whitespace"])
def test_signature_key_name_matches_complete_metadata_text(
    tmp_path: Path, metadata_name: str
) -> None:
    bundle = make_bundle(tmp_path)
    metadata_file = bundle.config.idp_metadata_file
    assert metadata_file is not None
    metadata = etree.parse(metadata_file).getroot()
    name = metadata.find(".//md:KeyDescriptor/ds:KeyInfo/ds:KeyName", NS)
    if metadata_name == "comment_split":
        comment = etree.Comment("split")
        name.append(comment)
        comment.tail = "-suffix"
        full_name = "test-signer-suffix"
    else:
        name.text = " test-signer "
        full_name = " test-signer "
    metadata_file.write_bytes(etree.tostring(metadata))

    service = SamlService(bundle.config)
    with pytest.raises(ValueError, match="^Invalid SAML response$"):
        service.decrypt(message(bundle))
    encoded = signed_message_with_key_name(bundle, full_name)
    assert service.decrypt(encoded).personalId == "NL:bsn:" + BSN


def test_rejects_metadata_key_name_with_nested_element(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    metadata_file = bundle.config.idp_metadata_file
    assert metadata_file is not None
    metadata = etree.parse(metadata_file).getroot()
    name = metadata.find(".//md:KeyDescriptor/ds:KeyInfo/ds:KeyName", NS)
    name.text = "test-"
    etree.SubElement(name, "unexpected").text = "signer"
    metadata_file.write_bytes(etree.tostring(metadata))
    encoded = signed_message_with_key_name(bundle, "test-signer")

    with pytest.raises(
        ValueError, match="^Invalid SAML key or metadata configuration$"
    ):
        SamlService(bundle.config).decrypt(encoded)


@pytest.mark.parametrize("place", ["artifact", "response", "assertion"])
def test_signed_duplicate_issuer_is_rejected(tmp_path: Path, place: str) -> None:
    bundle = make_bundle(tmp_path)

    def duplicate(root: etree._Element) -> None:
        response = root.find("./samlp:Response", NS)
        assertion = response.find("./saml:Assertion", NS)
        node = {"artifact": root, "response": response, "assertion": assertion}[place]
        node.append(copy.deepcopy(node.find("./saml:Issuer", NS)))

    with pytest.raises(ValueError, match="^Invalid SAML response$"):
        SamlService(bundle.config).decrypt(message(bundle, duplicate))


def test_optional_response_signature_precedes_decryption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = make_bundle(tmp_path)
    root = signed_artifact(bundle)
    root.remove(root.find("./ds:Signature", NS))
    sign(root.find("./samlp:Response", NS), bundle)
    sign(root, bundle)
    events: list[str] = []

    def verify(node: etree._Element, certificates: dict[str, bytes]) -> Any:
        result = actual_verify_signature(node, certificates)
        events.append(etree.QName(node).localname)
        return result

    def decrypt(*args: Any, **kwargs: Any) -> Any:
        events.append("decrypt")
        return actual_decrypt_identifier(*args, **kwargs)

    monkeypatch.setattr(service_module, "verify_signature", verify)
    monkeypatch.setattr(service_module, "decrypt_identifier", decrypt)
    result = SamlService(bundle.config).decrypt(soap_message(root))
    assert result.personalId == "NL:bsn:" + BSN
    assert events == ["ArtifactResponse", "Assertion", "Response", "decrypt"]


def test_unverified_assertion_never_reaches_decryption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = make_bundle(tmp_path)
    root = signed_artifact(bundle)
    root.find("./samlp:Response/saml:Assertion/saml:Issuer", NS).text = "tampered"
    root.remove(root.find("./ds:Signature", NS))
    sign(root, bundle)
    events: list[str] = []

    def decrypt(*args: Any, **kwargs: Any) -> Any:
        events.append("decrypt")
        return actual_decrypt_identifier(*args, **kwargs)

    monkeypatch.setattr(service_module, "decrypt_identifier", decrypt)
    with pytest.raises(ValueError, match="^Invalid SAML response$"):
        SamlService(bundle.config).decrypt(soap_message(root))
    assert events == []


def test_wrong_signed_destination_is_rejected(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)

    def mutate(root: etree._Element) -> None:
        root.find("./samlp:Response", NS).set(
            "Destination", "https://wrong.example/acs"
        )

    with pytest.raises(ValueError, match="^Invalid SAML response$"):
        SamlService(bundle.config).decrypt(message(bundle, mutate))


@pytest.mark.parametrize("place", ["ArtifactResponse", "Response"])
def test_pysaml_rejects_wrong_signed_response_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, place: str
) -> None:
    bundle = make_bundle(tmp_path)
    checked: list[str] = []
    verify = StatusResponse.verify

    def check_response(self: Any, *args: Any, **kwargs: Any) -> Any:
        checked.append(self.response.c_tag)
        return verify(self, *args, **kwargs)

    def wrong_version(root: etree._Element) -> None:
        response = (
            root if place == "ArtifactResponse" else root.find("./samlp:Response", NS)
        )
        response.set("Version", "1.0")

    monkeypatch.setattr(StatusResponse, "verify", check_response)
    with pytest.raises(ValueError, match="^Invalid SAML response$"):
        SamlService(bundle.config).decrypt(message(bundle, wrong_version))
    assert place in checked


@pytest.mark.parametrize("count", [0, 2])
def test_rejects_wrong_number_of_signed_authn_statements(
    tmp_path: Path, count: int
) -> None:
    bundle = make_bundle(tmp_path)

    def change_count(root: etree._Element) -> None:
        assertion = root.find("./samlp:Response/saml:Assertion", NS)
        statement = assertion.find("./saml:AuthnStatement", NS)
        if count == 0:
            assertion.remove(statement)
        else:
            assertion.insert(assertion.index(statement), copy.deepcopy(statement))

    with pytest.raises(ValueError, match="^Invalid SAML response$"):
        SamlService(bundle.config).decrypt(message(bundle, change_count))


def test_pysaml_rejects_signed_custom_condition_even_when_schema_valid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = make_bundle(tmp_path)
    checked: list[bool] = []
    condition_ok = AuthnResponse.condition_ok

    def check_condition(self: Any, *args: Any, **kwargs: Any) -> Any:
        checked.append(True)
        return condition_ok(self, *args, **kwargs)

    def add_condition(root: etree._Element) -> None:
        conditions = root.find("./samlp:Response/saml:Assertion/saml:Conditions", NS)
        condition = etree.SubElement(conditions, etree.QName(NS["saml"], "Condition"))
        condition.set(
            "{http://www.w3.org/2001/XMLSchema-instance}type", "saml:OneTimeUseType"
        )

    encoded = message(bundle, add_condition)
    validate_schema(_artifact_xml(encoded))
    monkeypatch.setattr(AuthnResponse, "condition_ok", check_condition)
    with pytest.raises(ValueError, match="^Invalid SAML response$"):
        SamlService(bundle.config).decrypt(encoded)
    assert checked == [True]


def _set_signed_current_times(root: etree._Element, fixed: datetime) -> None:
    response = root.find("./samlp:Response", NS)
    assertion = response.find("./saml:Assertion", NS)
    issued = (fixed - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for element in (root, response, assertion):
        element.set("IssueInstant", issued)
    assertion.find("./saml:AuthnStatement", NS).set("AuthnInstant", issued)


def _freeze_saml_time(monkeypatch: pytest.MonkeyPatch, fixed: datetime) -> None:
    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> Self:
            return cls.fromtimestamp(fixed.timestamp(), tz=tz)

    monkeypatch.setattr(service_module, "datetime", FixedDateTime)
    monkeypatch.setattr(time_util, "utc_now", lambda: int(fixed.timestamp()))


@pytest.mark.parametrize("boundary", ["conditions", "bearer"])
@pytest.mark.parametrize(
    ("scenario", "skew", "offset_ms", "allowed"),
    [
        pytest.param("exact-skew", 120, -120_000, True, id="exact-skew"),
        pytest.param("fractional", 0, -100, True, id="fractional"),
        pytest.param("expired-no-skew", 0, -1_000, False, id="expired-no-skew"),
        pytest.param("beyond-skew", 120, -121_000, False, id="beyond-skew"),
    ],
)
def test_signed_expiry_follows_pysaml(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    scenario: str,
    skew: int,
    offset_ms: int,
    allowed: bool,
) -> None:
    bundle = make_bundle(tmp_path)
    bundle.config.clock_skew_seconds = skew
    fixed = datetime.now(UTC).replace(
        microsecond=500_000 if scenario == "fractional" else 0
    )

    def set_expiry(root: etree._Element) -> None:
        _set_signed_current_times(root, fixed)
        assertion = root.find("./samlp:Response/saml:Assertion", NS)
        conditions = assertion.find("./saml:Conditions", NS)
        target = (
            conditions
            if boundary == "conditions"
            else assertion.find(
                "./saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData",
                NS,
            )
        )
        expiry = fixed + timedelta(milliseconds=offset_ms)
        target.set("NotOnOrAfter", expiry.isoformat().replace("+00:00", "Z"))
        if boundary == "conditions" and scenario != "fractional":
            conditions.set(
                "NotBefore",
                (fixed - timedelta(seconds=180)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            )

    valid = (
        message(bundle, lambda root: _set_signed_current_times(root, fixed))
        if not allowed
        else None
    )
    encoded = message(bundle, set_expiry)
    if scenario == "fractional":
        validate_schema(_artifact_xml(encoded))
    _freeze_saml_time(monkeypatch, fixed)
    service = SamlService(bundle.config)
    if allowed:
        assert service.decrypt(encoded).personalId == "NL:bsn:" + BSN
    else:
        assert valid is not None
        assert service.decrypt(valid).personalId == "NL:bsn:" + BSN
        with pytest.raises(ValueError, match="^Invalid SAML response$"):
            service.decrypt(encoded)


def test_signed_empty_interval_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = make_bundle(tmp_path)
    bundle.config.clock_skew_seconds = 120
    fixed = datetime.now(UTC).replace(microsecond=0)

    def set_empty_interval(root: etree._Element) -> None:
        _set_signed_current_times(root, fixed)
        conditions = root.find("./samlp:Response/saml:Assertion/saml:Conditions", NS)
        value = (fixed + timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        conditions.set("NotBefore", value)
        conditions.set("NotOnOrAfter", value)

    valid = message(bundle, lambda root: _set_signed_current_times(root, fixed))
    empty = message(bundle, set_empty_interval)
    _freeze_saml_time(monkeypatch, fixed)
    service = SamlService(bundle.config)
    assert service.decrypt(valid).personalId == "NL:bsn:" + BSN
    with pytest.raises(ValueError, match="^Invalid SAML response$"):
        service.decrypt(empty)


@pytest.mark.parametrize(
    "skew,offset_ms,extra_digits,allowed",
    [
        (0, -1, "", True),
        (0, 0, "", True),
        (0, 0, "0000", True),
        (0, 0, "1", True),
        (0, 0, "000001", True),
        (0, 800, "", True),
        (0, 1800, "", False),
        (1, 800, "", True),
        (1, 1000, "", True),
        (1, 1000, "0", True),
        (1, 1000, "1", True),
        (1, 1800, "", True),
    ],
)
def test_signed_fractional_not_before_respects_clock_skew(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    skew: int,
    offset_ms: int,
    extra_digits: str,
    allowed: bool,
) -> None:
    bundle = make_bundle(tmp_path)
    bundle.config.clock_skew_seconds = skew
    fixed = datetime.now(UTC).replace(microsecond=100_000)

    def fractional_not_before(root: etree._Element) -> None:
        _set_signed_current_times(root, fixed)
        response = root.find("./samlp:Response", NS)
        assertion = response.find("./saml:Assertion", NS)
        lower_bound = fixed + timedelta(milliseconds=offset_ms)
        assertion.find("./saml:Conditions", NS).set(
            "NotBefore",
            lower_bound.isoformat(timespec="microseconds").replace(
                "+00:00", f"{extra_digits}Z"
            ),
        )

    encoded = message(bundle, fractional_not_before)
    validate_schema(_artifact_xml(encoded))
    _freeze_saml_time(monkeypatch, fixed)
    service = SamlService(bundle.config)
    if allowed:
        assert service.decrypt(encoded).personalId == "NL:bsn:" + BSN
    else:
        with pytest.raises(ValueError, match="^Invalid SAML response$"):
            service.decrypt(encoded)


def test_signed_bearer_expiry_requires_timezone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = make_bundle(tmp_path)
    fixed = datetime.now(UTC).replace(microsecond=0)

    def set_expiry(root: etree._Element, *, aware: bool) -> None:
        _set_signed_current_times(root, fixed)
        bearer = root.find(
            "./samlp:Response/saml:Assertion/saml:Subject/"
            "saml:SubjectConfirmation/saml:SubjectConfirmationData",
            NS,
        )
        expiry = (fixed + timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%S")
        bearer.set("NotOnOrAfter", expiry + ("Z" if aware else ""))

    valid = message(bundle, lambda root: set_expiry(root, aware=True))
    naive = message(bundle, lambda root: set_expiry(root, aware=False))
    for encoded in (valid, naive):
        validate_schema(_artifact_xml(encoded))
    _freeze_saml_time(monkeypatch, fixed)
    service = SamlService(bundle.config)
    assert service.decrypt(valid).personalId == "NL:bsn:" + BSN
    with pytest.raises(ValueError, match="^Invalid SAML response$"):
        service.decrypt(naive)


@pytest.mark.parametrize(
    "missing",
    [
        "conditions",
        "not_before",
        "conditions_expiry",
        "bearer_expiry",
        "audience_restriction",
        "audience",
        "multiple_audience_restrictions",
    ],
)
def test_signed_missing_time_or_audience_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    bundle = make_bundle(tmp_path)
    fixed = datetime.now(UTC).replace(microsecond=0)

    def remove_claim(root: etree._Element) -> None:
        _set_signed_current_times(root, fixed)
        assertion = root.find("./samlp:Response/saml:Assertion", NS)
        conditions = assertion.find("./saml:Conditions", NS)
        if missing == "conditions":
            assertion.remove(conditions)
        elif missing == "not_before":
            del conditions.attrib["NotBefore"]
        elif missing == "conditions_expiry":
            del conditions.attrib["NotOnOrAfter"]
        elif missing == "bearer_expiry":
            bearer = assertion.find(
                "./saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData",
                NS,
            )
            del bearer.attrib["NotOnOrAfter"]
        else:
            restriction = conditions.find("./saml:AudienceRestriction", NS)
            if missing == "audience_restriction":
                conditions.remove(restriction)
            elif missing == "audience":
                restriction.remove(restriction.find("./saml:Audience", NS))
            else:
                conditions.append(copy.deepcopy(restriction))

    valid = message(bundle, lambda root: _set_signed_current_times(root, fixed))
    invalid = message(bundle, remove_claim)
    _freeze_saml_time(monkeypatch, fixed)
    service = SamlService(bundle.config)
    assert service.decrypt(valid).personalId == "NL:bsn:" + BSN
    with pytest.raises(ValueError, match="^Invalid SAML response$"):
        service.decrypt(invalid)


@pytest.mark.parametrize("claim", ["artifact", "response", "assertion", "authn"])
@pytest.mark.parametrize("seconds", [300, 36 * 60 * 60])
def test_signed_future_claims_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, claim: str, seconds: int
) -> None:
    bundle = make_bundle(tmp_path)
    bundle.config.clock_skew_seconds = 120
    fixed = datetime.now(UTC).replace(microsecond=0)

    def set_future(root: etree._Element) -> None:
        _set_signed_current_times(root, fixed)
        response = root.find("./samlp:Response", NS)
        assertion = response.find("./saml:Assertion", NS)
        target = {
            "artifact": root,
            "response": response,
            "assertion": assertion,
            "authn": assertion.find("./saml:AuthnStatement", NS),
        }[claim]
        target.set(
            "AuthnInstant" if claim == "authn" else "IssueInstant",
            (fixed + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

    valid = message(bundle, lambda root: _set_signed_current_times(root, fixed))
    future = message(bundle, set_future)
    _freeze_saml_time(monkeypatch, fixed)
    service = SamlService(bundle.config)
    assert service.decrypt(valid).personalId == "NL:bsn:" + BSN
    with pytest.raises(ValueError, match="^Invalid SAML response$"):
        service.decrypt(future)


def test_unexpected_signature_never_reaches_decryption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = make_bundle(tmp_path)

    def mutate(root: etree._Element) -> None:
        subject = root.find("./samlp:Response/saml:Assertion/saml:Subject", NS)
        etree.SubElement(subject, etree.QName(NS["ds"], "Signature"))

    events: list[str] = []

    def decrypt(*args: Any, **kwargs: Any) -> Any:
        events.append("decrypt")
        return actual_decrypt_identifier(*args, **kwargs)

    monkeypatch.setattr(service_module, "decrypt_identifier", decrypt)
    with pytest.raises(ValueError, match="^Invalid SAML response$"):
        SamlService(bundle.config).decrypt(message(bundle, mutate))
    assert events == []


@pytest.mark.parametrize("place", ["artifact", "response", "assertion"])
@pytest.mark.parametrize("failure", ["missing", "wrong_type", "exception"])
def test_model_conversion_rejects_and_sanitizes_library_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    place: str,
    failure: str,
) -> None:
    bundle = make_bundle(tmp_path)
    root = signed_artifact(bundle)
    root.remove(root.find("./ds:Signature", NS))
    sign(root.find("./samlp:Response", NS), bundle)
    sign(root, bundle)
    real_parser = create_class_from_xml_string
    expected = {
        "artifact": samlp.ArtifactResponse,
        "response": samlp.Response,
        "assertion": saml.Assertion,
    }[place]
    calls: list[type[object]] = []

    def fail(target: Any, document: str) -> Any:
        if target is not expected:
            return real_parser(target, document)
        calls.append(target)
        if failure == "exception":
            raise RuntimeError("sensitive library detail")
        return object() if failure == "wrong_type" else None

    monkeypatch.setattr(signatures_module, "create_class_from_xml_string", fail)
    with pytest.raises(ValueError, match="^Invalid SAML response$") as error:
        SamlService(bundle.config).decrypt(soap_message(root))
    assert calls == [expected]
    assert error.value.__cause__ is None
    assert error.value.__suppress_context__
    assert "sensitive library detail" not in str(error.value)
    assert "sensitive library detail" not in caplog.text
    captured = capsys.readouterr()
    assert "sensitive library detail" not in captured.out + captured.err


@pytest.mark.parametrize("entry", ["adapter", "service"])
@pytest.mark.parametrize("ambient_exception", [False, True])
def test_parser_exception_details_are_not_reachable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    entry: str,
    ambient_exception: bool,
) -> None:
    bundle = make_bundle(tmp_path)
    encoded = message(bundle)
    artifact = artifact_from_message(encoded)
    service = SamlService(bundle.config)
    sentinel = "synthetic-parser-exception-marker"
    parser_called = False

    def fail(_: Any, __: str) -> None:
        nonlocal parser_called
        parser_called = True
        try:
            raise RuntimeError(sentinel)
        except RuntimeError as cause:
            raise ValueError("parser failed") from cause

    monkeypatch.setattr(signatures_module, "create_class_from_xml_string", fail)

    def capture_error() -> ValueError:
        with pytest.raises(ValueError) as error:
            if entry == "adapter":
                actual_verify_signature(artifact, service.material.certificates)
            else:
                service.decrypt(encoded)
        return error.value

    if ambient_exception:
        try:
            raise RuntimeError(sentinel)
        except RuntimeError:
            error = capture_error()
    else:
        error = capture_error()

    assert parser_called
    leaked = exception_graph_contains(error, sentinel)
    captured = capsys.readouterr()
    leaked |= sentinel in captured.out + captured.err + caplog.text
    assert not leaked, "Sensitive detail remained in the exception graph or output"
    assert error.__context__ is None
    assert error.__cause__ is None


def test_unavailable_service_error_does_not_retain_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    bundle = make_bundle(tmp_path)
    service = SamlService(bundle.config)
    encoded = message(bundle)
    sentinel = "synthetic-trust-exception-marker"

    def expired(_: object, now: object) -> dict[str, bytes]:
        del now
        try:
            raise RuntimeError(sentinel)
        except RuntimeError as cause:
            raise ValueError("trust unavailable") from cause

    monkeypatch.setattr(type(service.material), "active_certificates", expired)
    with pytest.raises(SamlUnavailable, match="^SAML configuration expired$") as error:
        service.decrypt(encoded)

    captured = capsys.readouterr()
    leaked = exception_graph_contains(error.value, sentinel)
    leaked |= sentinel in captured.out + captured.err + caplog.text
    assert not leaked, "Sensitive detail remained in the exception graph or output"
    assert error.value.__context__ is None
    assert error.value.__cause__ is None


def test_invalid_optional_response_signature_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = make_bundle(tmp_path)
    root = signed_artifact(bundle)
    root.remove(root.find("./ds:Signature", NS))
    response = root.find("./samlp:Response", NS)
    sign(response, bundle)
    value = response.find("./ds:Signature/ds:SignatureValue", NS)
    signature = bytearray(base64.b64decode(value.text))
    signature[0] ^= 1
    value.text = base64.b64encode(signature).decode()
    sign(root, bundle)
    events: list[str] = []

    def decrypt(*args: Any, **kwargs: Any) -> Any:
        events.append("decrypt")
        return actual_decrypt_identifier(*args, **kwargs)

    monkeypatch.setattr(service_module, "decrypt_identifier", decrypt)
    with pytest.raises(ValueError, match="^Invalid SAML response$"):
        SamlService(bundle.config).decrypt(soap_message(root))
    assert events == []


def test_signature_verification_uses_original_soap_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = make_bundle(tmp_path)
    artifact = signed_artifact(bundle)
    artifact.remove(artifact.find("./ds:Signature", NS))
    sign(artifact.find("./samlp:Response", NS), bundle)
    sign(artifact, bundle)
    encoded = soap_message(artifact)
    parsed_roots: list[etree._Element] = []
    seen: list[str] = []
    original_parse_xml = actual_parse_xml
    original_verify = actual_verify_signature

    def parse_xml(data: bytes) -> etree._Element:
        root = original_parse_xml(data)
        parsed_roots.append(root)
        return root

    def verify(node: etree._Element, certificates: dict[str, bytes]) -> Any:
        assert len(parsed_roots) == 1
        assert node.getroottree().getroot() is parsed_roots[0]
        assert parsed_roots[0].tag == f"{{{SOAP11}}}Envelope"
        result = original_verify(node, certificates)
        seen.append(etree.QName(node).localname)
        return result

    monkeypatch.setattr(service_module, "parse_xml", parse_xml)
    monkeypatch.setattr(service_module, "verify_signature", verify)
    assert SamlService(bundle.config).decrypt(encoded).personalId == "NL:bsn:" + BSN
    assert seen == ["ArtifactResponse", "Assertion", "Response"]


def test_schema_rejects_non_whitespace_saml_node_tails(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)

    def add_tails(root: etree._Element) -> None:
        response = root.find("./samlp:Response", NS)
        response.tail = "response tail"
        response.find("./saml:Assertion", NS).tail = "assertion tail"

    artifact = signed_artifact(bundle, add_tails)
    artifact.tail = "artifact tail"
    encoded = soap_message(artifact)
    with pytest.raises(ValueError, match="^Invalid SAML response$"):
        SamlService(bundle.config).decrypt(encoded)


def test_claims_with_surrounding_whitespace_remain_valid(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)

    def add_whitespace(root: etree._Element) -> None:
        response = root.find("./samlp:Response", NS)
        assertion = response.find("./saml:Assertion", NS)
        for node in (root, response, assertion):
            issuer = node.find("./saml:Issuer", NS)
            issuer.text = f" \n\r{issuer.text}\t "
        loa = assertion.find(
            "./saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef", NS
        )
        loa.text = f" \n\r{loa.text}\t "

    result = SamlService(bundle.config).decrypt(message(bundle, add_whitespace))
    assert result.personalId == "NL:bsn:" + BSN
    assert result.authnContextClassRef == LOA


@pytest.mark.parametrize("placement", ["other_attribute", "service_value"])
def test_signed_additional_integer_value_preserves_result(
    tmp_path: Path, placement: str
) -> None:
    bundle = make_bundle(tmp_path)

    def add_value(root: etree._Element) -> None:
        attributes = root.find(
            "./samlp:Response/saml:Assertion/saml:AttributeStatement", NS
        )
        if placement == "other_attribute":
            attribute = etree.SubElement(
                attributes, etree.QName(NS["saml"], "Attribute"), Name="urn:test:extra"
            )
        else:
            attribute = attributes.find(
                "./saml:Attribute[@Name='urn:nl-eid-gdi:1.0:ServiceUUID']", NS
            )
        typed_value = etree.SubElement(
            attribute,
            etree.QName(NS["saml"], "AttributeValue"),
            nsmap={
                "xsi": "http://www.w3.org/2001/XMLSchema-instance",
                "xs": "http://www.w3.org/2001/XMLSchema",
            },
        )
        typed_value.set("{http://www.w3.org/2001/XMLSchema-instance}type", "xs:integer")
        typed_value.text = "+003"

    encoded = message(bundle, add_value)
    validate_schema(_artifact_xml(encoded))

    result = SamlService(bundle.config).decrypt(encoded)
    assert result.personalId == "NL:bsn:" + BSN
    assert result.authnContextClassRef == LOA


@pytest.mark.parametrize("empty_context_first", [True, False])
def test_schema_rejects_multiple_authn_contexts(
    tmp_path: Path, empty_context_first: bool
) -> None:
    bundle = make_bundle(tmp_path)

    def add_empty_context(root: etree._Element) -> None:
        statement = root.find("./samlp:Response/saml:Assertion/saml:AuthnStatement", NS)
        context = etree.Element(etree.QName(NS["saml"], "AuthnContext"))
        if empty_context_first:
            statement.insert(0, context)
        else:
            statement.append(context)

    with pytest.raises(ValueError, match="^Invalid SAML response$"):
        SamlService(bundle.config).decrypt(message(bundle, add_empty_context))


@pytest.mark.parametrize("layout", ["same_context", "separate_contexts"])
def test_rejects_signed_duplicate_authentication_context_references(
    tmp_path: Path, layout: str
) -> None:
    bundle = make_bundle(tmp_path)

    def duplicate_reference(root: etree._Element) -> None:
        statement = root.find("./samlp:Response/saml:Assertion/saml:AuthnStatement", NS)
        context = statement.find("./saml:AuthnContext", NS)
        duplicate = copy.deepcopy(context.find("./saml:AuthnContextClassRef", NS))
        if layout == "same_context":
            context.append(duplicate)
        else:
            other = etree.SubElement(statement, etree.QName(NS["saml"], "AuthnContext"))
            other.append(duplicate)

    with pytest.raises(ValueError, match="^Invalid SAML response$"):
        SamlService(bundle.config).decrypt(message(bundle, duplicate_reference))


def test_model_conversion_does_not_change_the_signed_tree(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    encoded = message(bundle)
    artifact = artifact_from_message(encoded)
    response = artifact.find("./samlp:Response", NS)
    assertion = response.find("./saml:Assertion", NS)
    original = etree.tostring(artifact)

    certificates = SamlService(bundle.config).material.certificates
    artifact_model = actual_verify_signature(artifact, certificates)
    assertion_model = actual_verify_signature(assertion, certificates)
    assert isinstance(artifact_model, samlp.ArtifactResponse)
    assert isinstance(
        artifact_model.extensions_as_elements("Response", samlp)[0], samlp.Response
    )
    assert isinstance(assertion_model, saml.Assertion)
    assert etree.tostring(artifact) == original
    assert SamlService(bundle.config).decrypt(encoded).personalId == ("NL:bsn:" + BSN)


def test_verified_message_returns_bsn_and_loa_without_request_ids(
    tmp_path: Path,
) -> None:
    bundle = make_bundle(tmp_path)
    result = SamlService(bundle.config).decrypt(message(bundle))
    assert result.personalId == "NL:bsn:" + BSN
    assert result.authnContextClassRef == LOA


def test_tvs_subject_without_format_and_multiple_services(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)

    def mutate(root: etree._Element) -> None:
        assertion = root.find("./samlp:Response/saml:Assertion", NS)
        name = assertion.find("./saml:Subject/saml:NameID", NS)
        del name.attrib["Format"]
        service = assertion.find(
            "./saml:AttributeStatement/saml:Attribute[@Name='urn:nl-eid-gdi:1.0:ServiceUUID']",
            NS,
        )
        value = etree.Element(etree.QName(NS["saml"], "AttributeValue"))
        value.text = "other-service"
        service.insert(0, value)

    assert (
        SamlService(bundle.config).decrypt(message(bundle, mutate)).personalId
        == "NL:bsn:" + BSN
    )


def test_representation_can_be_enabled(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    bundle.config.allow_representation = True

    def mutate(root: etree._Element) -> None:
        attributes = root.find(
            "./samlp:Response/saml:Assertion/saml:AttributeStatement", NS
        )
        acting = attributes.find(
            "./saml:Attribute[@Name='urn:nl-eid-gdi:1.0:ActingSubjectID']", NS
        )
        legal = copy.deepcopy(acting)
        legal.set("Name", "urn:nl-eid-gdi:1.0:LegalSubjectID")
        legal.find(".//xenc:EncryptedData", NS).set("Id", "_legal_data")
        attributes.append(legal)

    result = SamlService(bundle.config).decrypt(message(bundle, mutate))
    assert result.personalId == "NL:bsn:" + BSN
    assert result.representedPersonalId == "NL:bsn:" + BSN


def test_configured_decryption_key_name(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    bundle.config.decryption_key_name = "registered-key-name"

    def mutate(root: etree._Element) -> None:
        root.find(
            ".//xenc:EncryptedKey/ds:KeyInfo/ds:KeyName", NS
        ).text = "registered-key-name"

    assert (
        SamlService(bundle.config).decrypt(message(bundle, mutate)).personalId
        == "NL:bsn:" + BSN
    )


def test_sample_shaped_soap_and_encrypted_key_references(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)

    def mutate(root: etree._Element) -> None:
        assertion = root.find("./samlp:Response/saml:Assertion", NS)
        del assertion.find("./saml:Subject/saml:NameID", NS).attrib["Format"]
        advice = assertion.find("./saml:Advice", NS)
        nested = etree.SubElement(
            advice,
            etree.QName(NS["saml"], "Assertion"),
            ID="_advice",
            Version="2.0",
            IssueInstant=instant(),
        )
        etree.SubElement(
            nested, etree.QName(NS["saml"], "Issuer")
        ).text = assertion.find("./saml:Issuer", NS).text
        encrypted = assertion.find(".//saml:EncryptedID", NS)
        data = encrypted.find("./xenc:EncryptedData", NS)
        key = encrypted.find("./xenc:EncryptedKey", NS)
        method = key.find("./xenc:EncryptionMethod", NS)
        assert (
            method.get("Algorithm") == "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
        )
        assert method.find("./ds:DigestMethod", NS) is None
        key.set("Id", "_key")
        info = etree.Element(etree.QName(NS["ds"], "KeyInfo"))
        etree.SubElement(
            info,
            etree.QName(NS["ds"], "RetrievalMethod"),
            URI="#_key",
            Type=NS["xenc"] + "EncryptedKey",
        )
        data.insert(1, info)
        references = etree.SubElement(key, etree.QName(NS["xenc"], "ReferenceList"))
        etree.SubElement(
            references, etree.QName(NS["xenc"], "DataReference"), URI="#_encrypted"
        )

    encoded = soap_message(
        signed_artifact(bundle, mutate), SOAP11, xml_declaration=True
    )
    assert SamlService(bundle.config).decrypt(encoded).personalId == "NL:bsn:" + BSN


def test_signed_multiple_recipients_selects_only_configured_key(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)

    def add_other_recipient(root: etree._Element) -> None:
        encrypted = root.find(".//saml:EncryptedID", NS)
        other = copy.deepcopy(encrypted.find("./xenc:EncryptedKey", NS))
        other.set("Recipient", "urn:test:other-recipient")
        other.set("Id", "_other_key")
        other.find("./xenc:CipherData/xenc:CipherValue", NS).text = base64.b64encode(
            b"not a usable key"
        ).decode()
        encrypted.insert(1, other)

    encoded = message(bundle, add_other_recipient)
    validate_schema(_artifact_xml(encoded))
    assert SamlService(bundle.config).decrypt(encoded).personalId == "NL:bsn:" + BSN


def test_unselected_recipient_mixed_key_info_is_not_used(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)

    def add_other_recipient(root: etree._Element) -> None:
        encrypted = root.find(".//saml:EncryptedID", NS)
        other = copy.deepcopy(encrypted.find("./xenc:EncryptedKey", NS))
        other.set("Recipient", "urn:test:other-recipient")
        other.find("./ds:KeyInfo/ds:KeyName", NS).tail = "ignored signed text"
        encrypted.insert(1, other)

    encoded = message(bundle, add_other_recipient)
    validate_schema(_artifact_xml(encoded))
    assert SamlService(bundle.config).decrypt(encoded).personalId == "NL:bsn:" + BSN


@pytest.mark.parametrize("scenario", ["oaep11", "bad_padding", "wrong_key_length"])
def test_signed_model_encryption_and_content_failures(
    tmp_path: Path, scenario: str, capfd: pytest.CaptureFixture[str]
) -> None:
    bundle = make_bundle(tmp_path)

    def replace_encryption(root: etree._Element) -> None:
        value = root.find(
            "./samlp:Response/saml:Assertion/saml:AttributeStatement/"
            "saml:Attribute[@Name='urn:nl-eid-gdi:1.0:ActingSubjectID']/"
            "saml:AttributeValue",
            NS,
        )
        options: dict[str, Any] = {}
        if scenario == "oaep11":
            options.update(
                transport=OAEP11, digest="sha256", mgf="sha512", label=b"\0l"
            )
        elif scenario == "bad_padding":
            options["padding_byte"] = 0
        else:
            options["content_key"] = b"\x01" * 16
        encrypted = encrypted_identifier(bundle.decrypt_key, **options)
        key = encrypted.find("./xenc:EncryptedKey", NS)
        key.set("Recipient", bundle.config.entity_id)
        key.find(
            "./ds:KeyInfo/ds:KeyName", NS
        ).text = bundle.decrypt_certificate.fingerprint(hashes.SHA256()).hex()
        value.replace(value.find("./saml:EncryptedID", NS), encrypted)

    encoded = message(bundle, replace_encryption)
    validate_schema(_artifact_xml(encoded))
    service = SamlService(bundle.config)
    capfd.readouterr()
    if scenario == "oaep11":
        assert service.decrypt(encoded).personalId == "NL:bsn:" + BSN
    else:
        with pytest.raises(ValueError, match="^Invalid SAML response$") as caught:
            service.decrypt(encoded)
        assert caught.value.__cause__ is None and caught.value.__context__ is None
    captured = capfd.readouterr()
    assert captured.out == captured.err == ""


@pytest.mark.parametrize("subject", ["empty", "wrong_format"])
def test_rejects_invalid_summary_subject(tmp_path: Path, subject: str) -> None:
    bundle = make_bundle(tmp_path)

    def mutate(root: etree._Element) -> None:
        name = root.find("./samlp:Response/saml:Assertion/saml:Subject/saml:NameID", NS)
        if subject == "empty":
            name.text = ""
        else:
            name.set("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")

    with pytest.raises(ValueError):
        SamlService(bundle.config).decrypt(message(bundle, mutate))


@pytest.mark.parametrize("namespace", (SOAP11, SOAP12))
@pytest.mark.parametrize("xml_declaration", [False, True])
def test_accepts_soap_envelope(
    tmp_path: Path, namespace: str, xml_declaration: bool
) -> None:
    bundle = make_bundle(tmp_path)
    encoded = soap_message(
        signed_artifact(bundle), namespace, xml_declaration=xml_declaration
    )
    result = SamlService(bundle.config).decrypt(encoded)
    assert result.personalId == "NL:bsn:" + BSN
    assert result.authnContextClassRef == LOA


@pytest.mark.parametrize("address", [None, "192.0.2.10", "192.0.2.11"])
def test_signed_bearer_address_is_not_compared_with_user_agent(
    tmp_path: Path, address: str | None
) -> None:
    bundle = make_bundle(tmp_path)

    def set_address(root: etree._Element) -> None:
        data = root.find(
            "./samlp:Response/saml:Assertion/saml:Subject/"
            "saml:SubjectConfirmation/saml:SubjectConfirmationData",
            NS,
        )
        if address is not None:
            data.set("Address", address)

    encoded = message(bundle, set_address)
    artifact = artifact_from_message(encoded)
    validate_schema(etree.tostring(artifact, encoding="unicode"))
    service = SamlService(bundle.config)
    actual_verify_signature(artifact, service.material.certificates)
    actual_verify_signature(
        artifact.find("./samlp:Response/saml:Assertion", NS),
        service.material.certificates,
    )
    result = service.decrypt(encoded)
    assert result.personalId == "NL:bsn:" + BSN
    assert result.authnContextClassRef == LOA


def _bearer_data(root: etree._Element) -> etree._Element:
    data = root.find(
        "./samlp:Response/saml:Assertion/saml:Subject/"
        "saml:SubjectConfirmation/saml:SubjectConfirmationData",
        NS,
    )
    assert data is not None
    return data


def _verified_bearer_artifact(encoded: str, service: SamlService) -> etree._Element:
    artifact = artifact_from_message(encoded)
    validate_schema(etree.tostring(artifact, encoding="unicode"))
    actual_verify_signature(artifact, service.material.certificates)
    actual_verify_signature(
        artifact.find("./samlp:Response/saml:Assertion", NS),
        service.material.certificates,
    )
    return artifact


def test_signed_non_ip_bearer_address_preserves_original_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = make_bundle(tmp_path)
    service = SamlService(bundle.config)
    address = "not-" + str(0)
    valid_ip = ".".join(map(str, (192, 0, 2, 9)))

    def signed_with(value: str) -> str:
        return message(bundle, lambda root: _bearer_data(root).set("Address", value))

    control = signed_with(valid_ip)
    encoded = signed_with(address)
    for signed in (control, encoded):
        _verified_bearer_artifact(signed, service)
    if service.decrypt(control).personalId != "NL:bsn:" + BSN:
        _fail_sanitized("Bearer address control failed")

    roots: list[etree._Element] = []
    originals: list[bytes] = []
    events: list[str] = []

    def parse(data: bytes) -> etree._Element:
        root = actual_parse_xml(data)
        roots.append(root)
        originals.append(etree.tostring(root))
        return root

    def unchanged() -> None:
        if len(roots) != 1 or etree.tostring(roots[0]) != originals[0]:
            _fail_sanitized("Original signed tree changed")

    def verify(node: etree._Element, certificates: dict[str, bytes]) -> Any:
        unchanged()
        if node.getroottree().getroot() is not roots[0]:
            _fail_sanitized("Signature target is not in the original tree")
        result = actual_verify_signature(node, certificates)
        unchanged()
        events.append(etree.QName(node).localname)
        return result

    def decrypt(*args: Any, **kwargs: Any) -> Any:
        unchanged()
        events.append("decrypt")
        result = actual_decrypt_identifier(*args, **kwargs)
        unchanged()
        return result

    monkeypatch.setattr(service_module, "parse_xml", parse)
    monkeypatch.setattr(service_module, "verify_signature", verify)
    monkeypatch.setattr(service_module, "decrypt_identifier", decrypt)
    result = service.decrypt(encoded)
    unchanged()
    if result.personalId != "NL:bsn:" + BSN or result.authnContextClassRef != LOA:
        _fail_sanitized("Unexpected bearer address result")
    assert events == ["ArtifactResponse", "Assertion", "decrypt"]


@pytest.mark.parametrize("change", ["expiry", "recipient"])
def test_non_ip_bearer_address_does_not_bypass_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    bundle = make_bundle(tmp_path)
    service = SamlService(bundle.config)
    address = "not-" + str(0)

    def set_address(root: etree._Element) -> None:
        _bearer_data(root).set("Address", address)

    def invalidate(root: etree._Element) -> None:
        set_address(root)
        data = _bearer_data(root)
        if change == "expiry":
            data.set("NotOnOrAfter", instant(-300))
        else:
            assert bundle.config.acs_url
            data.set("Recipient", bundle.config.acs_url + "/other")

    control = message(bundle, set_address)
    invalid = message(bundle, invalidate)
    for signed in (control, invalid):
        _verified_bearer_artifact(signed, service)
    if service.decrypt(control).personalId != "NL:bsn:" + BSN:
        _fail_sanitized("Bearer address control failed")

    decryptions: list[bool] = []

    def decrypt(*args: Any, **kwargs: Any) -> Any:
        decryptions.append(True)
        return actual_decrypt_identifier(*args, **kwargs)

    monkeypatch.setattr(service_module, "decrypt_identifier", decrypt)
    with pytest.raises(ValueError):
        service.decrypt(invalid)
    assert not decryptions


@pytest.mark.parametrize("resign_artifact", [False, True])
def test_bearer_address_tampering_is_rejected_before_decryption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, resign_artifact: bool
) -> None:
    bundle = make_bundle(tmp_path)
    service = SamlService(bundle.config)
    address = "not-" + str(0)
    signed = message(bundle, lambda root: _bearer_data(root).set("Address", address))
    artifact = _verified_bearer_artifact(signed, service)
    if service.decrypt(signed).personalId != "NL:bsn:" + BSN:
        _fail_sanitized("Bearer address control failed")

    _bearer_data(artifact).set("Address", address + "-changed")
    if resign_artifact:
        artifact.remove(artifact.find("./ds:Signature", NS))
        sign(artifact, bundle)
        # Check the serialized test input on the fresh tree the service sees.
        artifact = etree.fromstring(etree.tostring(artifact))
        actual_verify_signature(artifact, service.material.certificates)
    validate_schema(etree.tostring(artifact, encoding="unicode"))
    tampered = soap_message(artifact)

    roots: list[etree._Element] = []
    originals: list[bytes] = []
    attempted: list[str] = []
    verified: list[str] = []
    decryptions: list[bool] = []

    def parse(data: bytes) -> etree._Element:
        root = actual_parse_xml(data)
        roots.append(root)
        originals.append(etree.tostring(root))
        return root

    def verify(node: etree._Element, certificates: dict[str, bytes]) -> Any:
        attempted.append(etree.QName(node).localname)
        result = actual_verify_signature(node, certificates)
        verified.append(etree.QName(node).localname)
        return result

    def decrypt(*args: Any, **kwargs: Any) -> Any:
        decryptions.append(True)
        return actual_decrypt_identifier(*args, **kwargs)

    monkeypatch.setattr(service_module, "parse_xml", parse)
    monkeypatch.setattr(service_module, "verify_signature", verify)
    monkeypatch.setattr(service_module, "decrypt_identifier", decrypt)
    with pytest.raises(ValueError):
        service.decrypt(tampered)
    assert attempted == (
        ["ArtifactResponse", "Assertion"] if resign_artifact else ["ArtifactResponse"]
    )
    assert verified == (["ArtifactResponse"] if resign_artifact else [])
    assert not decryptions
    if len(roots) != 1 or etree.tostring(roots[0]) != originals[0]:
        _fail_sanitized("Original signed tree changed")


@pytest.mark.parametrize(
    "change",
    [
        "audience",
        "issuer",
        "response_issuer",
        "assertion_issuer",
        "recipient",
        "service",
        "low_loa",
        "unknown_loa",
        "missing_authn_context",
        "status",
        "response_status",
        "representation",
        "missing_in_response_to",
        "inconsistent_in_response_to",
        "missing_conditions",
        "naive_time",
        "overflow_time",
        "multiple_assertions",
        "encrypted_assertion",
        "wrong_version",
        "unsupported_condition",
    ],
)
def test_rejects_signed_invalid_claims(tmp_path: Path, change: str) -> None:
    bundle = make_bundle(tmp_path)

    def mutate(root: etree._Element) -> None:
        response = root.find("./samlp:Response", NS)
        assertion = response.find("./saml:Assertion", NS)
        conditions = assertion.find("./saml:Conditions", NS)
        bearer = assertion.find(
            "./saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData", NS
        )
        if change == "audience":
            conditions.find(
                "./saml:AudienceRestriction/saml:Audience", NS
            ).text = "other"
        elif change == "issuer":
            root.find("./saml:Issuer", NS).text = "other"
        elif change == "response_issuer":
            response.find("./saml:Issuer", NS).text = "urn:wrong:issuer"
        elif change == "assertion_issuer":
            assertion.find("./saml:Issuer", NS).text = "other"
        elif change == "recipient":
            bearer.set("Recipient", "https://other.example/acs")
        elif change == "service":
            assertion.find(
                "./saml:AttributeStatement/saml:Attribute[@Name='urn:nl-eid-gdi:1.0:ServiceUUID']/saml:AttributeValue",
                NS,
            ).text = "other"
        elif change in ("low_loa", "unknown_loa"):
            assertion.find(
                "./saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef", NS
            ).text = (
                "http://eidas.europa.eu/LoA/low"
                if change == "low_loa"
                else "urn:unsupported:loa"
            )
        elif change == "missing_authn_context":
            statement = assertion.find("./saml:AuthnStatement", NS)
            statement.remove(statement.find("./saml:AuthnContext", NS))
        elif change in ("status", "response_status"):
            node = root if change == "status" else response
            node.find("./samlp:Status/samlp:StatusCode", NS).set(
                "Value", "urn:oasis:names:tc:SAML:2.0:status:Responder"
            )
        elif change == "representation":
            etree.SubElement(
                assertion.find("./saml:AttributeStatement", NS),
                etree.QName(NS["saml"], "Attribute"),
                Name="urn:nl-eid-gdi:1.0:LegalSubjectID",
            )
        elif change == "missing_in_response_to":
            del response.attrib["InResponseTo"]
        elif change == "inconsistent_in_response_to":
            bearer.set("InResponseTo", "other")
        elif change == "missing_conditions":
            assertion.remove(conditions)
        elif change == "naive_time":
            conditions.set("NotBefore", "2026-01-01T00:00:00")
        elif change == "overflow_time":
            conditions.set("NotBefore", "0001-01-01T00:00:00+01:00")
        elif change == "multiple_assertions":
            etree.SubElement(
                response, etree.QName(NS["saml"], "Assertion"), ID="_other"
            )
        elif change == "encrypted_assertion":
            etree.SubElement(response, etree.QName(NS["saml"], "EncryptedAssertion"))
        elif change == "wrong_version":
            assertion.set("Version", "1.0")
        elif change == "unsupported_condition":
            etree.SubElement(conditions, etree.QName(NS["saml"], "ProxyRestriction"))

    encoded = message(bundle, mutate)
    with pytest.raises(ValueError, match="^Invalid SAML response$"):
        SamlService(bundle.config).decrypt(encoded)


@pytest.mark.parametrize(
    "change",
    [
        "missing_assertion_signature",
        "invalid_outer_signature",
    ],
)
def test_requires_every_signature(tmp_path: Path, change: str) -> None:
    bundle = make_bundle(tmp_path)
    root = signed_artifact(bundle)
    assertion = root.find("./samlp:Response/saml:Assertion", NS)
    if change == "missing_assertion_signature":
        assertion.remove(assertion.find("./ds:Signature", NS))
        root.remove(root.find("./ds:Signature", NS))
        sign(root, bundle)
    else:
        root.find("./saml:Issuer", NS).text = "tampered"
    with pytest.raises(ValueError):
        SamlService(bundle.config).decrypt(soap_message(root))


def test_advice_does_not_control_identity_or_loa(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    bundle.config.minimum_loa = "http://eidas.europa.eu/LoA/low"
    conflicting_identity = "000000000"  # Synthetic, not a real person.
    conflicting_loa = "http://eidas.europa.eu/LoA/low"
    conflicting = encrypted_identifier(
        bundle.decrypt_key,
        plaintext=NAMEID.replace(BSN.encode(), conflicting_identity.encode()),
    )
    key = conflicting.find("./xenc:EncryptedKey", NS)
    key.set("Recipient", bundle.config.entity_id)
    key.find(
        "./ds:KeyInfo/ds:KeyName", NS
    ).text = bundle.decrypt_certificate.fingerprint(
        __import__(
            "cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]
        ).SHA256()
    ).hex()
    service = SamlService(bundle.config)
    name_id = actual_decrypt_identifier(
        conflicting,
        service.material.private_key,
        service.config.entity_id or "",
        service.material.key_name,
    )
    if name_id.text != conflicting_identity:
        pytest.fail("Conflicting Advice identity fixture is invalid", pytrace=False)

    def mutate(root: etree._Element) -> None:
        assertion = root.find("./samlp:Response/saml:Assertion", NS)
        advice = assertion.find("./saml:Advice", NS)
        nested = etree.SubElement(
            advice,
            etree.QName(NS["saml"], "Assertion"),
            ID="_advice",
            Version="2.0",
            IssueInstant=instant(),
        )
        etree.SubElement(
            nested, etree.QName(NS["saml"], "Issuer")
        ).text = assertion.find("./saml:Issuer", NS).text
        statement = copy.deepcopy(assertion.find("./saml:AuthnStatement", NS))
        statement.find(
            "./saml:AuthnContext/saml:AuthnContextClassRef", NS
        ).text = conflicting_loa
        nested.append(statement)
        attributes = copy.deepcopy(assertion.find("./saml:AttributeStatement", NS))
        acting = attributes.find(
            "./saml:Attribute[@Name='urn:nl-eid-gdi:1.0:ActingSubjectID']"
            "/saml:AttributeValue",
            NS,
        )
        acting.replace(
            acting.find("./saml:EncryptedID", NS), copy.deepcopy(conflicting)
        )
        nested.append(attributes)
        sign(nested, bundle)

    result = service.decrypt(message(bundle, mutate))
    if result.personalId != "NL:bsn:" + BSN:
        pytest.fail("Advice overrode the summary identity", pytrace=False)
    assert result.authnContextClassRef == LOA


def test_audience_is_not_taken_from_decryption_entity(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    bundle.config.audience = bundle.config.entity_id
    with pytest.raises(ValueError):
        SamlService(bundle.config).decrypt(message(bundle))


@pytest.mark.parametrize("value", ["not base64", "", "PHJvb3QvPg=="])
def test_rejects_invalid_input(tmp_path: Path, value: str) -> None:
    with pytest.raises(ValueError):
        SamlService(make_bundle(tmp_path).config).decrypt(value)


@pytest.mark.parametrize(
    "legacy_loa",
    [
        "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract",
        "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI",
    ],
)
def test_summary_requires_eid_loa_uri(tmp_path: Path, legacy_loa: str) -> None:
    bundle = make_bundle(tmp_path)

    def mutate(root: etree._Element) -> None:
        root.find(
            "./samlp:Response/saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef",
            NS,
        ).text = legacy_loa

    with pytest.raises(ValueError):
        SamlService(bundle.config).decrypt(message(bundle, mutate))


def test_basic_loa_is_distinct_from_eidas_low(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    bundle.config.minimum_loa = "http://eID.logius.nl/LoA/basic"

    def mutate(root: etree._Element) -> None:
        root.find(
            "./samlp:Response/saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef",
            NS,
        ).text = bundle.config.minimum_loa

    result = SamlService(bundle.config).decrypt(message(bundle, mutate))
    assert result.authnContextClassRef == bundle.config.minimum_loa


@pytest.mark.parametrize(
    "claim,path",
    [
        (
            "audience",
            "./samlp:Response/saml:Assertion/saml:Conditions/saml:AudienceRestriction/saml:Audience",
        ),
        (
            "loa",
            "./samlp:Response/saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef",
        ),
        ("issuer", "./saml:Issuer"),
        (
            "service",
            "./samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name='urn:nl-eid-gdi:1.0:ServiceUUID']/saml:AttributeValue",
        ),
    ],
)
def test_comments_cannot_truncate_signed_claims(
    tmp_path: Path, claim: str, path: str
) -> None:
    bundle = make_bundle(tmp_path)

    def mutate(root: etree._Element) -> None:
        node = root.find(path, NS)
        node.text += "-wrong"

    # Sign an unacceptable claim, then split it with a comment. Exclusive c14n
    # excludes comments, preserving BOTH signatures without knowing either key.
    root = signed_artifact(bundle, mutate)
    node = root.find(path, NS)
    node.text = node.text.removesuffix("-wrong")
    comment = etree.Comment("unsigned comment insertion")
    comment.tail = "-wrong"
    node.append(comment)
    with pytest.raises(ValueError):
        SamlService(bundle.config).decrypt(soap_message(root))
