"""SAML diagnostics are safe at INFO and detailed at DEBUG."""

import io
import logging
import traceback
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from typing import Any, NoReturn

import pytest
import xmlsec
from fastapi import FastAPI
from fastapi.testclient import TestClient
from lxml import etree
from saml2.response import AuthnResponse

from app.config import ConfigSaml
from app.container import get_saml_service
from app.saml import signatures
from app.saml.errors import SamlFailureReason, SamlRejected
from app.saml.service import SamlService, SamlUnavailable
from app.saml.trust import load_material, utc_time
from app.saml.xml import NS
from tests.saml_helpers import (
    artifact_from_message,
    make_bundle,
    message,
    signed_artifact,
    soap_message,
)


@pytest.fixture
def app_logs(
    app: FastAPI, caplog: pytest.LogCaptureFixture
) -> Iterator[pytest.LogCaptureFixture]:
    del app
    logger = logging.getLogger("app")
    logger.addHandler(caplog.handler)
    try:
        yield caplog
    finally:
        logger.removeHandler(caplog.handler)


@pytest.fixture
def configured_output(app: FastAPI, monkeypatch: pytest.MonkeyPatch) -> io.StringIO:
    del app
    stream = io.StringIO()
    handlers = logging.getLogger("app").handlers
    assert handlers
    for handler in handlers:
        if isinstance(handler, logging.StreamHandler):
            monkeypatch.setattr(handler, "stream", stream)
    return stream


def test_debug_level_alone_logs_original_library_error(
    app: FastAPI,
    app_logs: pytest.LogCaptureFixture,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = make_bundle(tmp_path)
    encoded = message(bundle)
    service = SamlService(bundle.config)
    app.dependency_overrides[get_saml_service] = lambda: service
    sentinel = "PRIVATE-DEBUG-LEVEL-ONLY-950000012"

    def fail(*args: Any, **kwargs: Any) -> NoReturn:
        del args, kwargs
        raise RuntimeError(sentinel)

    monkeypatch.setattr(signatures, "create_class_from_xml_string", fail)
    app_logs.set_level(logging.DEBUG, logger="app")
    with TestClient(app) as client:
        response = client.post("/saml/decrypt", json={"saml_response": encoded})
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_saml_response"}
    assert sentinel in app_logs.text


def test_debug_level_alone_logs_direct_timestamp_error(
    app: FastAPI, app_logs: pytest.LogCaptureFixture
) -> None:
    del app
    sentinel = "PRIVATE-DIRECT-TIMESTAMP-950000012"
    app_logs.set_level(logging.DEBUG, logger="app")
    with pytest.raises(ValueError, match="Invalid SAML time"):
        utc_time(sentinel)
    assert sentinel in app_logs.text


@pytest.mark.parametrize(
    ("failure", "reason"),
    [
        ("signature", "signature_failed"),
        ("issuer", "invalid_issuer"),
        ("audience", "invalid_conditions_or_audience"),
        ("unbounded_conditions", "invalid_conditions_or_audience"),
        ("format", "invalid_format"),
        ("destination", "validation_failed"),
    ],
)
def test_route_logs_safe_reason_without_request_data(
    app: FastAPI,
    app_logs: pytest.LogCaptureFixture,
    tmp_path: Path,
    failure: str,
    reason: str,
) -> None:
    bundle = make_bundle(tmp_path)

    def mutate(root: etree._Element) -> None:
        if failure == "issuer":
            root.find("./saml:Issuer", NS).text = "PRIVATE-ISSUER-SENTINEL"
        elif failure == "audience":
            root.find(
                "./samlp:Response/saml:Assertion/saml:Conditions/"
                "saml:AudienceRestriction/saml:Audience",
                NS,
            ).text = "PRIVATE-AUDIENCE-SENTINEL"
        elif failure == "unbounded_conditions":
            conditions = root.find(
                "./samlp:Response/saml:Assertion/saml:Conditions", NS
            )
            del conditions.attrib["NotOnOrAfter"]
        elif failure == "destination":
            root.find("./samlp:Response", NS).set(
                "Destination", "https://example.test/PRIVATE-DESTINATION-SENTINEL"
            )

    encoded = "not-base64" if failure == "format" else message(bundle, mutate)
    if failure == "signature":
        artifact = artifact_from_message(encoded)
        artifact.find("./saml:Issuer", NS).text = "PRIVATE-SIGNATURE-SENTINEL"
        encoded = soap_message(artifact)
    service = SamlService(bundle.config)
    app.dependency_overrides[get_saml_service] = lambda: service
    app_logs.set_level(logging.INFO, logger="app")

    with pytest.raises(SamlRejected, match="^Invalid SAML response$") as caught:
        service.decrypt(encoded)
    assert caught.value.reason.value == reason
    assert caught.value.__cause__ is None and caught.value.__context__ is None

    with TestClient(app) as client:
        response = client.post("/saml/decrypt", json={"saml_response": encoded})

    assert response.status_code == 400
    assert response.json() == {"error": "invalid_saml_response"}
    assert reason in app_logs.text
    assert encoded not in app_logs.text
    assert "PRIVATE-" not in app_logs.text


def test_throwing_conditions_validator_keeps_its_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = make_bundle(tmp_path)
    service = SamlService(bundle.config)

    def fail(_: AuthnResponse) -> NoReturn:
        raise RuntimeError("PRIVATE-CONDITIONS-LIBRARY-ERROR")

    monkeypatch.setattr(AuthnResponse, "condition_ok", fail)
    with pytest.raises(SamlRejected, match="^Invalid SAML response$") as caught:
        service.decrypt(message(bundle))

    assert caught.value.reason is SamlFailureReason.INVALID_CONDITIONS_OR_AUDIENCE
    assert caught.value.__cause__ is None and caught.value.__context__ is None


@pytest.mark.parametrize(
    ("level", "shows_trace"), [(logging.INFO, False), (logging.DEBUG, True)]
)
def test_route_logs_arbitrary_value_error_only_at_debug(
    app: FastAPI,
    app_logs: pytest.LogCaptureFixture,
    level: int,
    shows_trace: bool,
) -> None:
    sentinel = "PRIVATE-ARBITRARY-ERROR-950000012"

    class FailingService:
        def decrypt(self, saml_response: str) -> NoReturn:
            raise ValueError(f"{sentinel}: {saml_response}")

    service = FailingService()
    app.dependency_overrides[get_saml_service] = lambda: service
    app_logs.set_level(level, logger="app")
    with TestClient(app) as client:
        response = client.post("/saml/decrypt", json={"saml_response": sentinel})

    assert response.status_code == 400
    assert response.json() == {"error": "invalid_saml_response"}
    assert sentinel not in response.text
    assert (sentinel in app_logs.text) is shows_trace


def test_safe_reason_reaches_configured_application_console(
    app: FastAPI, configured_output: io.StringIO, tmp_path: Path
) -> None:
    bundle = make_bundle(tmp_path)

    def invalid_issuer(root: etree._Element) -> None:
        root.find("./saml:Issuer", NS).text = "PRIVATE-ISSUER-SENTINEL"

    service = SamlService(bundle.config)
    app.dependency_overrides[get_saml_service] = lambda: service
    encoded = message(bundle, invalid_issuer)
    with TestClient(app) as client:
        response = client.post("/saml/decrypt", json={"saml_response": encoded})
    output = configured_output.getvalue()
    assert response.status_code == 400
    assert "invalid_issuer" in output
    assert "PRIVATE-ISSUER-SENTINEL" not in output


@pytest.mark.parametrize(
    ("level", "shows_trace"), [(logging.INFO, False), (logging.DEBUG, True)]
)
def test_debug_trace_reaches_configured_console(
    app: FastAPI,
    configured_output: io.StringIO,
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    level: int,
    shows_trace: bool,
) -> None:
    bundle = make_bundle(tmp_path)
    encoded = message(bundle)
    service = SamlService(bundle.config)
    app.dependency_overrides[get_saml_service] = lambda: service
    sentinel = "PRIVATE-CONSOLE-TRACE-950000012"

    def fail(*args: Any, **kwargs: Any) -> NoReturn:
        del args, kwargs
        raise RuntimeError(sentinel)

    monkeypatch.setattr(signatures, "create_class_from_xml_string", fail)
    caplog.set_level(level, logger="app")
    for handler in logging.getLogger("app").handlers:
        if (
            isinstance(handler, logging.StreamHandler)
            and handler.stream is configured_output
        ):
            monkeypatch.setattr(handler, "level", level)
    with TestClient(app) as client:
        response = client.post("/saml/decrypt", json={"saml_response": encoded})
    output = configured_output.getvalue()
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_saml_response"}
    assert (sentinel in output) is shows_trace


@pytest.mark.parametrize(
    ("level", "shows_trace"),
    [
        (logging.INFO, False),
        (logging.DEBUG, True),
    ],
)
def test_startup_material_failure_logs_raw_details_only_at_debug(
    app: FastAPI,
    app_logs: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    level: int,
    shows_trace: bool,
) -> None:
    del app
    sentinel = "PRIVATE-STARTUP-KEY-SENTINEL"

    def fail(_: ConfigSaml) -> NoReturn:
        raise OSError(sentinel)

    monkeypatch.setattr("app.saml.trust._load_material", fail)
    config = ConfigSaml()
    app_logs.set_level(level, logger="app")
    with pytest.raises(
        ValueError, match="Invalid SAML key or metadata configuration"
    ) as caught:
        load_material(config)
    assert sentinel not in "".join(traceback.format_exception(caught.value))
    assert (sentinel in app_logs.text) is shows_trace


@pytest.mark.parametrize(
    ("level", "shows_trace"),
    [
        (logging.INFO, False),
        (logging.DEBUG, True),
    ],
)
@pytest.mark.parametrize(
    "boundary", ["pysaml2", "xmlsec-signature", "xmlsec-decryption"]
)
def test_raw_library_errors_are_logged_only_at_debug(
    app: FastAPI,
    app_logs: pytest.LogCaptureFixture,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    level: int,
    shows_trace: bool,
    boundary: str,
) -> None:
    bundle = make_bundle(tmp_path)
    encoded = message(bundle)
    service = SamlService(bundle.config)
    app.dependency_overrides[get_saml_service] = lambda: service
    sentinel = "PRIVATE-LOCAL-TRACE-950000012"

    def fail(*args: Any, **kwargs: Any) -> NoReturn:
        del args, kwargs
        try:
            raise RuntimeError(sentinel)
        except RuntimeError as cause:
            raise ValueError("synthetic library wrapper") from cause

    if boundary == "pysaml2":
        monkeypatch.setattr(signatures, "create_class_from_xml_string", fail)
    elif boundary == "xmlsec-signature":
        monkeypatch.setattr(xmlsec, "SignatureContext", fail)
    else:
        monkeypatch.setattr(xmlsec, "EncryptionContext", fail)

    app_logs.set_level(level, logger="app")
    with TestClient(app) as client:
        response = client.post("/saml/decrypt", json={"saml_response": encoded})
        assert response.status_code == 400
        assert response.json() == {"error": "invalid_saml_response"}
        assert (
            "decryption_failed"
            if boundary == "xmlsec-decryption"
            else "signature_failed"
        ) in app_logs.text
        assert (sentinel in app_logs.text) is shows_trace
        if shows_trace:
            assert "synthetic library wrapper" in app_logs.text
            app_logs.clear()
            app_logs.set_level(logging.INFO, logger="app")
            response = client.post("/saml/decrypt", json={"saml_response": encoded})
            assert response.status_code == 400
            assert sentinel not in app_logs.text


def test_simultaneous_requests_keep_failure_reasons_isolated(
    app: FastAPI,
    app_logs: pytest.LogCaptureFixture,
    tmp_path: Path,
) -> None:
    del app
    bundle = make_bundle(tmp_path)
    service = SamlService(bundle.config)

    def invalid_issuer(root: etree._Element) -> None:
        root.find("./saml:Issuer", NS).text = "urn:unexpected"

    issuer_message = message(bundle, invalid_issuer)
    artifact = signed_artifact(bundle)
    artifact.find("./saml:Issuer", NS).text = "urn:tampered"
    signature_message = soap_message(artifact)
    release = Event()
    app_logs.set_level(logging.INFO, logger="app")

    def run(encoded: str) -> str:
        assert release.wait(5)
        with pytest.raises(SamlRejected, match="Invalid SAML response") as caught:
            service.decrypt(encoded)
        return caught.value.reason.value

    with ThreadPoolExecutor(max_workers=2) as pool:
        signature_future = pool.submit(run, signature_message)
        issuer_future = pool.submit(run, issuer_message)
        release.set()
        assert signature_future.result(timeout=5) == "signature_failed"
        assert issuer_future.result(timeout=5) == "invalid_issuer"


@pytest.mark.parametrize(
    ("level", "shows_trace"), [(logging.INFO, False), (logging.DEBUG, True)]
)
@pytest.mark.parametrize("boundary", ["xml", "timestamp", "material"])
def test_debug_exposes_exceptions_hidden_by_inner_sanitizers(
    app: FastAPI,
    app_logs: pytest.LogCaptureFixture,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    level: int,
    shows_trace: bool,
) -> None:
    del app
    bundle = make_bundle(tmp_path)
    service = SamlService(bundle.config)
    sentinel = "PRIVATE-INNER-EXCEPTION-950000012"
    encoded = "PHgvPg=="
    expected_type: type[ValueError] = ValueError
    expected_message = "Invalid SAML response"
    if boundary == "xml":

        def fail_parser(*args: Any, **kwargs: Any) -> NoReturn:
            del args, kwargs
            raise etree.XMLSyntaxError(sentinel, 0, 1, 1)

        monkeypatch.setattr(etree, "fromstring", fail_parser)
    elif boundary == "timestamp":

        def fail_timestamp(_: str) -> NoReturn:
            utc_time(sentinel)
            raise AssertionError("invalid timestamp was accepted")

        monkeypatch.setattr(service, "_decrypt", fail_timestamp)
    else:
        encoded = message(bundle)
        expected_type = SamlUnavailable
        expected_message = "SAML configuration expired"

        def fail_material(*args: Any, **kwargs: Any) -> NoReturn:
            del args, kwargs
            raise ValueError(sentinel)

        monkeypatch.setattr(
            type(service.material), "active_certificates", fail_material
        )

    app_logs.set_level(level, logger="app")
    with pytest.raises(expected_type, match=expected_message) as caught:
        service.decrypt(encoded)
    assert sentinel not in "".join(traceback.format_exception(caught.value))
    assert (sentinel in app_logs.text) is shows_trace
