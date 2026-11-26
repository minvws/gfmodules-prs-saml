import base64
import logging
import traceback
import warnings
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn, cast
from unittest.mock import Mock

import pytest
import xmlsec
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI
from fastapi.testclient import TestClient
from gfmodules.logging.testing import capture_records
from lxml import etree
from pydantic import BaseModel
from saml2.response import AuthnResponse
from starlette.responses import JSONResponse

import app.saml.service as service_module
import app.saml.signatures as signatures_module
from app.container import get_saml_service
from app.logging.events import Log
from app.models.saml import DecryptRequest, DecryptResult
from app.routers.saml import post_decrypt
from app.saml.decryption import decrypt_identifier
from app.saml.errors import SamlFailureReason, SamlRejected
from app.saml.service import SamlService, SamlUnavailable
from app.saml.xml import NS
from tests.saml_helpers import (
    BSN,
    LOA,
    artifact_from_message,
    make_bundle,
    message,
    sign,
    signed_artifact,
    soap_message,
)

ENDPOINT = "/saml/decrypt"


@pytest.fixture
def configured_application_logs(
    app: FastAPI, caplog: pytest.LogCaptureFixture
) -> Iterator[pytest.LogCaptureFixture]:
    del app  # Ensure logging is configured before attaching the observer.
    app_logger = logging.getLogger("app")
    caplog.set_level("INFO", logger="app")
    app_logger.addHandler(caplog.handler)
    try:
        yield caplog
    finally:
        app_logger.removeHandler(caplog.handler)


@pytest.mark.parametrize("xml_declaration", [False, True])
def test_decrypt_rejects_bare_artifact_response(
    app: FastAPI,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    xml_declaration: bool,
) -> None:
    bundle = make_bundle(tmp_path)
    service = SamlService(bundle.config)
    app.dependency_overrides[get_saml_service] = lambda: service
    encoded = base64.b64encode(
        etree.tostring(
            signed_artifact(bundle), encoding="UTF-8", xml_declaration=xml_declaration
        )
    ).decode()
    verify_signature_spy = Mock(wraps=signatures_module.verify_signature)
    decrypt_identifier_spy = Mock(wraps=decrypt_identifier)
    monkeypatch.setattr(service_module, "verify_signature", verify_signature_spy)
    monkeypatch.setattr(service_module, "decrypt_identifier", decrypt_identifier_spy)

    with TestClient(app) as client:
        response = client.post(ENDPOINT, json={"saml_response": encoded})

    assert response.status_code == 400
    assert response.json() == {"error": "invalid_saml_response"}
    verify_signature_spy.assert_not_called()
    decrypt_identifier_spy.assert_not_called()


@pytest.mark.parametrize(
    ("root_path", "path", "mounted"),
    [
        ("", "/saml/decrypt", False),
        ("/edge", "/edge/saml/decrypt", False),
        ("/base", "/base/edge/saml/decrypt", True),
    ],
    ids=["direct", "root-path", "mounted"],
)
@pytest.mark.parametrize("valid", [True, False], ids=["valid", "invalid-saml"])
def test_decrypt_status_contract_across_routes(
    app: FastAPI, tmp_path: Path, root_path: str, path: str, mounted: bool, valid: bool
) -> None:
    bundle = make_bundle(tmp_path)
    service = SamlService(bundle.config)
    app.dependency_overrides[get_saml_service] = lambda: service
    target = app
    if mounted:
        target = FastAPI()
        target.mount("/edge", app)
    value = message(bundle) if valid else "PRIVATE-INVALID-SAML"
    with TestClient(target, root_path=root_path) as client:
        response = client.post(path, json={"saml_response": value})
    if valid:
        assert response.status_code == 200
        assert response.json() == {
            "personalId": "NL:bsn:" + BSN,
            "authnContextClassRef": LOA,
        }
    else:
        assert response.status_code == 400
        assert response.json() == {"error": "invalid_saml_response"}
        assert value not in response.text


@pytest.mark.parametrize("failure", ["service", "invalid-result-dict"])
def test_unexpected_decrypt_failure_is_private_at_asgi_boundary(
    app: FastAPI,
    caplog: pytest.LogCaptureFixture,
    capfd: pytest.CaptureFixture[str],
    failure: str,
) -> None:
    sentinel = "PRIVATE-ASGI-FAILURE-SENTINEL-950000012"

    class FailingService:
        def decrypt(self, saml_response: str) -> object:
            if failure == "service":
                raise RuntimeError(f"unexpected service failure: {saml_response}")
            return {
                "personalId": {"invalid": saml_response},
                "authnContextClassRef": LOA,
            }

    service = FailingService()
    app.dependency_overrides[get_saml_service] = lambda: service

    caplog.set_level("DEBUG")
    capfd.readouterr()
    escaped = None
    response = None
    with capture_records("app.application") as outer_logs:
        try:
            with TestClient(app) as client:
                response = client.post(ENDPOINT, json={"saml_response": sentinel})
        except Exception as error:  # noqa: BLE001 - observe the ASGI server boundary
            escaped = type(error).__name__
    captured = capfd.readouterr()

    assert escaped is None
    assert response is not None
    assert response.status_code == 500
    assert response.json() == {"error": "Internal server error"}
    assert sentinel not in response.text
    assert sentinel not in caplog.text
    assert sentinel not in captured.out + captured.err
    assert not any(
        getattr(entry.record, "event_id", None) == Log.SYS_UNHANDLED_EXCEPTION.event_id
        for entry in outer_logs.entries
    )


@pytest.mark.parametrize(
    ("failure", "status", "body"),
    [
        ("unexpected-service", 500, b'{"error":"Internal server error"}'),
        ("invalid-saml", 400, b'{"error":"invalid_saml_response"}'),
        ("unavailable-service", 503, b'{"error":"saml_unavailable"}'),
        ("disabled-service", 503, b'{"error":"saml_unavailable"}'),
    ],
)
def test_saml_error_responses_do_not_depend_on_json_renderer(
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
    configured_application_logs: pytest.LogCaptureFixture,
    capfd: pytest.CaptureFixture[str],
    failure: str,
    status: int,
    body: bytes,
) -> None:
    sentinel = "PRIVATE-PERSISTENT-RENDER-950000012"
    render_attempts = 0

    def broken_render(self: JSONResponse, content: Any) -> bytes:
        nonlocal render_attempts
        del self, content
        render_attempts += 1
        raise RuntimeError("synthetic persistent renderer failure")

    class FailingService:
        def decrypt(self, saml_response: str) -> NoReturn:
            if failure == "unexpected-service":
                raise RuntimeError(f"synthetic service failure: {saml_response}")
            if failure == "invalid-saml":
                raise ValueError(f"synthetic invalid input: {saml_response}")
            if failure == "unavailable-service":
                raise SamlUnavailable(f"synthetic unavailable: {saml_response}")
            raise AssertionError("Unexpected synthetic failure mode")

    monkeypatch.setattr(JSONResponse, "render", broken_render)
    if failure != "disabled-service":
        service = FailingService()
        app.dependency_overrides[get_saml_service] = lambda: service

    capfd.readouterr()
    escaped: Exception | None = None
    response = None
    with warnings.catch_warnings(record=True) as observed_warnings:
        warnings.simplefilter("always")
        try:
            with TestClient(app) as client:
                response = client.post(ENDPOINT, json={"saml_response": sentinel})
        except Exception as error:  # noqa: BLE001 - inspect the ASGI boundary
            escaped = error
    captured = capfd.readouterr()
    escaped_trace = "".join(traceback.format_exception(escaped)) if escaped else ""

    problems = []
    if escaped is not None:
        problems.append(f"ASGI escaped {type(escaped).__name__}")
    if sentinel in escaped_trace:
        problems.append("marker in escaped exception chain")
    if sentinel in configured_application_logs.text:
        problems.append("marker in configured application logs")
    if sentinel in captured.out + captured.err:
        problems.append("marker in stdout/stderr")
    if observed_warnings:
        problems.append("warnings emitted")
    if response is None:
        problems.append("no response")
    else:
        if response.status_code != status:
            problems.append(f"status {response.status_code}, expected {status}")
        if response.content != body:
            problems.append("incorrect JSON body")
        if response.headers.get("content-type") != "application/json":
            problems.append("incorrect content type")
        if sentinel.encode() in response.content:
            problems.append("marker in response")
    if render_attempts:
        problems.append(f"JSON renderer called {render_attempts} times")
    if "SAML response processed" in configured_application_logs.text:
        problems.append("premature success log")
    assert not problems, ", ".join(problems)


def test_post_decrypt_returns_the_service_model(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    payload = DecryptRequest(saml_response=message(bundle))

    result = post_decrypt(payload, SamlService(bundle.config))

    assert isinstance(result, DecryptResult)
    assert result.personalId == "NL:bsn:" + BSN
    assert result.authnContextClassRef == LOA


def test_application_handles_response_serialization_failure(app: FastAPI) -> None:
    class ResultService:
        def decrypt(self, saml_response: str) -> DecryptResult:
            del saml_response
            return DecryptResult(personalId="\ud800", authnContextClassRef=LOA)

    service = ResultService()
    app.dependency_overrides[get_saml_service] = lambda: service

    with (
        capture_records("app.application") as captured,
        TestClient(app, raise_server_exceptions=False) as client,
    ):
        response = client.post(ENDPOINT, json={"saml_response": "synthetic-input"})

    assert response.status_code == 500
    assert response.json() == {"error": "Internal server error"}
    assert any(
        getattr(entry.record, "event_id", None) == Log.SYS_UNHANDLED_EXCEPTION.event_id
        for entry in captured.entries
    )


@pytest.mark.parametrize("represented", [None, "NL:bsn:000000000"])
def test_decrypt_response_fields_and_openapi_are_preserved(
    app: FastAPI,
    configured_application_logs: pytest.LogCaptureFixture,
    represented: str | None,
) -> None:
    class ResultService:
        def decrypt(self, saml_response: str) -> DecryptResult:
            del saml_response
            return DecryptResult(
                personalId="NL:bsn:" + BSN,
                authnContextClassRef=LOA,
                representedPersonalId=represented,
            )

    service = ResultService()
    app.dependency_overrides[get_saml_service] = lambda: service
    with TestClient(app) as client:
        response = client.post(ENDPOINT, json={"saml_response": "synthetic-input"})
    expected = {"personalId": "NL:bsn:" + BSN, "authnContextClassRef": LOA}
    if represented is not None:
        expected["representedPersonalId"] = represented
    assert response.status_code == 200
    assert response.json() == expected
    assert any(
        record.name == "app.routers.saml"
        and record.getMessage() == "SAML response processed"
        for record in configured_application_logs.records
    )
    openapi = app.openapi()
    schema = openapi["paths"][ENDPOINT]["post"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]
    assert schema == {"$ref": "#/components/schemas/DecryptResult"}
    assert set(openapi["components"]["schemas"]["DecryptResult"]["properties"]) == {
        "personalId",
        "authnContextClassRef",
        "representedPersonalId",
    }


@pytest.mark.parametrize(
    ("status", "bodies"),
    [
        (
            "400",
            [
                {"error": "invalid_saml_response"},
                {"detail": "There was an error parsing the body"},
            ],
        ),
        ("503", [{"error": "saml_unavailable"}]),
        ("500", [{"error": "Internal server error"}]),
    ],
)
def test_decrypt_openapi_describes_actual_private_error_bodies(
    app: FastAPI, status: str, bodies: list[dict[str, str]]
) -> None:
    responses = app.openapi()["paths"][ENDPOINT]["post"]["responses"]
    assert status in responses
    schema = responses[status]["content"]["application/json"]["schema"]
    variants = schema.get("oneOf", [schema])
    assert len(variants) == len(bodies)
    for variant, body in zip(variants, bodies, strict=True):
        field, value = next(iter(body.items()))
        assert variant == {
            "type": "object",
            "properties": {field: {"type": "string", "const": value}},
            "required": [field],
            "additionalProperties": False,
        }


@pytest.mark.parametrize(
    ("body", "status"),
    [
        (b'{"saml_response":"anything"}', 503),
        (b'{"saml_response":"SECRET-MALFORMED', 422),
        (b'{"saml_response":{"SECRET-MALFORMED":1}}', 422),
    ],
    ids=["valid", "malformed", "wrong-type"],
)
def test_request_validation_precedes_disabled_service(
    app: FastAPI,
    caplog: pytest.LogCaptureFixture,
    capfd: pytest.CaptureFixture[str],
    body: bytes,
    status: int,
) -> None:
    caplog.set_level("DEBUG")
    capfd.readouterr()
    with TestClient(app) as client:
        response = client.post(
            ENDPOINT, content=body, headers={"Content-Type": "application/json"}
        )
    captured = capfd.readouterr()
    assert response.status_code == status
    if status == 422:
        assert isinstance(response.json()["detail"], list)
    else:
        assert response.json() == {"error": "saml_unavailable"}
    assert "SECRET-MALFORMED" not in caplog.text
    assert "SECRET-MALFORMED" not in captured.out + captured.err


@pytest.mark.parametrize("enabled", [False, True], ids=["disabled", "enabled"])
def test_body_parser_failures_keep_private_framework_errors(
    app: FastAPI,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    capfd: pytest.CaptureFixture[str],
    enabled: bool,
) -> None:
    if enabled:
        service = SamlService(make_bundle(tmp_path).config)
        app.dependency_overrides[get_saml_service] = lambda: service
    caplog.set_level("DEBUG")
    capfd.readouterr()
    with TestClient(app) as client:
        response = client.post(
            ENDPOINT,
            content=b'{"saml_response":"PRIVATE-PARSE-SENTINEL\xff"}',
            headers={"Content-Type": "application/json"},
        )
    captured = capfd.readouterr()
    assert response.status_code == 400
    assert response.json() == {"detail": "There was an error parsing the body"}
    assert "PRIVATE-PARSE-SENTINEL" not in response.text
    assert "PRIVATE-PARSE-SENTINEL" not in caplog.text
    assert "PRIVATE-PARSE-SENTINEL" not in captured.out + captured.err


def test_mounted_endpoint_uses_fastapi_validation_error(app: FastAPI) -> None:
    parent = FastAPI()
    parent.mount("/edge", app)
    with TestClient(parent, root_path="/base") as client:
        response = client.post(
            "/base/edge/saml/decrypt",
            content=b'{"secret-value":',
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 422
    assert isinstance(response.json()["detail"], list)
    assert "secret-value" not in response.text


@pytest.mark.parametrize("swagger_enabled", [False, True])
def test_ini_root_path_depends_on_swagger_configuration(
    app: FastAPI,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    swagger_enabled: bool,
) -> None:
    from app.application import get_uvicorn_params, setup_fastapi
    from app.config import Config, read_ini_file

    config_file = tmp_path / "root-path.ini"
    config_file.write_text(
        f"[app]\n[uvicorn]\nroot_path = /edge\nswagger_enabled = {swagger_enabled}\n"
    )
    config = Config.model_validate(read_ini_file(str(config_file)))
    monkeypatch.setattr("app.application.get_config", lambda: config)
    configured_app = setup_fastapi()
    assert configured_app.root_path == ("/edge" if swagger_enabled else "")
    assert "root_path" not in get_uvicorn_params()
    with TestClient(configured_app) as client:
        prefixed = client.post("/edge/saml/decrypt", json={"saml_response": "x"})
        unprefixed = client.post("/saml/decrypt", json={"saml_response": "x"})
    assert prefixed.status_code == (503 if swagger_enabled else 404)
    assert unprefixed.status_code == 503
    assert unprefixed.json() == {"error": "saml_unavailable"}


class OtherRequest(BaseModel):
    count: int


def test_unrelated_route_keeps_default_validation_error(app: FastAPI) -> None:
    @app.post("/test-validated")
    def validated(payload: OtherRequest) -> dict[str, int]:
        return {"count": payload.count}

    with TestClient(app) as client:
        response = client.post("/test-validated", json={"count": "not-a-number"})
    assert response.status_code == 422
    assert isinstance(response.json()["detail"], list)


def test_unrelated_response_validation_keeps_generic_error_contract(
    app: FastAPI,
) -> None:
    @app.get("/test-invalid-response", response_model=OtherRequest)
    def invalid_response() -> dict[str, str]:
        return {"count": "not-a-number"}

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/test-invalid-response")
    assert response.status_code == 500
    assert response.json() == {"error": "Internal server error"}


def test_unrelated_unexpected_errors_keep_original_contract(app: FastAPI) -> None:
    @app.post("/saml/decrypt-extra", response_model=None)
    def fail() -> NoReturn:
        raise RuntimeError("synthetic unrelated failure")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post("/saml/decrypt-extra")
    assert response.status_code == 500
    assert response.json() == {"error": "Internal server error"}
    assert "cache-control" not in response.headers


@pytest.fixture
def enabled_client(client: TestClient, tmp_path: Path) -> TestClient:
    bundle = make_bundle(tmp_path)
    service = SamlService(bundle.config)
    cast(FastAPI, client.app).dependency_overrides[get_saml_service] = lambda: service
    return client


def test_real_signed_and_encrypted_response_is_processed(
    client: TestClient, tmp_path: Path
) -> None:
    bundle = make_bundle(tmp_path)
    service = SamlService(bundle.config)
    cast(FastAPI, client.app).dependency_overrides[get_saml_service] = lambda: service
    response = client.post(
        ENDPOINT,
        json={
            "saml_response": message(bundle),
            "recipientOrganization": "ignored-by-crypto-service",
            "domain": "vad",
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "personalId": "NL:bsn:" + BSN,
        "authnContextClassRef": LOA,
    }


def test_signed_cancellation_without_assertion_returns_generic_400(
    client: TestClient, tmp_path: Path
) -> None:
    bundle = make_bundle(tmp_path)
    service = SamlService(bundle.config)
    cast(FastAPI, client.app).dependency_overrides[get_saml_service] = lambda: service
    artifact = signed_artifact(bundle)
    artifact.remove(artifact.find("./ds:Signature", NS))
    response_node = artifact.find("./samlp:Response", NS)
    response_node.remove(response_node.find("./saml:Assertion", NS))
    status = response_node.find("./samlp:Status", NS)
    code = status.find("./samlp:StatusCode", NS)
    code.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Responder")
    etree.SubElement(
        code,
        etree.QName(NS["samlp"], "StatusCode"),
        Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
    )
    etree.SubElement(
        status, etree.QName(NS["samlp"], "StatusMessage")
    ).text = "Authentication cancelled"
    sign(artifact, bundle)
    encoded = soap_message(artifact)

    # Independently verify the artifact inside the exact SOAP input.
    independent = artifact_from_message(encoded)
    context = xmlsec.SignatureContext()
    context.key = xmlsec.Key.from_memory(
        bundle.signing_certificate.public_bytes(serialization.Encoding.PEM),
        xmlsec.constants.KeyDataFormatCertPem,
    )
    context.register_id(independent, "ID")
    context.verify(independent.find("./ds:Signature", NS))

    response = client.post(ENDPOINT, json={"saml_response": encoded})
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_saml_response"}


def test_signed_response_above_former_xml_limit_succeeds(
    client: TestClient, tmp_path: Path
) -> None:
    bundle = make_bundle(tmp_path)
    service = SamlService(bundle.config)
    cast(FastAPI, client.app).dependency_overrides[get_saml_service] = lambda: service

    def enlarge(root: etree._Element) -> None:
        advice = root.find("./samlp:Response/saml:Assertion/saml:Advice", NS)
        assert advice is not None
        advice.text = " " * 2_097_153

    encoded = message(bundle, enlarge)
    assert len(base64.b64decode(encoded)) > 2_097_152
    response = client.post(ENDPOINT, json={"saml_response": encoded})
    assert response.status_code == 200
    assert response.json()["personalId"] == "NL:bsn:" + BSN


def test_large_ignored_json_field_does_not_limit_request_body(
    client: TestClient, tmp_path: Path
) -> None:
    bundle = make_bundle(tmp_path)
    service = SamlService(bundle.config)
    cast(FastAPI, client.app).dependency_overrides[get_saml_service] = lambda: service
    response = client.post(
        ENDPOINT,
        json={"saml_response": message(bundle), "ignored": "x" * 2_800_000},
    )
    assert response.status_code == 200
    assert response.json()["personalId"] == "NL:bsn:" + BSN


@pytest.mark.parametrize(
    "payload",
    [
        {"samlResponse": "legacy-field-value"},
        {"saml_response": 42},
        {"saml_response": ""},
    ],
    ids=["legacy-field", "not-a-string", "empty"],
)
def test_invalid_request_returns_fastapi_validation_detail(
    enabled_client: TestClient, payload: object
) -> None:
    response = enabled_client.post(ENDPOINT, json=payload)
    assert response.status_code == 422
    assert isinstance(response.json()["detail"], list)


def test_invalid_saml_does_not_leak_input_or_library_error(
    enabled_client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    sensitive = "sensitive-invalid-response"
    response = enabled_client.post(ENDPOINT, json={"saml_response": sensitive})
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_saml_response"}
    assert sensitive not in response.text
    assert sensitive not in caplog.text


@pytest.mark.parametrize(
    "boundary", ["pysaml2", "xmlsec-signature", "xmlsec-decryption"]
)
def test_library_exception_details_are_not_exposed(
    app: FastAPI,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    capfd: pytest.CaptureFixture[str],
    boundary: str,
) -> None:
    bundle = make_bundle(tmp_path)
    service = SamlService(bundle.config)
    app.dependency_overrides[get_saml_service] = lambda: service
    encoded = message(bundle)
    sentinel = "PRIVATE-SENTINEL-950000012"
    calls: list[bool] = []

    def fail(*args: Any, **kwargs: Any) -> NoReturn:
        del args, kwargs
        calls.append(True)
        raise RuntimeError(sentinel)

    if boundary == "pysaml2":
        monkeypatch.setattr(signatures_module, "create_class_from_xml_string", fail)
    elif boundary == "xmlsec-signature":
        monkeypatch.setattr(xmlsec, "SignatureContext", fail)
    else:
        monkeypatch.setattr(xmlsec, "EncryptionContext", fail)

    caplog.set_level("DEBUG")
    capfd.readouterr()
    try:
        service.decrypt(encoded)
    except Exception as caught:  # noqa: BLE001 - inspect any escaped library error
        error = caught
    else:
        pytest.fail("Injected library exception did not reach the boundary")
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post(ENDPOINT, json={"saml_response": encoded})
    captured = capfd.readouterr()

    assert calls == [True, True]
    assert isinstance(error, SamlRejected)
    assert error.reason is (
        SamlFailureReason.DECRYPTION_FAILED
        if boundary == "xmlsec-decryption"
        else SamlFailureReason.SIGNATURE_FAILED
    )
    assert sentinel not in str(error)
    assert sentinel not in "".join(traceback.format_exception(error))
    assert error.__cause__ is None and error.__context__ is None
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_saml_response"}
    assert sentinel not in response.text
    assert sentinel not in caplog.text
    assert sentinel not in captured.out + captured.err


@pytest.mark.parametrize(
    "boundary",
    ["pysaml2", "pysaml2-conditions", "xmlsec-signature", "xmlsec-decryption"],
)
@pytest.mark.parametrize("ambient_exception", [False, True])
def test_library_unavailable_is_sanitized_and_remains_unavailable(
    app: FastAPI,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    capfd: pytest.CaptureFixture[str],
    boundary: str,
    ambient_exception: bool,
) -> None:
    bundle = make_bundle(tmp_path)
    service = SamlService(bundle.config)
    app.dependency_overrides[get_saml_service] = lambda: service
    encoded = message(bundle)
    sentinel = "PRIVATE-UNAVAILABLE-SENTINEL-950000012"
    safe_message = "SAML configuration unavailable"
    calls: list[bool] = []

    def unavailable(*args: Any, **kwargs: Any) -> NoReturn:
        del args, kwargs
        calls.append(True)
        try:
            raise RuntimeError(sentinel)
        except RuntimeError as cause:
            raise SamlUnavailable(
                safe_message if boundary == "pysaml2-conditions" else sentinel
            ) from cause

    if boundary == "pysaml2":
        monkeypatch.setattr(
            signatures_module, "create_class_from_xml_string", unavailable
        )
    elif boundary == "pysaml2-conditions":
        monkeypatch.setattr(AuthnResponse, "condition_ok", unavailable)
    elif boundary == "xmlsec-signature":
        monkeypatch.setattr(xmlsec, "SignatureContext", unavailable)
    else:
        monkeypatch.setattr(xmlsec, "EncryptionContext", unavailable)

    def capture_error() -> Exception:
        try:
            service.decrypt(encoded)
        except Exception as error:  # noqa: BLE001 - inspect escaped boundary errors
            return error
        pytest.fail("Injected unavailable exception did not reach the boundary")

    caplog.set_level("DEBUG")
    capfd.readouterr()
    if ambient_exception:
        try:
            raise RuntimeError(sentinel)
        except RuntimeError:
            error = capture_error()
    else:
        error = capture_error()
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post(ENDPOINT, json={"saml_response": encoded})
    captured = capfd.readouterr()

    problems = []
    if type(error) is not SamlUnavailable:
        problems.append(f"direct type={type(error).__name__}")
    elif error.reason is not SamlFailureReason.CONFIGURATION_UNAVAILABLE:
        problems.append("direct reason is not configuration_unavailable")
    if sentinel in str(error) or sentinel in "".join(traceback.format_exception(error)):
        problems.append("sentinel in direct exception")
    if error.__cause__ is not None or error.__context__ is not None:
        problems.append("direct exception retains cause/context")
    if response.status_code != 503 or response.json() != {"error": "saml_unavailable"}:
        problems.append(f"HTTP status={response.status_code}")
    if sentinel in response.text or sentinel in caplog.text:
        problems.append("sentinel in response or logs")
    if sentinel in captured.out + captured.err:
        problems.append("sentinel in stdout/stderr")
    assert calls == [True, True]
    assert not problems, ", ".join(problems)
    assert str(error) == safe_message


def test_signature_validation_programming_error_is_not_swallowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = make_bundle(tmp_path)
    service = SamlService(bundle.config)
    encoded = message(bundle)

    def bug(*args: Any, **kwargs: Any) -> NoReturn:
        del args, kwargs
        raise RuntimeError("synthetic validation programming error")

    monkeypatch.setattr(signatures_module, "_select_certificate", bug)
    with pytest.raises(RuntimeError, match="^synthetic validation programming error$"):
        service.decrypt(encoded)


def test_malformed_json_does_not_leak_input(enabled_client: TestClient) -> None:
    response = enabled_client.post(
        ENDPOINT,
        content=b'{"secret-value":',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    (detail,) = response.json()["detail"]
    assert detail["type"] == "json_invalid"
    assert "secret-value" not in response.text


@pytest.mark.parametrize("enabled", [False, True], ids=["disabled", "enabled"])
@pytest.mark.parametrize(
    ("body", "error_type"),
    [
        (b'{"saml_response":"PRIVATE-VALIDATION-SENTINEL', "json_invalid"),
        (b'{"saml_response":{"PRIVATE-VALIDATION-SENTINEL":42}}', "string_type"),
    ],
    ids=["malformed-json", "wrong-type"],
)
def test_request_validation_does_not_log_private_input(
    app: FastAPI,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    capfd: pytest.CaptureFixture[str],
    enabled: bool,
    body: bytes,
    error_type: str,
) -> None:
    if enabled:
        bundle = make_bundle(tmp_path)
        service = SamlService(bundle.config)
        app.dependency_overrides[get_saml_service] = lambda: service
    caplog.set_level("DEBUG")
    capfd.readouterr()
    with TestClient(app) as client:
        response = client.post(
            ENDPOINT, content=body, headers={"Content-Type": "application/json"}
        )
    captured = capfd.readouterr()
    assert response.status_code == 422
    (detail,) = response.json()["detail"]
    assert detail["type"] == error_type
    assert "PRIVATE-VALIDATION-SENTINEL" not in caplog.text
    assert "PRIVATE-VALIDATION-SENTINEL" not in captured.out
    assert "PRIVATE-VALIDATION-SENTINEL" not in captured.err


def test_invalid_material_prevents_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.application import setup_fastapi
    from app.config import get_config

    bundle = make_bundle(tmp_path)
    assert bundle.config.decryption_key_file is not None
    bundle.config.decryption_key_file.unlink()
    config = get_config().model_copy(update={"saml": bundle.config})
    monkeypatch.setattr("app.application.get_config", lambda: config)
    with pytest.raises(ValueError, match="Invalid SAML key or metadata configuration"):
        setup_fastapi()


def test_expired_loaded_material_returns_unavailable(
    enabled_client: TestClient, tmp_path: Path
) -> None:
    bundle = make_bundle(tmp_path)
    service = SamlService(bundle.config)
    service.material = replace(
        service.material, valid_until=datetime.now(UTC) - timedelta(seconds=1)
    )
    app = cast(FastAPI, enabled_client.app)
    app.dependency_overrides[get_saml_service] = lambda: service
    encoded = message(bundle)
    with pytest.raises(SamlUnavailable, match="^SAML configuration expired$") as caught:
        service.decrypt(encoded)
    assert caught.value.reason is SamlFailureReason.CONFIGURATION_UNAVAILABLE
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    response = enabled_client.post(ENDPOINT, json={"saml_response": encoded})
    assert response.status_code == 503
    assert response.json() == {"error": "saml_unavailable"}


@pytest.mark.parametrize(
    ("body", "status", "error"),
    [
        (b'{"secret-value":', 422, "json_invalid"),
        (
            b'{"saml_response":"sensitive-invalid-response"}',
            400,
            "invalid_saml_response",
        ),
    ],
    ids=["malformed-json", "malformed-saml"],
)
def test_expired_material_does_not_override_malformed_request(
    enabled_client: TestClient, tmp_path: Path, body: bytes, status: int, error: str
) -> None:
    bundle = make_bundle(tmp_path)
    service = SamlService(bundle.config)
    service.material = replace(
        service.material, valid_until=datetime.now(UTC) - timedelta(seconds=1)
    )
    app = cast(FastAPI, enabled_client.app)
    app.dependency_overrides[get_saml_service] = lambda: service
    response = enabled_client.post(
        ENDPOINT, content=body, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == status
    if status == 422:
        (detail,) = response.json()["detail"]
        assert detail["type"] == error
    else:
        assert response.json() == {"error": error}
