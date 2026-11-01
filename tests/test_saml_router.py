from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.saml.service import SamlService
from tests.saml_helpers import BSN, LOA, make_bundle, message

ENDPOINT = "/saml/decrypt"


def test_disabled_service_returns_unavailable(client: TestClient) -> None:
    response = client.post(ENDPOINT, json={"samlResponse": "anything"})
    assert response.status_code == 503
    assert response.json() == {"error": "saml_unavailable"}
    assert response.headers["cache-control"] == "no-store"


@pytest.fixture
def enabled_client(client: TestClient, tmp_path: Path) -> TestClient:
    bundle = make_bundle(tmp_path)
    cast(FastAPI, client.app).state.saml_service = SamlService(bundle.config)
    return client


def test_real_signed_and_encrypted_response_is_processed(
    client: TestClient, tmp_path: Path
) -> None:
    bundle = make_bundle(tmp_path)
    cast(FastAPI, client.app).state.saml_service = SamlService(bundle.config)
    response = client.post(
        ENDPOINT,
        json={
            "samlResponse": message(bundle),
            "recipientOrganization": "ignored-by-crypto-service",
            "domain": "vad",
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "personalId": "NL:bsn:" + BSN,
        "authnContextClassRef": LOA,
    }
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    "payload",
    [{}, {"samlResponse": 42}, {"samlResponse": ""}, ["arbitrary"], "secret-value"],
)
def test_invalid_request_does_not_echo_values(
    enabled_client: TestClient, payload: object
) -> None:
    response = enabled_client.post(ENDPOINT, json=payload)
    assert response.status_code == 422
    assert response.json() == {"error": "invalid_request"}


def test_invalid_saml_does_not_leak_input_or_library_error(
    enabled_client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    sensitive = "sensitive-invalid-response"
    response = enabled_client.post(ENDPOINT, json={"samlResponse": sensitive})
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_saml_response"}
    assert sensitive not in response.text
    assert sensitive not in caplog.text


def test_malformed_json_does_not_leak_input(enabled_client: TestClient) -> None:
    response = enabled_client.post(
        ENDPOINT,
        content=b'{"secret-value":',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert response.json() == {"error": "invalid_request"}


def test_oversized_request_is_rejected_before_json_parsing(
    client: TestClient, tmp_path: Path
) -> None:
    bundle = make_bundle(tmp_path)
    bundle.config.max_xml_bytes = 1024
    cast(FastAPI, client.app).state.saml_service = SamlService(bundle.config)
    response = client.post(ENDPOINT, content=b"A" * 100000)
    assert response.status_code == 413
    assert response.json() == {"error": "request_too_large"}


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
    cast(FastAPI, enabled_client.app).state.saml_service = service
    response = enabled_client.post(ENDPOINT, json={"samlResponse": message(bundle)})
    assert response.status_code == 503
    assert response.json() == {"error": "saml_unavailable"}
    assert response.headers["cache-control"] == "no-store"
