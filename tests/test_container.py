from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.application import setup_fastapi, setup_logging
from app.config import Config, get_config
from app.saml.service import SamlService
from tests.saml_helpers import make_bundle, message


def test_apps_resolve_independent_saml_services(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first_bundle = make_bundle(tmp_path / "first")
    second_bundle = make_bundle(tmp_path / "second")
    first_config = get_config().model_copy(update={"saml": first_bundle.config})
    second_config = get_config().model_copy(update={"saml": second_bundle.config})

    setup_logging()
    monkeypatch.setattr("app.application.get_config", lambda: first_config)
    first_app = setup_fastapi()
    monkeypatch.setattr("app.application.get_config", lambda: second_config)
    second_app = setup_fastapi()

    first_container = first_app.state.container
    second_container = second_app.state.container
    first_service = first_container.get_instance(SamlService)
    second_service = second_container.get_instance(SamlService)
    assert first_container is not second_container
    assert first_container.get_instance(Config) is first_config
    assert second_container.get_instance(Config) is second_config
    assert first_service is first_container.get_instance(SamlService)
    assert first_service is not second_service
    assert first_service.config is first_bundle.config
    assert second_service.config is second_bundle.config

    endpoint = "/saml/decrypt"
    with (
        TestClient(first_app) as first_client,
        TestClient(second_app) as second_client,
    ):
        first_payload = {"saml_response": message(first_bundle)}
        second_payload = {"saml_response": message(second_bundle)}
        assert first_client.post(endpoint, json=first_payload).status_code == 200
        assert second_client.post(endpoint, json=second_payload).status_code == 200
        assert second_client.post(endpoint, json=first_payload).status_code == 400


def test_disabled_app_binds_no_saml_service(app: FastAPI, client: TestClient) -> None:
    assert app.state.container.get_instance(SamlService) is None
    assert not hasattr(app.state, "saml_service")

    invalid = client.post("/saml/decrypt", json={})
    assert invalid.status_code == 422
    (detail,) = invalid.json()["detail"]
    assert detail["type"] == "missing"
    assert detail["loc"] == ["body", "saml_response"]

    unavailable = client.post("/saml/decrypt", json={"saml_response": "synthetic"})
    assert unavailable.status_code == 503
    assert unavailable.json() == {"error": "saml_unavailable"}
