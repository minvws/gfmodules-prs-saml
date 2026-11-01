from typing import NoReturn, cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.models.saml import DecryptRequest
from app.routers.saml import post_decrypt
from app.saml.errors import SamlFailureReason, SamlRejected, SamlUnavailable
from app.saml.service import SamlService


@pytest.mark.parametrize(
    ("error", "status", "body"),
    [
        (
            SamlRejected(SamlFailureReason.INVALID_FORMAT),
            400,
            b'{"error":"invalid_saml_response"}',
        ),
        (
            SamlUnavailable("synthetic unavailable"),
            503,
            b'{"error":"saml_unavailable"}',
        ),
    ],
)
def test_saml_exceptions_are_handled_by_app(
    app: FastAPI, error: Exception, status: int, body: bytes
) -> None:
    @app.get("/saml-error-probe")
    def fail() -> None:
        raise error

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/saml-error-probe")

    assert (response.status_code, response.content) == (status, body)
    assert response.headers["content-type"] == "application/json"


def test_unrelated_value_error_keeps_generic_handler(app: FastAPI) -> None:
    @app.get("/unrelated-error-probe")
    def fail() -> None:
        raise ValueError("synthetic unrelated error")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/unrelated-error-probe")

    assert response.status_code == 500
    assert response.json() == {"error": "Internal server error"}


def test_post_decrypt_raises_sanitized_saml_rejection() -> None:
    class FailingService:
        def decrypt(self, saml_response: str) -> NoReturn:
            raise ValueError(f"synthetic service error: {saml_response}")

    payload = DecryptRequest(saml_response="synthetic input")
    with pytest.raises(SamlRejected, match="^Invalid SAML response$") as error:
        post_decrypt(payload, cast(SamlService, FailingService()))

    assert error.value.reason is SamlFailureReason.UNKNOWN
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
