import pytest
from fastapi.testclient import TestClient

ENDPOINT = "/saml/decrypt"


def test_saml_decrypt_echoes_object(client: TestClient) -> None:
    payload = {
        "samlResponse": "PHNhbWxwOlJlc3BvbnNlPi4uLjwvc2FtbHA6UmVzcG9uc2U+",
        "recipientOrganization": "oin:00000099000000001000",
        "domain": "vad",
    }
    response = client.post(ENDPOINT, json=payload)
    assert response.status_code == 200
    assert response.json() == payload


@pytest.mark.parametrize(
    "payload",
    [
        "arbitrary string",
        ["a", "list", 1],
        {"nested": {"structure": [True, None, 1.5]}},
        42,
    ],
)
def test_saml_decrypt_echoes_arbitrary_json(
    client: TestClient, payload: object
) -> None:
    response = client.post(ENDPOINT, json=payload)
    assert response.status_code == 200
    assert response.json() == payload
