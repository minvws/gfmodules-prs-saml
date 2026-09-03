from fastapi.testclient import TestClient


def test_index_shows_banner_and_version(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "PRS-SAML" in response.text or "Version" in response.text


def test_version_json(client: TestClient) -> None:
    response = client.get("/version.json")
    assert response.status_code == 200
    assert "version" in response.json()


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
