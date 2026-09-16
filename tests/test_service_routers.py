import builtins
import io
from typing import Any

import pytest
from fastapi.testclient import TestClient

VERSION_JSON_CONTENT = '{"version": "v0.0.0", "git_ref": "0000000000000000000000000"}'


def _mock_open_version_json(monkeypatch: pytest.MonkeyPatch) -> None:
    real_open = builtins.open

    def fake_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if str(file).endswith("version.json"):
            return io.StringIO(VERSION_JSON_CONTENT)
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)


def test_index_shows_banner_and_version(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mock_open_version_json(monkeypatch)

    response = client.get("/")
    assert response.status_code == 200
    assert "PRS-SAML" in response.text or "Version" in response.text


def test_version_json(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_open_version_json(monkeypatch)

    response = client.get("/version.json")
    assert response.status_code == 200
    assert "version" in response.json()


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
