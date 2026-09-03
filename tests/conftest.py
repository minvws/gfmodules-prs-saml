import os
from collections.abc import Generator

os.environ["FASTAPI_CONFIG_PATH"] = "./app.test.conf"

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def app() -> Generator[FastAPI, None, None]:
    from app.application import create_fastapi_app

    yield create_fastapi_app()


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)
