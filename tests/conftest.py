import os
from collections.abc import Generator

import gfmodules.logging as gflog
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from gfmodules.logging.testing import reset_for_tests

from app.config import (
    Config,
    ConfigApp,
    ConfigLogging,
    ConfigUvicorn,
    reset_config,
    set_config,
)
from app.logging.events import Log


@pytest.fixture(autouse=True)
def test_config(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    # A test that resets the cache must not fall back to the local app.conf.
    monkeypatch.setenv("FASTAPI_CONFIG_PATH", os.devnull)
    set_config(
        Config(
            app=ConfigApp(),
            logging=ConfigLogging(application_id="prs-saml", access_logs=True),
            uvicorn=ConfigUvicorn(swagger_enabled=True, reload=False),
        )
    )
    try:
        yield
    finally:
        reset_config()


@pytest.fixture(autouse=True)
def logging_catalogue() -> Generator[None, None, None]:
    gflog.configure(
        config=ConfigLogging(console_streams=["debug"], access_logs=True),
        # Privacy tests exercise ordinary logging; diagnostic tests opt into DEBUG.
        loglevel="INFO",
        catalogue=Log,
        strict_fields=True,
    )
    try:
        yield
    finally:
        reset_for_tests()


@pytest.fixture
def app() -> Generator[FastAPI, None, None]:
    from app.application import setup_fastapi

    yield setup_fastapi()


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)
