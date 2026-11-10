import os
from collections.abc import Generator

os.environ["FASTAPI_CONFIG_PATH"] = "./app.test.conf"

import gfmodules.logging as gflog
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from gfmodules.logging import ConfigLogging
from gfmodules.logging.testing import reset_for_tests

from app.logging.events import Log


@pytest.fixture(autouse=True)
def logging_catalogue() -> Generator[None, None, None]:
    gflog.configure(
        config=ConfigLogging(console_streams=["debug"], access_logs=True),
        loglevel="DEBUG",
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
