import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import gfmodules.logging as gflog
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from gfmodules.logging.middleware import (
    RequestContextMiddleware,
    restore_request_context,
)

from app.config import get_config
from app.events import Log
from app.routers.default import router as default_router
from app.routers.health import router as health_router
from app.routers.saml import router as saml_router

logger = logging.getLogger(__name__)

# Component name carried on the PRS-HEALTH / PRS-SYS audit events.
COMPONENT = "prs-saml"

API_DESCRIPTION = """
The PRS-SAML service is the SAML-ontvanger of the Pseudoniemendienst (PRS): it
processes incoming DigiD SAML responses on behalf of the PRS so that XML/SAML
parsing is isolated from the pseudonym engine.

This is an **internal** service: it is only reachable by the PRS, never by
external clients.

**Current state: echo mock.** The service accepts the SAML exchange payload
from the PRS and returns it unchanged; no parsing, validation, or decryption
is performed yet.
"""

TAGS_METADATA = [
    {
        "name": "Service Information",
        "description": (
            "Public, unauthenticated endpoints reporting the service version and "
            "health status. Useful for load balancers, monitoring, and smoke tests."
        ),
    },
    {
        "name": "Health",
        "description": "Health check for the service and its dependencies.",
    },
    {
        "name": "SAML Services",
        "description": (
            "Process a DigiD SAML response for the PRS. Currently a mock that "
            "echoes the payload."
        ),
    },
]


def get_uvicorn_params() -> dict[str, Any]:
    config = get_config()

    kwargs = {
        "host": config.uvicorn.host,
        "port": config.uvicorn.port,
        "reload": config.uvicorn.reload,
        "reload_delay": config.uvicorn.reload_delay,
        "reload_dirs": config.uvicorn.reload_dirs,
        "factory": True,
    }
    if (
        config.uvicorn.use_ssl
        and config.uvicorn.ssl_base_dir is not None
        and config.uvicorn.ssl_cert_file is not None
        and config.uvicorn.ssl_key_file is not None
    ):
        kwargs["ssl_keyfile"] = (
            config.uvicorn.ssl_base_dir + "/" + config.uvicorn.ssl_key_file
        )
        kwargs["ssl_certfile"] = (
            config.uvicorn.ssl_base_dir + "/" + config.uvicorn.ssl_cert_file
        )
    return kwargs


def run() -> None:
    uvicorn.run("app.application:create_fastapi_app", **get_uvicorn_params())


def application_init() -> None:
    setup_logging()
    gflog.install_excepthook(logger)
    gflog.install_signal_handlers()


def create_fastapi_app() -> FastAPI:
    application_init()
    try:
        return setup_fastapi()
    except Exception as exc:
        gflog.emit(
            logger,
            Log.SYS_APP_CRASHED,
            "Application crashed during startup",
            exc_info=exc,
            fields={
                "shutdown_reason": "crash",
                "last_exception_type": type(exc).__name__,
            },
        )
        raise


def _read_version() -> str:
    path = Path(__file__).parent.parent / "version.json"
    try:
        with open(path, "r") as fh:
            data = json.load(fh)
            return str(data.get("version", "unknown"))
    except (FileNotFoundError, json.JSONDecodeError):
        return "unknown"


@asynccontextmanager
async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
    config = get_config()
    async with gflog.lifespan_logging(
        logger,
        version=_read_version(),
        started_fields={
            "component": COMPONENT,
            "environment": config.app.environment,
        },
    ):
        yield


@restore_request_context
def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    gflog.emit(
        logger,
        Log.SYS_UNHANDLED_EXCEPTION,
        "Unhandled exception",
        exc_info=exc,
        fields={
            "exception_type": type(exc).__name__,
            "endpoint": request.url.path,
            "method": request.method,
        },
    )
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


def setup_logging() -> None:
    config = get_config()
    gflog.configure(
        config=config.logging,
        loglevel=config.app.loglevel,
        catalogue=Log,
    )


def setup_fastapi() -> FastAPI:
    config = get_config()

    fastapi = (
        FastAPI(
            docs_url=config.uvicorn.docs_url,
            redoc_url=config.uvicorn.redoc_url,
            title="PRS-SAML API",
            summary="SAML receiver for the Pseudoniemendienst",
            description=API_DESCRIPTION,
            openapi_tags=TAGS_METADATA,
            root_path=config.uvicorn.root_path,
            lifespan=_lifespan,
        )
        if config.uvicorn.swagger_enabled
        else FastAPI(docs_url=None, redoc_url=None, lifespan=_lifespan)
    )

    fastapi.add_middleware(
        RequestContextMiddleware,
        correlation_id_expected=config.logging.correlation_id_expected,
        trust_forwarded_for=config.logging.trust_forwarded_for,
    )
    fastapi.add_exception_handler(Exception, _unhandled_exception_handler)

    for router in [default_router, health_router, saml_router]:
        fastapi.include_router(router)

    return fastapi
