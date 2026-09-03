import json
import logging
import signal
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from logging.config import dictConfig
from pathlib import Path
from types import TracebackType
from typing import Any

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.config import get_config
from app.logging.config_builder import LogConfigBuilder
from app.logging.events import (
    SYS_APP_CRASHED,
    SYS_APP_STARTED,
    SYS_APP_STOPPED,
    SYS_UNHANDLED_EXCEPTION,
    log_event,
)
from app.logging.middleware import RequestContextMiddleware, restore_request_context
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
    _install_excepthook()
    _install_signal_handlers()


def create_fastapi_app() -> FastAPI:
    application_init()
    try:
        fastapi = setup_fastapi()
    except Exception as exc:
        log_event(
            logger,
            SYS_APP_CRASHED,
            "Application crashed during startup",
            exc_info=exc,
            component=COMPONENT,
            shutdown_reason="crash",
            last_exception_type=type(exc).__name__,
        )
        raise
    _emit_app_started()

    return fastapi


_shutdown_reason: str = "graceful"


def _read_version() -> str:
    path = Path(__file__).parent.parent / "version.json"
    try:
        with open(path, "r") as fh:
            data = json.load(fh)
            return str(data.get("version", "unknown"))
    except (FileNotFoundError, json.JSONDecodeError):
        return "unknown"


def _emit_app_started() -> None:
    config = get_config()
    log_event(
        logger,
        SYS_APP_STARTED,
        "Application started",
        component=COMPONENT,
        version=_read_version(),
        environment=config.app.environment,
    )


def _install_excepthook() -> None:
    """Route uncaught exceptions through our own logging so the crash is
    recorded as a PRS-SYS-002 event before the process dies."""

    def _hook(
        exc_type: type[BaseException],
        exc_value: BaseException,
        exc_tb: TracebackType | None,
    ) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return
        global _shutdown_reason
        _shutdown_reason = "crash"
        log_event(
            logger,
            SYS_APP_CRASHED,
            "Application crashed: uncaught exception",
            exc_info=(exc_type, exc_value, exc_tb),
            component=COMPONENT,
            shutdown_reason="crash",
            last_exception_type=exc_type.__name__,
        )

    sys.excepthook = _hook


def _install_signal_handlers() -> None:
    """Record the shutdown reason then delegate to the previously-installed
    handler (typically uvicorn's), so we don't disrupt graceful shutdown."""

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            previous = signal.getsignal(sig)
        except (ValueError, OSError):
            continue

        def _make_handler(signum: int, prev: Any) -> Any:
            def _handler(s: int, frame: Any) -> None:
                global _shutdown_reason
                _shutdown_reason = f"signal:{signal.Signals(signum).name}"
                if callable(prev):
                    prev(s, frame)

            return _handler

        try:
            signal.signal(sig, _make_handler(sig, previous))
        except (ValueError, OSError):
            pass


@asynccontextmanager
async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
    try:
        yield
    finally:
        if _shutdown_reason != "crash":
            log_event(
                logger,
                SYS_APP_STOPPED,
                "Application stopped",
                component=COMPONENT,
                shutdown_reason=_shutdown_reason,
            )


@restore_request_context
def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    log_event(
        logger,
        SYS_UNHANDLED_EXCEPTION,
        "Unhandled exception",
        exc_info=exc,
        exception_type=type(exc).__name__,
        endpoint=request.url.path,
        method=request.method,
    )
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


def setup_logging() -> None:
    config = get_config()
    loglevel = config.app.loglevel.upper()
    if loglevel not in logging.getLevelNamesMapping():
        raise ValueError(f"Invalid loglevel {loglevel}")

    log_config = LogConfigBuilder(
        loglevel=loglevel,
        logging_config=config.logging,
    ).build()
    dictConfig(log_config)


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
    )
    fastapi.add_exception_handler(Exception, _unhandled_exception_handler)

    for router in [default_router, health_router, saml_router]:
        fastapi.include_router(router)

    return fastapi
