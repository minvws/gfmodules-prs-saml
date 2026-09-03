import logging
import re
import time
import uuid
from collections.abc import Callable, Generator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import wraps
from typing import TypeVar

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from app.logging.context import (
    CLIENT_TRACE_ID_HEADER,
    CORRELATION_ID_HEADER,
    REQUEST_ID_HEADER,
    UNSET,
    client_trace_id_var,
    correlation_id_var,
    endpoint_var,
    ip_var,
    method_var,
    request_id_var,
)
from app.logging.events import ACCESS_REQUEST, SYS_MISSING_CORRELATION_ID, log_event

_SAFE_HEADER_VALUE = re.compile(r"[^a-zA-Z0-9\-_]")
_access_logger = logging.getLogger("app.access")
_logger = logging.getLogger(__name__)

_REQUEST_CONTEXT_STATE_KEY = "request_context"


def _sanitize(value: str) -> str:
    return _SAFE_HEADER_VALUE.sub("", value)[:64] or UNSET


@dataclass(frozen=True)
class RequestContext:
    request_id: str
    ip: str
    client_trace_id: str
    correlation_id: str
    endpoint: str
    method: str

    @classmethod
    def from_request(cls, request: Request) -> "RequestContext":
        return cls(
            request_id=str(uuid.uuid4()),
            ip=request.client.host if request.client else UNSET,
            client_trace_id=_sanitize(
                request.headers.get(CLIENT_TRACE_ID_HEADER, UNSET)
            ),
            correlation_id=_sanitize(request.headers.get(CORRELATION_ID_HEADER, UNSET)),
            endpoint=request.url.path,
            method=request.method,
        )

    def apply_to(self, response: Response) -> None:
        response.headers[REQUEST_ID_HEADER] = self.request_id
        if self.client_trace_id != UNSET:
            response.headers[CLIENT_TRACE_ID_HEADER] = self.client_trace_id
        if self.correlation_id != UNSET:
            response.headers[CORRELATION_ID_HEADER] = self.correlation_id


_CONTEXT_VARS: tuple[tuple[str, ContextVar[str]], ...] = (
    ("request_id", request_id_var),
    ("ip", ip_var),
    ("client_trace_id", client_trace_id_var),
    ("correlation_id", correlation_id_var),
    ("endpoint", endpoint_var),
    ("method", method_var),
)


@contextmanager
def _bind(context: RequestContext) -> Generator[None]:
    tokens = [(var, var.set(getattr(context, name))) for name, var in _CONTEXT_VARS]
    try:
        yield
    finally:
        for var, token in reversed(tokens):
            var.reset(token)


_ResponseT = TypeVar("_ResponseT", bound=Response)


def restore_request_context(
    handler: Callable[[Request, Exception], _ResponseT],
) -> Callable[[Request, Exception], _ResponseT]:
    @wraps(handler)
    def wrapper(request: Request, exc: Exception) -> _ResponseT:
        context: RequestContext | None = getattr(
            request.state, _REQUEST_CONTEXT_STATE_KEY, None
        )
        if context is None:
            return handler(request, exc)

        with _bind(context):
            response = handler(request, exc)
            context.apply_to(response)
            return response

    return wrapper


class RequestContextMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, correlation_id_expected: bool = False) -> None:
        super().__init__(app)
        self.correlation_id_expected = correlation_id_expected

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        context = RequestContext.from_request(request)
        setattr(request.state, _REQUEST_CONTEXT_STATE_KEY, context)

        response: Response | None = None
        start = time.perf_counter()
        with _bind(context):
            if self.correlation_id_expected and context.correlation_id == UNSET:
                log_event(
                    _logger,
                    SYS_MISSING_CORRELATION_ID,
                    f"Request arrived without {CORRELATION_ID_HEADER}",
                    endpoint=context.endpoint,
                    method=context.method,
                )
            try:
                response = await call_next(request)
                context.apply_to(response)
                return response
            finally:
                duration_ms = round((time.perf_counter() - start) * 1000)
                # endpoint and method are attached automatically from the request context.
                log_event(
                    _access_logger,
                    ACCESS_REQUEST,
                    "access",
                    status_code=response.status_code if response is not None else None,
                    duration_ms=duration_ms,
                )
