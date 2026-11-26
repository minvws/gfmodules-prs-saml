"""Translate SAML errors into privacy-preserving HTTP responses."""

import logging

from fastapi import FastAPI, Request
from gfmodules.logging import LoggingStreams
from starlette.responses import Response

from app.saml.errors import (
    SamlDisabled,
    SamlProcessingError,
    SamlRejected,
    SamlUnavailable,
)

logger = logging.getLogger(__name__)

# Do not rely on a JSON renderer or include request data in error responses.
_ERROR_CONTENT = {
    400: b'{"error":"invalid_saml_response"}',
    503: b'{"error":"saml_unavailable"}',
    500: b'{"error":"Internal server error"}',
}


def _handle_saml_error(_request: Request, exc: Exception) -> Response:
    if isinstance(exc, SamlUnavailable):
        status = 503
        if not isinstance(exc, SamlDisabled):
            logger.warning(
                "SAML processing unavailable: %s",
                exc.reason,
                extra={"stream": [LoggingStreams.APP]},
            )
    elif isinstance(exc, SamlRejected):
        status = 400
        logger.warning(
            "SAML response rejected: %s",
            exc.reason,
            extra={"stream": [LoggingStreams.APP]},
        )
    else:
        assert isinstance(exc, SamlProcessingError)
        status = 500
        logger.error("SAML processing failed", extra={"stream": [LoggingStreams.APP]})
    return Response(
        content=_ERROR_CONTENT[status],
        status_code=status,
        media_type="application/json",
    )


def register_saml_error_handlers(app: FastAPI) -> None:
    for error in (SamlRejected, SamlUnavailable, SamlProcessingError):
        app.add_exception_handler(error, _handle_saml_error)
