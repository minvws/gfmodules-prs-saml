"""Privacy-preserving SAML errors and DEBUG diagnostics."""

import logging
import sys
from enum import StrEnum
from typing import NoReturn

from gfmodules.logging import LoggingStreams

logger = logging.getLogger(__name__)


class SamlFailureReason(StrEnum):
    INVALID_FORMAT = "invalid_format"
    SIGNATURE_FAILED = "signature_failed"
    INVALID_ISSUER = "invalid_issuer"
    INVALID_CONDITIONS_OR_AUDIENCE = "invalid_conditions_or_audience"
    VALIDATION_FAILED = "validation_failed"
    DECRYPTION_FAILED = "decryption_failed"
    CONFIGURATION_UNAVAILABLE = "configuration_unavailable"
    UNKNOWN = "unknown"


class SamlRejected(ValueError):
    """A rejected response with an input-independent diagnostic reason."""

    def __init__(
        self, reason: SamlFailureReason, message: str = "Invalid SAML response"
    ) -> None:
        super().__init__(message)
        self.reason = reason


class SamlUnavailable(ValueError):
    """Previously loaded trust/key material is no longer usable."""

    reason = SamlFailureReason.CONFIGURATION_UNAVAILABLE


class SamlDisabled(SamlUnavailable):
    """No SAML service is configured."""


class SamlProcessingError(Exception):
    """An unexpected SAML failure with no original exception details."""


def debug_active_exception() -> None:
    """Log raw active exceptions only at DEBUG level."""
    if logger.isEnabledFor(logging.DEBUG) and sys.exc_info()[0] is not None:
        # This helper is called while the caller is handling the exception.
        logger.debug(
            "SAML exception",
            exc_info=True,  # noqa: LOG014
            extra={"stream": [LoggingStreams.APP]},
        )


def raise_sanitized(error: Exception) -> NoReturn:
    """Suppress and detach the active exception, including an ambient context."""
    debug_active_exception()
    try:
        raise error from None
    finally:
        error.__context__ = None


def raise_sanitized_unavailable() -> NoReturn:
    """Preserve unavailability without exposing a library exception's details."""
    raise_sanitized(SamlUnavailable("SAML configuration unavailable"))
