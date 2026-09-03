import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from app.logging.filters import LoggingStreams

_APP = LoggingStreams.APP
_SIEM = LoggingStreams.SIEM


@dataclass(frozen=True)
class PRSEvent:
    event_id: str
    level: int
    streams: tuple[LoggingStreams, ...]
    # Per-stream allow-list of field names. APP == "stroom 2", SIEM == "stroom 3".
    # When empty, no per-field routing is applied and every field is sent to all
    # streams in ``streams``.
    fields: Mapping[LoggingStreams, tuple[str, ...]] = field(default_factory=dict)


# DigiD SAML exchange events (PRS-SAML), see
# https://github.com/minvws/gfmodules-coordination-private/issues/1037
# PRS-SAML-001 (230400, exchange succeeded) and PRS-SAML-002 (230401, exchange
# failed) are emitted by the pseudoniemendienst, which owns the exchange flow;
# this service owns the decryption/validation events below. They are not
# emitted yet: the current implementation is an echo mock that does not decrypt
# or validate assertions (coordination issue #1088).
SAML_DECRYPT_FAILED = PRSEvent(  # PRS-SAML-003
    "230402",
    logging.ERROR,
    (_APP, _SIEM),
    {
        _APP: ("handelende_oin", "error_reason", "saml_decrypt_key_versie", "endpoint"),
        _SIEM: ("handelende_oin", "error_reason"),
    },
)
SAML_ASSERTION_INVALID = PRSEvent(  # PRS-SAML-004
    "230403",
    logging.WARNING,
    (_APP, _SIEM),
    {
        _APP: ("handelende_oin", "failure_reason", "saml_issuer", "endpoint"),
        _SIEM: ("handelende_oin", "failure_reason", "saml_issuer"),
    },
)

# Health and system events (PRS-HEALTH / PRS-SYS), see
# https://github.com/minvws/gfmodules-coordination-private/issues/1041
HEALTH_UNHEALTHY = PRSEvent(  # PRS-HEALTH-001
    "270400",
    logging.ERROR,
    (_APP, _SIEM),
    {
        _APP: ("component", "status", "error_detail"),
        _SIEM: ("component", "status"),
    },
)
SYS_APP_STARTED = PRSEvent(  # PRS-SYS-001 (APP stream only per spec)
    "270401",
    logging.INFO,
    (_APP,),
    {
        _APP: ("component", "version", "environment"),
    },
)
SYS_APP_STOPPED = PRSEvent(  # PRS-SYS-002 (controlled shutdown)
    "270402",
    logging.INFO,
    (_APP, _SIEM),
    {
        _APP: ("component", "shutdown_reason", "last_exception_type"),
        _SIEM: ("component", "shutdown_reason"),
    },
)
SYS_APP_CRASHED = PRSEvent(  # PRS-SYS-002 (uncontrolled shutdown)
    "270402",
    logging.CRITICAL,
    (_APP, _SIEM),
    {
        _APP: ("component", "shutdown_reason", "last_exception_type"),
        _SIEM: ("component", "shutdown_reason"),
    },
)
SYS_UNHANDLED_EXCEPTION = PRSEvent(  # PRS-SYS-004
    "270404",
    logging.ERROR,
    (_APP, _SIEM),
    {
        _APP: ("exception_type", "endpoint", "method"),
        _SIEM: ("exception_type", "endpoint", "method"),
    },
)
SYS_MISSING_CORRELATION_ID = PRSEvent(  # PRS-SYS-007
    "270407",
    logging.ERROR,
    (_APP, _SIEM),
    {
        _APP: ("endpoint", "method"),
        _SIEM: ("endpoint", "method"),
    },
)

ACCESS_REQUEST = PRSEvent("001000", logging.INFO, (LoggingStreams.APP,))


def log_event(
    logger: logging.Logger,
    event: PRSEvent,
    message: str,
    *,
    exc_info: Any = None,
    **fields: Any,
) -> None:
    extra: dict[str, Any] = {
        "event_id": event.event_id,
        "stream": list(event.streams),
    }
    if event.fields:
        extra["field_streams"] = event.fields
    extra.update(fields)
    logger.log(event.level, message, extra=extra, exc_info=exc_info)
