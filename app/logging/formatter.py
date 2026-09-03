import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

from app.logging.context import (
    UNSET,
    client_trace_id_var,
    correlation_id_var,
    endpoint_var,
    ip_var,
    method_var,
    request_id_var,
)
from app.logging.filters import LoggingStreams

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

_BUILTIN_LOGRECORD_ATTRS: frozenset[str] = frozenset(
    logging.LogRecord(
        name="", level=0, pathname="", lineno=0, msg="", args=(), exc_info=None
    ).__dict__.keys()
) | {"message", "asctime", "event_id", "stream", "field_streams"}

# Correlation metadata that is always retained, regardless of per-stream field routing.
_ALWAYS_KEEP_FIELDS: frozenset[str] = frozenset(
    {"request_id", "ip", "client_trace_id", "correlation_id"}
)


def _route_fields(
    record: logging.LogRecord,
    stream: LoggingStreams | None,
    data: dict[str, Any],
) -> dict[str, Any]:
    """Restrict ``data`` to the fields allowed for ``stream`` by the event.

    When the formatter is not bound to a stream (console/debug), or the event
    carries no per-stream routing, every field is kept. Correlation metadata is
    always retained so records remain traceable across streams.
    """
    field_streams: dict[LoggingStreams, tuple[str, ...]] | None = getattr(
        record, "field_streams", None
    )
    if stream is None or not field_streams:
        return data
    allowed = set(field_streams.get(stream, ())) | _ALWAYS_KEEP_FIELDS
    return {key: value for key, value in data.items() if key in allowed}


def _sanitize_message(value: str) -> str:
    return _CONTROL_CHARS.sub("", value)


def _collect_context() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, var in (
        ("request_id", request_id_var),
        ("ip", ip_var),
        ("client_trace_id", client_trace_id_var),
        ("correlation_id", correlation_id_var),
        ("endpoint", endpoint_var),
        ("method", method_var),
    ):
        value = var.get()
        if value != UNSET:
            out[key] = value
    return out


def _collect_extras(record: logging.LogRecord) -> dict[str, Any]:
    return {
        k: v for k, v in record.__dict__.items() if k not in _BUILTIN_LOGRECORD_ATTRS
    }


class JsonFormatter(logging.Formatter):
    """Structured JSON formatter for the debug-json view.

    All streams share a single syslog channel; ``stream_id`` tells the log
    server which stream (app, siem, public_inspect, debug) a record belongs
    to, and ``application_id`` which application emitted it.

    Example output:
        {
            "application_id": "pseudoniemendienst",
            "stream_id": "app",
            "event_id": "100601",
            "timestamp": "2026-04-23T10:11:12Z",
            "level": "INFO",
            "event_description": "Application started",
            "source": "app.application:123",
            "message": {
                "version": "...",
                "environment": "...",
                "request_id": "...",
                ...
            }
        }
    """

    def __init__(
        self,
        include_traces: bool = True,
        stream: LoggingStreams | None = None,
        stream_id: str | None = None,
        application_id: str | None = None,
    ) -> None:
        super().__init__()
        self.include_traces = include_traces
        self.stream = stream
        self.stream_id = stream_id
        self.application_id = application_id

    def format(self, record: logging.LogRecord) -> str:
        message: dict[str, Any] = {}

        if record.exc_info and self.include_traces:
            message["exception"] = self.formatException(record.exc_info)
        if record.stack_info and self.include_traces:
            message["stack_info"] = self.formatStack(record.stack_info)

        data = {**_collect_context(), **_collect_extras(record)}
        message.update(_route_fields(record, self.stream, data))

        log_record: dict[str, Any] = {
            "event_id": getattr(record, "event_id", None),
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "event_description": _sanitize_message(record.getMessage()),
            "source": f"{record.module}:{record.lineno}",
        }
        if self.application_id is not None:
            log_record["application_id"] = self.application_id
        if self.stream_id is not None:
            log_record["stream_id"] = self.stream_id
        log_record["message"] = message

        return json.dumps(log_record, default=str)


class PlainTextFormatter(logging.Formatter):
    """Human-readable formatter for the debug-stdout view.

    Example output:
        2026-04-23T10:11:12Z INFO app.application [100601] Application started version=...
    """

    def __init__(self, stream: LoggingStreams | None = None) -> None:
        super().__init__()
        self.stream = stream

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        event_id = getattr(record, "event_id", None) or "-"
        base = (
            f"{timestamp} {record.levelname:<8} {record.name} "
            f"[{event_id}] {_sanitize_message(record.getMessage())}"
        )

        data = {**_collect_context(), **_collect_extras(record)}
        pairs = [
            f"{key}={value}"
            for key, value in _route_fields(record, self.stream, data).items()
        ]

        out = base if not pairs else f"{base} {' '.join(pairs)}"

        if record.exc_info:
            out = f"{out}\n{self.formatException(record.exc_info)}"
        return out
