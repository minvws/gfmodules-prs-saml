from typing import Any

from app.config import ConfigLogging
from app.logging.filters import (
    AppFilter,
    LoggingStreams,
    PublicInspectFilter,
    SiemFilter,
)
from app.logging.formatter import JsonFormatter, PlainTextFormatter


class LogConfigBuilder:
    def __init__(
        self,
        logging_config: ConfigLogging,
        loglevel: str = "INFO",
    ) -> None:
        self.loglevel = loglevel
        self.logging_config = logging_config

    def _syslog_handler(
        self, path: str, formatter: str = "json", filters: list[str] | None = None
    ) -> dict[str, Any]:
        host, port_str = path.rsplit(":", 1)
        cfg: dict[str, Any] = {
            "class": "logging.handlers.SysLogHandler",
            "address": (host, int(port_str)),
            "formatter": formatter,
        }
        if filters:
            cfg["filters"] = filters
        return cfg

    def build(self) -> dict[str, Any]:
        if self.logging_config.debug_logs_in_console:
            console: dict[str, Any] = {
                "class": "logging.StreamHandler",
                "level": "DEBUG",
                "formatter": "plain",
                "stream": "ext://sys.stdout",
            }
        else:
            console = {
                "class": "logging.StreamHandler",
                "level": self.loglevel,
                "formatter": "json_traces"
                if self.logging_config.include_traces
                else "json",
                "filters": ["app_filter"],
                "stream": "ext://sys.stdout",
            }

        conf: dict[str, Any] = {
            "version": 1,
            "disable_existing_loggers": False,
            "filters": {
                "app_filter": {"()": AppFilter},
                "siem_filter": {"()": SiemFilter},
                "public_inspect_filter": {"()": PublicInspectFilter},
            },
            "formatters": {
                "json": {
                    "()": JsonFormatter,
                    "include_traces": False,
                },
                "json_traces": {
                    "()": JsonFormatter,
                    "include_traces": True,
                },
                # Stream-stamped formatters: all streams are multiplexed over a
                # single syslog channel, and stream_id lets the log server tell
                # them apart. json_app/json_siem are additionally stream-bound so
                # the per-event field allow-list restricts each stream to the data
                # the spec assigns to it. APP == "stroom 2", SIEM == "stroom 3".
                "json_app": {
                    "()": JsonFormatter,
                    "include_traces": False,
                    "stream_id": "app",
                    "stream": LoggingStreams.APP,
                },
                "json_siem": {
                    "()": JsonFormatter,
                    "include_traces": False,
                    "stream_id": "siem",
                    "stream": LoggingStreams.SIEM,
                },
                "json_public_inspect": {
                    "()": JsonFormatter,
                    "include_traces": False,
                    "stream_id": "public_inspect",
                },
                "json_debug": {
                    "()": JsonFormatter,
                    "include_traces": True,
                    "stream_id": "debug",
                },
                "plain": {
                    "()": PlainTextFormatter,
                },
            },
            "handlers": {
                "console": console,
            },
            "loggers": {
                "app": {
                    "handlers": ["console"],
                    "level": self.loglevel,
                    "propagate": False,
                },
                "uvicorn": {
                    "handlers": ["console"],
                    "level": self.loglevel,
                    "propagate": False,
                },
                "uvicorn.error": {
                    "handlers": ["console"],
                    "level": self.loglevel,
                    "propagate": False,
                },
                # uvicorn.access is disabled as RequestContextMiddleware handles access logs
                "uvicorn.access": {
                    "handlers": [],
                    "level": "CRITICAL",
                    "propagate": False,
                },
                # inject logs every binding at DEBUG including full instance reprs,
                # which would expose configuration secrets
                "inject": {
                    "handlers": ["console"],
                    "level": "INFO",
                    "propagate": False,
                },
            },
            "root": {"handlers": ["console"], "level": self.loglevel},
        }

        # Stamp every JSON record with the configured application id so the
        # log server can tell apart applications sharing the syslog channel.
        if self.logging_config.application_id:
            for formatter in conf["formatters"].values():
                if formatter["()"] is JsonFormatter:
                    formatter["application_id"] = self.logging_config.application_id

        self._add_log_handlers(conf)

        return conf

    def _add_log_handlers(self, conf: dict[str, Any]) -> None:
        # All streams share one syslog channel; each handler stamps its records
        # with a stream_id via its formatter so the log server can split them.
        path = self.logging_config.syslog_path
        if not path:
            return

        app_logger_handlers = conf["loggers"]["app"]["handlers"]
        uvicorn_handlers = conf["loggers"]["uvicorn"]["handlers"]
        uvicorn_error_handlers = conf["loggers"]["uvicorn.error"]["handlers"]

        conf["handlers"]["syslog_app"] = self._syslog_handler(
            path, formatter="json_app", filters=["app_filter"]
        )
        app_logger_handlers.append("syslog_app")
        uvicorn_handlers.append("syslog_app")
        uvicorn_error_handlers.append("syslog_app")

        conf["handlers"]["syslog_siem"] = self._syslog_handler(
            path, formatter="json_siem", filters=["siem_filter"]
        )
        app_logger_handlers.append("syslog_siem")

        conf["handlers"]["syslog_public_inspect"] = self._syslog_handler(
            path, formatter="json_public_inspect", filters=["public_inspect_filter"]
        )
        app_logger_handlers.append("syslog_public_inspect")

        conf["handlers"]["syslog_debug"] = self._syslog_handler(
            path, formatter="json_debug"
        )
        app_logger_handlers.append("syslog_debug")
        uvicorn_handlers.append("syslog_debug")
        uvicorn_error_handlers.append("syslog_debug")
        conf["root"]["handlers"].append("syslog_debug")
