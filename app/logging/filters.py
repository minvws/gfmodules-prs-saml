import logging
from enum import Enum

_LOGGER_ACCESS = "app.access"
_UVICORN_LOGGERS = {"uvicorn", "uvicorn.error"}


class LoggingStreams(Enum):
    PUBLIC_INSPECT = 1
    APP = 2
    SIEM = 3


class AppFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if LoggingStreams.APP in getattr(record, "stream", []):
            return True
        return record.name in _UVICORN_LOGGERS or record.name == _LOGGER_ACCESS


class PublicInspectFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return LoggingStreams.PUBLIC_INSPECT in getattr(record, "stream", [])


class SiemFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return LoggingStreams.SIEM in getattr(record, "stream", [])
