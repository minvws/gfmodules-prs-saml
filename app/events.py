import logging

from gfmodules.logging import EventCatalogue, LogEvent, LoggingStreams

_APP = LoggingStreams.APP
_SIEM = LoggingStreams.SIEM


class Log(EventCatalogue):

    SYS_APP_STARTED = LogEvent(  # PRS-SYS-001 (APP stream only per spec)
        "270401",
        logging.INFO,
        (_APP,),
        {_APP: ("component", "version", "environment", "config_path")},
    )
    SYS_APP_STOPPED = LogEvent(  # PRS-SYS-002 (controlled shutdown)
        "270402",
        logging.INFO,
        (_APP, _SIEM),
        {
            _APP: ("shutdown_reason", "last_exception_type"),
            _SIEM: ("shutdown_reason",),
        },
    )
    SYS_APP_CRASHED = LogEvent(  # PRS-SYS-002 (uncontrolled shutdown)
        "270402",
        logging.CRITICAL,
        (_APP, _SIEM),
        {
            _APP: ("shutdown_reason", "last_exception_type"),
            _SIEM: ("shutdown_reason",),
        },
    )
    SYS_UNHANDLED_EXCEPTION = LogEvent(  # PRS-SYS-004
        "270404",
        logging.ERROR,
        (_APP, _SIEM),
        {
            _APP: ("exception_type", "endpoint", "method"),
            _SIEM: ("exception_type", "endpoint", "method"),
        },
    )
    SYS_MISSING_CORRELATION_ID = LogEvent(  # PRS-SYS-007
        "270407",
        logging.ERROR,
        (_APP, _SIEM),
        {
            _APP: ("endpoint", "method"),
            _SIEM: ("endpoint", "method"),
        },
    )
    ACCESS_REQUEST = LogEvent("001000", logging.INFO, (_APP,))

