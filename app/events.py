from gfmodules.logging import DefaultEventCatalogue

_Base = DefaultEventCatalogue


class Log(_Base):
    SYS_APP_STARTED = _Base.SYS_APP_STARTED.with_id("270401")  # PRS-SYS-001 (APP stream only per spec)
    SYS_APP_STOPPED = _Base.SYS_APP_STOPPED.with_id("270402")  # PRS-SYS-002 (controlled shutdown)
    SYS_APP_CRASHED = _Base.SYS_APP_CRASHED.with_id("270402")  # PRS-SYS-002 (uncontrolled shutdown)
    SYS_UNHANDLED_EXCEPTION = _Base.SYS_UNHANDLED_EXCEPTION.with_id("270404")  # PRS-SYS-004
    SYS_MISSING_CORRELATION_ID = _Base.SYS_MISSING_CORRELATION_ID.with_id("270407")  # PRS-SYS-007
