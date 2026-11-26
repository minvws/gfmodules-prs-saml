"""Serialize application xmlsec operations and native diagnostic settings."""

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from threading import Lock

import xmlsec

_LOCK = Lock()
_VALIDATING: ContextVar[bool] = ContextVar("saml_validation", default=False)


def _outside_validation(_record: logging.LogRecord) -> bool:
    return not _VALIDATING.get()


# PySAML2 can log whole messages and identifiers. Do not silence unrelated
# threads or other callers of these library loggers.
for _name in ("saml2.sigver", "saml2.response"):
    logging.getLogger(_name).addFilter(_outside_validation)


@contextmanager
def saml_validation() -> Iterator[None]:
    token = _VALIDATING.set(True)
    try:
        yield
    finally:
        _VALIDATING.reset(token)


@contextmanager
def xmlsec_operation() -> Iterator[None]:
    """Guard app-owned xmlsec calls; unrelated native users remain uncoordinated."""
    with _LOCK:
        xmlsec.enable_debug_trace(False)
        yield
