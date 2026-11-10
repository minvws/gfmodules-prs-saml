from gfmodules.logging.testing import assert_event_overview_current

from app.logging.events import Log


def test_the_event_overview_is_current() -> None:
    assert_event_overview_current(Log, "docs/log-events.md")
