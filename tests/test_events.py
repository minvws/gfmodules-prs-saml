from gfmodules.logging.testing import (
    assert_catalogue_complete,
    assert_event_overview_current,
)

from app.logging.events import Log


def test_the_catalogue_is_complete_and_its_overview_current() -> None:
    assert_catalogue_complete(Log)
    assert_event_overview_current(Log, "docs/log-events.md")
