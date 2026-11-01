import pytest

from app.saml.xml import parse_xml


def test_parses_xml_bytes() -> None:
    assert parse_xml(b"<root/>", 100).tag == "root"


@pytest.mark.parametrize(
    "xml",
    [
        b'<!DOCTYPE root [<!ENTITY x "secret">]><root>&x;</root>',
        b'<!DOCTYPE root SYSTEM "file:///etc/passwd"><root/>',
        b'<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd"/></root>',
        b'<root><a ID="same"/><b ID="same"/></root>',
        b'<root><a ID="same"/><b Id="same"/></root>',
        b"<root>",
    ],
)
def test_rejects_unsafe_or_invalid_xml(xml: bytes) -> None:
    with pytest.raises(ValueError):
        parse_xml(xml, 1000)


def test_rejects_oversized_xml() -> None:
    with pytest.raises(ValueError):
        parse_xml(b"<root/>", 5)
