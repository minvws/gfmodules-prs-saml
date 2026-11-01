import pytest
from lxml import etree

from app.saml import xml
from app.saml.xml import parse_xml
from tests.saml_helpers import SOAP11, SOAP12


def test_parses_xml_bytes() -> None:
    assert parse_xml(b"<root/>").tag == "root"


def test_parses_xml_above_former_application_limit() -> None:
    data = b"<root>" + b" " * 2_097_153 + b"</root>"
    assert parse_xml(data).tag == "root"


def test_libxml_parser_text_limit_remains_enabled() -> None:
    data = b"<root>" + b" " * 10_485_761 + b"</root>"
    with pytest.raises(ValueError, match="^Invalid XML$"):
        parse_xml(data)


@pytest.mark.parametrize(
    "xml",
    [
        b'<!DOCTYPE root [<!ENTITY x "secret">]><root>&x;</root>',
        b'<!DOCTYPE root SYSTEM "file:///etc/passwd"><root/>',
        b'<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd"/></root>',
        b'<root><a ID="same"/><b ID="same"/></root>',
        b'<root><a ID="same"/><b Id="same"/></root>',
        b"<root>",
        b"",
    ],
)
def test_rejects_unsafe_or_invalid_xml(xml: bytes) -> None:
    with pytest.raises(ValueError):
        parse_xml(xml)


def test_qualified_tag() -> None:
    assert (
        xml.qualified_tag("xenc:EncryptedData")
        == "{http://www.w3.org/2001/04/xmlenc#}EncryptedData"
    )


def test_child_elements_ignores_comments_and_processing_instructions() -> None:
    root = parse_xml(b"<r><!-- c --><?pi data?><n/></r>")

    assert xml.child_elements(root) == [root.find("./n")]


def test_optional_requires_at_most_one_match() -> None:
    root = parse_xml(b"<r><nested><leaf/></nested><leaf/></r>")

    assert xml.optional(root, "./absent") is None
    assert xml.optional(root, "./leaf") is root[-1]

    etree.SubElement(root, "leaf")
    with pytest.raises(ValueError, match="^Invalid SAML structure$"):
        xml.optional(root, "./leaf")


@pytest.mark.parametrize(
    "soap_namespace",
    [
        pytest.param(SOAP11, id="soap11"),
        pytest.param(SOAP12, id="soap12"),
    ],
)
def test_artifact_response_elements_preserve_source_nodes(soap_namespace: str) -> None:
    payload = b"""<samlp:ArtifactResponse
        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <samlp:Response>
            <saml:Assertion>
                <saml:Issuer>  synthetic issuer \t </saml:Issuer>
            </saml:Assertion>
        </samlp:Response>
    </samlp:ArtifactResponse>"""
    opening = f'<soap:Envelope xmlns:soap="{soap_namespace}"><soap:Body>'
    root = etree.fromstring(
        opening.encode()
        + b"\n<!-- keep -->\n"
        + payload
        + b"\n<?pi keep?>\n</soap:Body></soap:Envelope>"
    )
    artifact = root[0][1]
    response = artifact[0]
    assertion = response[0]
    before = etree.tostring(root)

    selected = xml.artifact_response_elements(root)

    assert selected[0] is artifact
    assert selected[1] is response
    assert selected[2] is assertion
    assert etree.tostring(root) == before


_RESPONSE = b"<samlp:Response><saml:Assertion/></samlp:Response>"


def _artifact_xml(content: bytes = _RESPONSE) -> bytes:
    return (
        b'<samlp:ArtifactResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
        b' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
        + content
        + b"</samlp:ArtifactResponse>"
    )


def _soap_xml(
    content: bytes,
    *,
    envelope_namespace: str = SOAP11,
    body_namespace: str = SOAP11,
    bodies: int = 1,
) -> bytes:
    body = f'<Body xmlns="{body_namespace}">'.encode() + content + b"</Body>"
    return (
        f'<Envelope xmlns="{envelope_namespace}">'.encode()
        + body * bodies
        + b"</Envelope>"
    )


@pytest.mark.parametrize(
    "document",
    [
        pytest.param(
            _soap_xml(_artifact_xml() + b"<extra/>"), id="extra-soap-body-child"
        ),
        pytest.param(_soap_xml(_artifact_xml(_RESPONSE * 2)), id="duplicate-responses"),
        pytest.param(
            _soap_xml(_artifact_xml(b"<wrapper>" + _RESPONSE + b"</wrapper>")),
            id="nested-response",
        ),
        pytest.param(
            _soap_xml(
                _artifact_xml(
                    b"<samlp:Response><saml:Assertion/><saml:EncryptedAssertion/>"
                    b"</samlp:Response>"
                )
            ),
            id="encrypted-assertion",
        ),
        pytest.param(
            _soap_xml(
                _artifact_xml(),
                envelope_namespace="urn:test:unknown-soap",
                body_namespace="urn:test:unknown-soap",
            ),
            id="unknown-envelope-namespace",
        ),
        pytest.param(
            _soap_xml(_artifact_xml(), body_namespace=SOAP12),
            id="mismatched-body-namespace",
        ),
        pytest.param(_soap_xml(_artifact_xml(), bodies=2), id="duplicate-soap-body"),
        pytest.param(
            _soap_xml(b"<wrapper>" + _artifact_xml() + b"</wrapper>"),
            id="nested-artifact",
        ),
    ],
)
def test_artifact_response_elements_reject_ambiguous_structure(document: bytes) -> None:
    root = etree.fromstring(document)

    with pytest.raises(ValueError):
        xml.artifact_response_elements(root)
