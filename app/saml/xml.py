"""XML parsing without external resources or ambiguous identifiers."""

from lxml import etree

NS = {
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xenc": "http://www.w3.org/2001/04/xmlenc#",
    "xenc11": "http://www.w3.org/2009/xmlenc11#",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
}


def parse_xml(data: bytes, max_bytes: int) -> etree._Element:
    if not data or len(data) > max_bytes:
        raise ValueError("Invalid XML")
    parser = etree.XMLParser(
        resolve_entities=False,
        load_dtd=False,
        no_network=True,
        dtd_validation=False,
        recover=False,
        huge_tree=False,
    )
    try:
        root = etree.fromstring(data, parser=parser)
    except (etree.XMLSyntaxError, ValueError):
        raise ValueError("Invalid XML") from None
    if root.getroottree().docinfo.doctype:
        raise ValueError("Invalid XML")
    ids: set[str] = set()
    for element in root.iter():
        if not isinstance(element.tag, str):
            continue
        if element.tag.startswith("{http://www.w3.org/2001/XInclude}"):
            raise ValueError("Invalid XML")
        for name, value in element.attrib.items():
            if name in ("ID", "Id", "id", "{http://www.w3.org/XML/1998/namespace}id"):
                if not value or value in ids:
                    raise ValueError("Invalid XML")
                ids.add(value)
    return root


def one(element: etree._Element, path: str) -> etree._Element:
    matches = element.findall(path, NS)
    if len(matches) != 1:
        raise ValueError("Invalid SAML structure")
    return matches[0]


def simple_text(element: etree._Element) -> str:
    # Comments disappear during signature canonicalization but can split lxml's
    # .text from a tail. Reject mixed content rather than truncate signed claims.
    value: str | None = element.text
    if len(element) or value is None or not value.strip():
        raise ValueError("Invalid SAML structure")
    return value.strip()


def text(element: etree._Element, path: str) -> str:
    return simple_text(one(element, path))
