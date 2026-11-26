"""XML parsing without external resources or ambiguous identifiers."""

from lxml import etree
from saml2 import md, saml, samlp, xmldsig, xmlenc
from saml2.schema import soapenv

from app.saml.errors import debug_active_exception

NS: dict[str, str] = {
    "saml": saml.NAMESPACE,
    "samlp": samlp.NAMESPACE,
    "ds": xmldsig.NAMESPACE,
    "xenc": xmlenc.NAMESPACE,
    "xenc11": "http://www.w3.org/2009/xmlenc11#",
    "md": md.NAMESPACE,
}


def parse_xml(data: bytes) -> etree._Element:
    if not data:
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
        debug_active_exception()
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


def qualified_tag(name: str) -> str:
    prefix, local_name = name.split(":", 1)
    return str(etree.QName(NS[prefix], local_name))


def child_elements(element: etree._Element) -> list[etree._Element]:
    return [child for child in element if isinstance(child.tag, str)]


def optional(element: etree._Element, path: str) -> etree._Element | None:
    matches = element.findall(path, NS)
    if len(matches) > 1:
        raise ValueError("Invalid SAML structure")
    return matches[0] if matches else None


def one(element: etree._Element, path: str) -> etree._Element:
    match = optional(element, path)
    if match is None:
        raise ValueError("Invalid SAML structure")
    return match


def _artifact(root: etree._Element) -> etree._Element:
    artifact_tag = qualified_tag("samlp:ArtifactResponse")
    for namespace in (soapenv.NAMESPACE, "http://www.w3.org/2003/05/soap-envelope"):
        if root.tag == f"{{{namespace}}}Envelope":
            body = one(root, f"./{{{namespace}}}Body")
            children = child_elements(body)
            if len(children) == 1 and children[0].tag == artifact_tag:
                return children[0]
    raise ValueError("Invalid SAML envelope")


def artifact_response_elements(
    root: etree._Element,
) -> tuple[etree._Element, etree._Element, etree._Element]:
    """Select the original artifact, response, and assertion nodes."""
    artifact = _artifact(root)
    response = one(artifact, "./samlp:Response")
    assertion = one(response, "./saml:Assertion")
    if response.findall("./saml:EncryptedAssertion", NS):
        raise ValueError("Unsupported SAML profile")
    return artifact, response, assertion


def simple_text(element: etree._Element) -> str:
    # Comments disappear during signature canonicalization but can split lxml's
    # .text from a tail. Reject mixed content rather than truncate signed claims.
    value: str | None = element.text
    if len(element) or value is None or not value.strip():
        raise ValueError("Invalid SAML structure")
    return value.strip()


def text(element: etree._Element, path: str) -> str:
    return simple_text(one(element, path))
