import base64
import copy
from pathlib import Path

import pytest
from lxml import etree

from app.saml.service import SamlService
from app.saml.xml import NS
from tests.saml_helpers import (
    BSN,
    LOA,
    instant,
    make_bundle,
    message,
    sign,
)


def test_verified_message_returns_bsn_and_loa_without_request_ids(
    tmp_path: Path,
) -> None:
    bundle = make_bundle(tmp_path)
    result = SamlService(bundle.config).decrypt(message(bundle))
    assert result.personalId == "NL:bsn:" + BSN
    assert result.authnContextClassRef == LOA


def test_tvs_subject_without_format_and_multiple_services(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)

    def mutate(root: etree._Element) -> None:
        assertion = root.find("./samlp:Response/saml:Assertion", NS)
        name = assertion.find("./saml:Subject/saml:NameID", NS)
        del name.attrib["Format"]
        service = assertion.find(
            "./saml:AttributeStatement/saml:Attribute[@Name='urn:nl-eid-gdi:1.0:ServiceUUID']",
            NS,
        )
        value = etree.Element(etree.QName(NS["saml"], "AttributeValue"))
        value.text = "other-service"
        service.insert(0, value)

    assert (
        SamlService(bundle.config).decrypt(message(bundle, mutate)).personalId
        == "NL:bsn:" + BSN
    )


def test_representation_can_be_enabled(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    bundle.config.allow_representation = True

    def mutate(root: etree._Element) -> None:
        attributes = root.find(
            "./samlp:Response/saml:Assertion/saml:AttributeStatement", NS
        )
        acting = attributes.find(
            "./saml:Attribute[@Name='urn:nl-eid-gdi:1.0:ActingSubjectID']", NS
        )
        legal = copy.deepcopy(acting)
        legal.set("Name", "urn:nl-eid-gdi:1.0:LegalSubjectID")
        legal.find(".//xenc:EncryptedData", NS).set("Id", "_legal_data")
        attributes.append(legal)

    result = SamlService(bundle.config).decrypt(message(bundle, mutate))
    assert result.personalId == "NL:bsn:" + BSN
    assert result.representedPersonalId == "NL:bsn:" + BSN


def test_configured_decryption_key_name(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    bundle.config.decryption_key_name = "registered-key-name"

    def mutate(root: etree._Element) -> None:
        root.find(
            ".//xenc:EncryptedKey/ds:KeyInfo/ds:KeyName", NS
        ).text = "registered-key-name"

    assert (
        SamlService(bundle.config).decrypt(message(bundle, mutate)).personalId
        == "NL:bsn:" + BSN
    )


def test_sample_shaped_soap_and_encrypted_key_references(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)

    def mutate(root: etree._Element) -> None:
        assertion = root.find("./samlp:Response/saml:Assertion", NS)
        del assertion.find("./saml:Subject/saml:NameID", NS).attrib["Format"]
        advice = assertion.find("./saml:Advice", NS)
        etree.SubElement(advice, etree.QName(NS["saml"], "Assertion"), ID="_advice")
        encrypted = assertion.find(".//saml:EncryptedID", NS)
        data = encrypted.find("./xenc:EncryptedData", NS)
        key = encrypted.find("./xenc:EncryptedKey", NS)
        key.set("Id", "_key")
        info = etree.Element(etree.QName(NS["ds"], "KeyInfo"))
        etree.SubElement(
            info,
            etree.QName(NS["ds"], "RetrievalMethod"),
            URI="#_key",
            Type=NS["xenc"] + "EncryptedKey",
        )
        data.insert(1, info)
        references = etree.SubElement(key, etree.QName(NS["xenc"], "ReferenceList"))
        etree.SubElement(
            references, etree.QName(NS["xenc"], "DataReference"), URI="#_encrypted"
        )

    envelope = etree.Element("{http://schemas.xmlsoap.org/soap/envelope/}Envelope")
    body = etree.SubElement(envelope, "{http://schemas.xmlsoap.org/soap/envelope/}Body")
    body.append(etree.fromstring(base64.b64decode(message(bundle, mutate))))
    encoded = base64.b64encode(etree.tostring(envelope)).decode()
    assert SamlService(bundle.config).decrypt(encoded).personalId == "NL:bsn:" + BSN


@pytest.mark.parametrize("subject", ["empty", "wrong_format"])
def test_rejects_invalid_summary_subject(tmp_path: Path, subject: str) -> None:
    bundle = make_bundle(tmp_path)

    def mutate(root: etree._Element) -> None:
        name = root.find("./samlp:Response/saml:Assertion/saml:Subject/saml:NameID", NS)
        if subject == "empty":
            name.text = ""
        else:
            name.set("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")

    with pytest.raises(ValueError):
        SamlService(bundle.config).decrypt(message(bundle, mutate))


@pytest.mark.parametrize(
    "namespace",
    [
        "http://schemas.xmlsoap.org/soap/envelope/",
        "http://www.w3.org/2003/05/soap-envelope",
    ],
)
def test_accepts_soap_envelope(tmp_path: Path, namespace: str) -> None:
    bundle = make_bundle(tmp_path)
    envelope = etree.Element(etree.QName(namespace, "Envelope"))
    body = etree.SubElement(envelope, etree.QName(namespace, "Body"))
    body.append(etree.fromstring(base64.b64decode(message(bundle))))
    result = SamlService(bundle.config).decrypt(
        base64.b64encode(etree.tostring(envelope)).decode()
    )
    assert result.personalId == "NL:bsn:" + BSN


@pytest.mark.parametrize(
    "change",
    [
        "audience",
        "issuer",
        "assertion_issuer",
        "destination",
        "recipient",
        "service",
        "expired",
        "not_yet_valid",
        "expired_bearer",
        "low_loa",
        "unknown_loa",
        "status",
        "response_status",
        "representation",
        "missing_in_response_to",
        "inconsistent_in_response_to",
        "future_issue",
        "missing_conditions",
        "naive_time",
        "overflow_time",
        "multiple_assertions",
        "encrypted_assertion",
        "wrong_version",
        "unsupported_condition",
    ],
)
def test_rejects_signed_invalid_claims(tmp_path: Path, change: str) -> None:
    bundle = make_bundle(tmp_path)

    def mutate(root: etree._Element) -> None:
        response = root.find("./samlp:Response", NS)
        assertion = response.find("./saml:Assertion", NS)
        conditions = assertion.find("./saml:Conditions", NS)
        bearer = assertion.find(
            "./saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData", NS
        )
        if change == "audience":
            conditions.find(
                "./saml:AudienceRestriction/saml:Audience", NS
            ).text = "other"
        elif change == "issuer":
            root.find("./saml:Issuer", NS).text = "other"
        elif change == "assertion_issuer":
            assertion.find("./saml:Issuer", NS).text = "other"
        elif change == "destination":
            response.set("Destination", "https://other.example/acs")
        elif change == "recipient":
            bearer.set("Recipient", "https://other.example/acs")
        elif change == "service":
            assertion.find(
                "./saml:AttributeStatement/saml:Attribute[@Name='urn:nl-eid-gdi:1.0:ServiceUUID']/saml:AttributeValue",
                NS,
            ).text = "other"
        elif change == "expired":
            conditions.set("NotOnOrAfter", instant(-1))
        elif change == "not_yet_valid":
            conditions.set("NotBefore", instant(300))
        elif change == "expired_bearer":
            bearer.set("NotOnOrAfter", instant(-1))
        elif change in ("low_loa", "unknown_loa"):
            assertion.find(
                "./saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef", NS
            ).text = (
                "http://eidas.europa.eu/LoA/low" if change == "low_loa" else "unknown"
            )
        elif change in ("status", "response_status"):
            node = root if change == "status" else response
            node.find("./samlp:Status/samlp:StatusCode", NS).set(
                "Value", "urn:oasis:names:tc:SAML:2.0:status:Responder"
            )
        elif change == "representation":
            etree.SubElement(
                assertion.find("./saml:AttributeStatement", NS),
                etree.QName(NS["saml"], "Attribute"),
                Name="urn:nl-eid-gdi:1.0:LegalSubjectID",
            )
        elif change == "missing_in_response_to":
            del response.attrib["InResponseTo"]
        elif change == "inconsistent_in_response_to":
            bearer.set("InResponseTo", "other")
        elif change == "future_issue":
            root.set("IssueInstant", instant(300))
        elif change == "missing_conditions":
            assertion.remove(conditions)
        elif change == "naive_time":
            conditions.set("NotBefore", "2026-01-01T00:00:00")
        elif change == "overflow_time":
            conditions.set("NotBefore", "0001-01-01T00:00:00+01:00")
        elif change == "multiple_assertions":
            etree.SubElement(
                response, etree.QName(NS["saml"], "Assertion"), ID="_other"
            )
        elif change == "encrypted_assertion":
            etree.SubElement(response, etree.QName(NS["saml"], "EncryptedAssertion"))
        elif change == "wrong_version":
            assertion.set("Version", "1.0")
        elif change == "unsupported_condition":
            etree.SubElement(conditions, etree.QName(NS["saml"], "ProxyRestriction"))

    with pytest.raises(ValueError):
        SamlService(bundle.config).decrypt(message(bundle, mutate))


@pytest.mark.parametrize(
    "change",
    [
        "missing_assertion_signature",
        "invalid_assertion_signature",
        "invalid_outer_signature",
    ],
)
def test_requires_every_signature(tmp_path: Path, change: str) -> None:
    bundle = make_bundle(tmp_path)
    root = etree.fromstring(base64.b64decode(message(bundle)))
    assertion = root.find("./samlp:Response/saml:Assertion", NS)
    if change == "missing_assertion_signature":
        assertion.remove(assertion.find("./ds:Signature", NS))
    else:
        parent = root if change == "invalid_outer_signature" else assertion
        parent.find("./saml:Issuer", NS).text = "tampered"
    if change != "invalid_outer_signature":
        root.remove(root.find("./ds:Signature", NS))
        sign(root, bundle)
    with pytest.raises(ValueError):
        SamlService(bundle.config).decrypt(
            base64.b64encode(etree.tostring(root)).decode()
        )


def test_advice_does_not_control_identity_or_loa(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)

    def mutate(root: etree._Element) -> None:
        advice = root.find("./samlp:Response/saml:Assertion/saml:Advice", NS)
        etree.SubElement(
            advice, etree.QName(NS["saml"], "Assertion"), ID="_advice"
        ).append(etree.fromstring(f'<ds:Signature xmlns:ds="{NS["ds"]}"/>'.encode()))

    assert (
        SamlService(bundle.config).decrypt(message(bundle, mutate)).personalId
        == "NL:bsn:" + BSN
    )


def test_audience_is_not_taken_from_decryption_entity(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    bundle.config.audience = bundle.config.entity_id
    with pytest.raises(ValueError):
        SamlService(bundle.config).decrypt(message(bundle))


@pytest.mark.parametrize("value", ["not base64", "", "PHJvb3QvPg=="])
def test_rejects_invalid_input(tmp_path: Path, value: str) -> None:
    with pytest.raises(ValueError):
        SamlService(make_bundle(tmp_path).config).decrypt(value)


@pytest.mark.parametrize(
    "legacy_loa",
    [
        "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract",
        "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI",
    ],
)
def test_summary_requires_eid_loa_uri(tmp_path: Path, legacy_loa: str) -> None:
    bundle = make_bundle(tmp_path)

    def mutate(root: etree._Element) -> None:
        root.find(
            "./samlp:Response/saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef",
            NS,
        ).text = legacy_loa

    with pytest.raises(ValueError):
        SamlService(bundle.config).decrypt(message(bundle, mutate))


def test_basic_loa_is_distinct_from_eidas_low(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    bundle.config.minimum_loa = "http://eID.logius.nl/LoA/basic"

    def mutate(root: etree._Element) -> None:
        root.find(
            "./samlp:Response/saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef",
            NS,
        ).text = bundle.config.minimum_loa

    result = SamlService(bundle.config).decrypt(message(bundle, mutate))
    assert result.authnContextClassRef == bundle.config.minimum_loa


@pytest.mark.parametrize(
    "claim,path",
    [
        (
            "audience",
            "./samlp:Response/saml:Assertion/saml:Conditions/saml:AudienceRestriction/saml:Audience",
        ),
        (
            "loa",
            "./samlp:Response/saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef",
        ),
        ("issuer", "./saml:Issuer"),
        (
            "service",
            "./samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name='urn:nl-eid-gdi:1.0:ServiceUUID']/saml:AttributeValue",
        ),
    ],
)
def test_comments_cannot_truncate_signed_claims(
    tmp_path: Path, claim: str, path: str
) -> None:
    bundle = make_bundle(tmp_path)

    def mutate(root: etree._Element) -> None:
        node = root.find(path, NS)
        node.text += "-wrong"

    # Sign an unacceptable claim, then split it with a comment. Exclusive c14n
    # excludes comments, preserving BOTH signatures without knowing either key.
    root = etree.fromstring(base64.b64decode(message(bundle, mutate)))
    node = root.find(path, NS)
    node.text = node.text.removesuffix("-wrong")
    comment = etree.Comment("unsigned comment insertion")
    comment.tail = "-wrong"
    node.append(comment)
    with pytest.raises(ValueError):
        SamlService(bundle.config).decrypt(
            base64.b64encode(etree.tostring(root)).decode()
        )
