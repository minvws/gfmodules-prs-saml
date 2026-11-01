"""Verify a supplied TVS response before releasing its decrypted identity."""

import base64
import binascii
from datetime import UTC, datetime, timedelta

from lxml import etree
from pydantic import BaseModel, ConfigDict

from app.config import ConfigSaml
from app.saml.decryption import decrypt_identifier
from app.saml.signatures import verify_signature
from app.saml.trust import load_material, utc_time
from app.saml.xml import NS, one, parse_xml, simple_text, text

SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
ATTRIBUTE_PREFIX = "urn:nl-eid-gdi:1.0:"
LEVELS = {
    "http://eID.logius.nl/LoA/basic": 0,
    "http://eidas.europa.eu/LoA/low": 1,
    "http://eidas.europa.eu/LoA/substantial": 2,
    "http://eidas.europa.eu/LoA/high": 3,
}


class SamlUnavailable(ValueError):
    """Previously loaded trust/key material is no longer usable."""


class DecryptResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    personalId: str
    authnContextClassRef: str
    representedPersonalId: str | None = None


class SamlService:
    def __init__(self, config: ConfigSaml) -> None:
        if not config.enabled or config.minimum_loa not in LEVELS:
            raise ValueError("Invalid SAML configuration")
        self.config = config
        self.material = load_material(config)

    def decrypt(self, saml_response: str) -> DecryptResult:
        try:
            return self._decrypt(saml_response)
        except SamlUnavailable:
            raise
        except (ValueError, TypeError, binascii.Error, etree.Error):
            raise ValueError("Invalid SAML response") from None

    def _decrypt(self, encoded: str) -> DecryptResult:
        if len(encoded) > 4 * ((self.config.max_xml_bytes + 2) // 3):
            raise ValueError("Invalid SAML response")
        root = parse_xml(
            base64.b64decode(encoded, validate=True), self.config.max_xml_bytes
        )
        artifact = self._artifact(root)
        response = one(artifact, "./samlp:Response")
        assertion = one(response, "./saml:Assertion")
        if response.findall("./saml:EncryptedAssertion", NS):
            raise ValueError("Unsupported SAML profile")
        now = datetime.now(UTC)
        try:
            certificates = self.material.active_certificates(now)
        except ValueError:
            raise SamlUnavailable("SAML configuration expired") from None
        verify_signature(artifact, certificates)
        verify_signature(assertion, certificates)
        if response.findall("./ds:Signature", NS):
            verify_signature(response, certificates)
        for signature in artifact.iter(f"{{{NS['ds']}}}Signature"):
            if signature.getparent() in (artifact, response, assertion):
                continue
            if any(
                parent.tag == f"{{{NS['saml']}}}Advice"
                and parent.getparent() is assertion
                for parent in signature.iterancestors()
            ):
                continue
            raise ValueError("Unexpected SAML signature")
        skew = timedelta(seconds=self.config.clock_skew_seconds)
        for element in (artifact, response, assertion):
            if element.get("Version") != "2.0":
                raise ValueError("Invalid SAML version")
            if utc_time(element.get("IssueInstant")) > now + skew:
                raise ValueError("Invalid SAML issue time")
            if text(element, "./saml:Issuer") != self.material.issuer:
                raise ValueError("Invalid SAML issuer")
        self._status(artifact)
        self._status(response)
        if not artifact.get("InResponseTo") or not response.get("InResponseTo"):
            raise ValueError("Missing SAML correlation")
        if response.get("Destination") != self.config.acs_url:
            raise ValueError("Invalid SAML destination")
        self._conditions(assertion, now, skew)
        self._subject(assertion, response, now, skew)
        statement = one(assertion, "./saml:AuthnStatement")
        if utc_time(statement.get("AuthnInstant")) > now + skew:
            raise ValueError("Invalid SAML authentication time")
        loa = text(statement, "./saml:AuthnContext/saml:AuthnContextClassRef")
        if loa not in LEVELS or LEVELS[loa] < LEVELS[self.config.minimum_loa]:
            raise ValueError("Unsupported SAML authentication level")
        attributes = one(assertion, "./saml:AttributeStatement")
        legal_attributes = attributes.findall(
            f"./saml:Attribute[@Name='{ATTRIBUTE_PREFIX}LegalSubjectID']", NS
        )
        if legal_attributes and not self.config.allow_representation:
            raise ValueError("SAML representation is unsupported")
        if len(legal_attributes) > 1:
            raise ValueError("Ambiguous SAML representation")
        service = one(
            attributes, f"./saml:Attribute[@Name='{ATTRIBUTE_PREFIX}ServiceUUID']"
        )
        values = service.findall("./saml:AttributeValue", NS)
        if not values or self.config.service_uuid not in {
            simple_text(v) for v in values
        }:
            raise ValueError("Invalid SAML service")
        acting = one(
            attributes, f"./saml:Attribute[@Name='{ATTRIBUTE_PREFIX}ActingSubjectID']"
        )
        identity = self._identity(acting)
        represented = self._identity(legal_attributes[0]) if legal_attributes else None
        return DecryptResult(
            personalId="NL:bsn:" + identity,
            authnContextClassRef=loa,
            representedPersonalId="NL:bsn:" + represented if represented else None,
        )

    def _identity(self, acting: etree._Element) -> str:
        identities: set[str] = set()
        for value in acting.findall("./saml:AttributeValue", NS):
            encrypted = one(value, "./saml:EncryptedID")
            # A multi-recipient response may include copies for other parties.
            if not any(
                key.get("Recipient") == self.config.entity_id
                for key in encrypted.findall("./xenc:EncryptedKey", NS)
            ):
                continue
            name_id = decrypt_identifier(
                encrypted,
                self.material.private_key,
                self.config.entity_id or "",
                self.material.key_name,
                self.config.max_xml_bytes,
            )
            identities.add(self._bsn(name_id.text))
        if len(identities) != 1:
            raise ValueError("Missing or ambiguous SAML identity")
        return identities.pop()

    @staticmethod
    def _artifact(root: etree._Element) -> etree._Element:
        if root.tag == f"{{{NS['samlp']}}}ArtifactResponse":
            return root
        for namespace in (
            "http://schemas.xmlsoap.org/soap/envelope/",
            "http://www.w3.org/2003/05/soap-envelope",
        ):
            if root.tag == f"{{{namespace}}}Envelope":
                body = one(root, f"./{{{namespace}}}Body")
                children = [child for child in body if isinstance(child.tag, str)]
                if (
                    len(children) == 1
                    and children[0].tag == f"{{{NS['samlp']}}}ArtifactResponse"
                ):
                    return children[0]
        raise ValueError("Invalid SAML envelope")

    @staticmethod
    def _status(element: etree._Element) -> None:
        status = one(one(element, "./samlp:Status"), "./samlp:StatusCode")
        if status.get("Value") != SUCCESS or len(status):
            raise ValueError("Unsuccessful SAML response")

    def _conditions(
        self, assertion: etree._Element, now: datetime, skew: timedelta
    ) -> None:
        conditions = one(assertion, "./saml:Conditions")
        not_before = utc_time(conditions.get("NotBefore"))
        not_after = utc_time(conditions.get("NotOnOrAfter"))
        if (
            not_before >= not_after
            or now + skew < not_before
            or now - skew >= not_after
        ):
            raise ValueError("Invalid SAML validity period")
        restriction = one(conditions, "./saml:AudienceRestriction")
        if any(
            child.tag != f"{{{NS['saml']}}}AudienceRestriction" for child in conditions
        ):
            raise ValueError("Unsupported SAML condition")
        audiences = restriction.findall("./saml:Audience", NS)
        if not audiences or self.config.audience not in {
            simple_text(node) for node in audiences
        }:
            raise ValueError("Invalid SAML audience")

    def _subject(
        self,
        assertion: etree._Element,
        response: etree._Element,
        now: datetime,
        skew: timedelta,
    ) -> None:
        subject = one(assertion, "./saml:Subject")
        name = one(subject, "./saml:NameID")
        simple_text(name)
        if name.get("Format") not in (
            None,
            "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        ):
            raise ValueError("Invalid SAML subject")
        confirmation = one(subject, "./saml:SubjectConfirmation")
        if confirmation.get("Method") != "urn:oasis:names:tc:SAML:2.0:cm:bearer":
            raise ValueError("Invalid SAML subject confirmation")
        data = one(confirmation, "./saml:SubjectConfirmationData")
        if (
            data.get("Recipient") != self.config.acs_url
            or data.get("InResponseTo") != response.get("InResponseTo")
            or data.get("NotBefore") is not None
            or now - skew >= utc_time(data.get("NotOnOrAfter"))
        ):
            raise ValueError("Invalid SAML subject confirmation")

    @staticmethod
    def _bsn(value: str | None) -> str:
        if (
            value is None
            or len(value) != 9
            or not value.isascii()
            or not value.isdigit()
        ):
            raise ValueError("Invalid SAML identifier")
        digits = [int(digit) for digit in value]
        if (
            sum(digit * (9 - i) for i, digit in enumerate(digits[:-1])) - digits[-1]
        ) % 11:
            raise ValueError("Invalid SAML identifier")
        return value
