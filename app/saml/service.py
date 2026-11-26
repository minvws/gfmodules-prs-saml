"""Verify a supplied TVS response before releasing its decrypted identity."""

import base64
import traceback
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from lxml import etree
from saml2 import saml, samlp
from saml2.response import AuthnResponse, StatusResponse
from saml2.sigver import CryptoBackend, SecurityContext

from app.config import ConfigSaml
from app.models.saml import DecryptResult
from app.saml.decryption import decrypt_identifier
from app.saml.errors import (
    SamlFailureReason,
    SamlRejected,
    debug_active_exception,
    raise_sanitized,
    raise_sanitized_unavailable,
)
from app.saml.errors import SamlUnavailable as SamlUnavailable  # noqa: PLC0414
from app.saml.native import saml_validation
from app.saml.signatures import verify_signature
from app.saml.trust import load_material, utc_time
from app.saml.xml import NS, artifact_response_elements, one, parse_xml, simple_text

ATTRIBUTE_PREFIX = "urn:nl-eid-gdi:1.0:"
LEVELS = {
    "http://eID.logius.nl/LoA/basic": 0,
    "http://eidas.europa.eu/LoA/low": 1,
    "http://eidas.europa.eu/LoA/substantial": 2,
    "http://eidas.europa.eu/LoA/high": 3,
}
_RESPONSE_ERRORS = (ValueError, TypeError, etree.Error)
_INVALID_CONDITIONS = SamlFailureReason.INVALID_CONDITIONS_OR_AUDIENCE


@contextmanager
def _reject_as(
    reason: SamlFailureReason,
    errors: type[Exception] | tuple[type[Exception], ...] = _RESPONSE_ERRORS,
) -> Iterator[None]:
    """Classify a failing operation; decrypt() logs and detaches its cause."""
    try:
        yield
    except (SamlRejected, SamlUnavailable):
        raise
    except errors as error:
        raise SamlRejected(reason) from error


class SamlService:
    def __init__(self, config: ConfigSaml) -> None:
        if not config.enabled or config.minimum_loa not in LEVELS:
            raise ValueError("Invalid SAML configuration")
        self.config = config
        self.material = load_material(config)

    def decrypt(self, saml_response: str) -> DecryptResult:
        try:
            return self._decrypt(saml_response)
        except SamlUnavailable as error:
            # This exception is re-raised, so its finished child frames persist.
            traceback.clear_frames(error.__traceback__)
            raise_sanitized(error)
        except _RESPONSE_ERRORS as error:
            reason = (
                error.reason
                if isinstance(error, SamlRejected)
                else SamlFailureReason.VALIDATION_FAILED
            )
            raise_sanitized(SamlRejected(reason))
        except Exception:
            debug_active_exception()
            raise
        except (KeyboardInterrupt, SystemExit) as interruption:
            # An interruption can occur before a child's own cleanup starts.
            traceback.clear_frames(interruption.__traceback__)
            interruption.__cause__ = None
            try:
                raise
            finally:
                interruption.__context__ = None
        finally:
            # Drop this frame's request reference; this is not memory zeroization.
            del saml_response

    def _decrypt(self, encoded: str) -> DecryptResult:
        with _reject_as(SamlFailureReason.INVALID_FORMAT):
            root = parse_xml(base64.b64decode(encoded, validate=True))
            artifact, response, assertion = artifact_response_elements(root)
        now = datetime.now(UTC)
        try:
            certificates = self.material.active_certificates(now)
        except ValueError:
            debug_active_exception()
            raise SamlUnavailable("SAML configuration expired") from None
        with _reject_as(SamlFailureReason.SIGNATURE_FAILED):
            artifact_model = verify_signature(artifact, certificates)
            assertion_model = verify_signature(assertion, certificates)
            if response.findall("./ds:Signature", NS):
                verify_signature(response, certificates)
        # The PySAML2 validators need a context even for non-crypto checks.
        with (
            _reject_as(SamlFailureReason.SIGNATURE_FAILED, Exception),
            saml_validation(),
        ):
            try:
                security_context = SecurityContext(
                    CryptoBackend(), only_use_keys_in_metadata=True
                )
            except SamlUnavailable:
                raise_sanitized_unavailable()
        with _reject_as(SamlFailureReason.VALIDATION_FAILED, Exception):
            responses = artifact_model.extensions_as_elements("Response", samlp)
        if len(responses) != 1 or not isinstance(responses[0], samlp.Response):
            raise ValueError("Invalid SAML response")
        response_model = responses[0]
        skew = timedelta(seconds=self.config.clock_skew_seconds)
        if assertion_model.version != "2.0":
            raise ValueError("Invalid SAML version")
        for model in (artifact_model, response_model, assertion_model):
            if utc_time(model.issue_instant) > now + skew:
                raise ValueError("Invalid SAML issue time")
            if (
                model.issuer is None
                or not isinstance(model.issuer.text, str)
                or model.issuer.text.strip() != self.material.issuer
            ):
                raise SamlRejected(
                    SamlFailureReason.INVALID_ISSUER, "Invalid SAML issuer"
                )
        if not artifact_model.in_response_to or not response_model.in_response_to:
            raise ValueError("Missing SAML correlation")
        if response_model.destination != self.config.acs_url:
            raise ValueError("Invalid SAML destination")

        artifact_validator = StatusResponse(
            security_context, timeslack=self.config.clock_skew_seconds, asynchop=False
        )
        artifact_validator.response = artifact_model
        authn = AuthnResponse(
            security_context,
            [],
            self.config.audience,
            return_addrs=[self.config.acs_url],
            timeslack=self.config.clock_skew_seconds,
            asynchop=True,
            allow_unsolicited=True,
            conv_info={"entity_id": self.config.audience},
        )
        authn.response = response_model
        authn.assertion = assertion_model
        for model in (artifact_model, response_model):
            if model.status.status_code.status_code is not None:
                raise ValueError("Invalid SAML status")

        # TVS requires bounded conditions and one audience restriction.
        with _reject_as(_INVALID_CONDITIONS):
            conditions = assertion_model.conditions
            if (
                conditions is None
                or len(conditions.audience_restriction) != 1
                or conditions.one_time_use
                or conditions.proxy_restriction
                or conditions.extension_elements
                or utc_time(conditions.not_before)
                >= utc_time(conditions.not_on_or_after)
            ):
                raise ValueError("Invalid SAML conditions")
        subject = assertion_model.subject
        if (
            subject is None
            or subject.name_id is None
            or not subject.name_id.text
            or not subject.name_id.text.strip()
            or subject.name_id.format not in (None, saml.NAMEID_FORMAT_TRANSIENT)
            or len(subject.subject_confirmation) != 1
        ):
            raise ValueError("Invalid SAML subject")
        confirmation = subject.subject_confirmation[0]
        data = confirmation.subject_confirmation_data
        if (
            confirmation.method != saml.SCM_BEARER
            or data is None
            or data.recipient != self.config.acs_url
            or data.in_response_to != response_model.in_response_to
            or data.not_before is not None
        ):
            raise ValueError("Invalid SAML bearer")
        # Require a time with a timezone; PySAML2 handles the expiry comparison.
        utc_time(data.not_on_or_after)
        # These are the real library response, time, audience and subject checks;
        # avoid its identity-conversion/decrypt_keys path, which writes key files.
        with (
            _reject_as(SamlFailureReason.VALIDATION_FAILED, Exception),
            saml_validation(),
        ):
            if (
                not artifact_validator.verify()
                or not StatusResponse.verify(authn)
                or not authn.authn_statement_ok()
            ):
                raise ValueError("Invalid SAML response")
            with _reject_as(_INVALID_CONDITIONS, Exception):
                if not authn.condition_ok():
                    raise ValueError("Invalid SAML response")
            # Address was never checked here. Omit it only from the verified
            # subject model so PySAML2 does not impose IP syntax; the
            # source-XSD-validated and signed XML tree remains untouched.
            data.address = None
            if not authn.get_subject():
                raise ValueError("Invalid SAML response")

        statement_model = assertion_model.authn_statement[0]
        if utc_time(statement_model.authn_instant) > now + skew:
            raise ValueError("Invalid SAML authentication time")
        context = statement_model.authn_context
        if (
            context is None
            or context.authn_context_class_ref is None
            or not isinstance(context.authn_context_class_ref.text, str)
        ):
            raise ValueError("Invalid SAML authentication context")
        loa = context.authn_context_class_ref.text.strip()
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
        if self.config.service_uuid not in {simple_text(v) for v in values}:
            raise ValueError("Invalid SAML service")
        acting = one(
            attributes, f"./saml:Attribute[@Name='{ATTRIBUTE_PREFIX}ActingSubjectID']"
        )
        identity = None
        represented = None
        try:
            with _reject_as(SamlFailureReason.DECRYPTION_FAILED):
                identity = self._identity(acting)
                represented = (
                    self._identity(legal_attributes[0]) if legal_attributes else None
                )
                return DecryptResult(
                    personalId="NL:bsn:" + identity,
                    authnContextClassRef=loa,
                    representedPersonalId="NL:bsn:" + represented
                    if represented
                    else None,
                )
        finally:
            # Drop local references if a later identity interrupts processing.
            identity = None
            represented = None

    def _identity(self, attribute: etree._Element) -> str:
        identities: set[str] = set()
        name_id = None
        try:
            for value in attribute.findall("./saml:AttributeValue", NS):
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
                )
                identities.add(self._bsn(name_id.text))
                name_id = None
            if len(identities) != 1:
                raise ValueError("Missing or ambiguous SAML identity")
            return identities.pop()
        finally:
            # Do not retain earlier decrypted values in interrupted frames.
            name_id = None
            identities.clear()

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
