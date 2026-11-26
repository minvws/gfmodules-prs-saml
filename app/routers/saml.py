import logging
from typing import Annotated

from fastapi import APIRouter, Depends

from app.container import get_saml_service
from app.models.saml import DecryptRequest, DecryptResult
from app.saml.errors import (
    SamlDisabled,
    SamlFailureReason,
    SamlProcessingError,
    SamlRejected,
    SamlUnavailable,
    debug_active_exception,
    raise_sanitized,
)
from app.saml.service import SamlService

logger = logging.getLogger(__name__)

router = APIRouter()


def _error_schema(field: str, value: str) -> dict[str, object]:
    return {
        "type": "object",
        "properties": {field: {"type": "string", "const": value}},
        "required": [field],
        "additionalProperties": False,
    }


@router.post(
    "/saml/decrypt",
    summary="Verify and decrypt a TVS SAML response for the PRS",
    response_model=DecryptResult,
    response_model_exclude_none=True,
    responses={
        400: {
            "description": "Invalid SAML response or body-parser failure",
            "content": {
                "application/json": {
                    "schema": {
                        "oneOf": [
                            _error_schema("error", "invalid_saml_response"),
                            _error_schema(
                                "detail", "There was an error parsing the body"
                            ),
                        ]
                    }
                }
            },
        },
        503: {
            "description": "SAML processing unavailable",
            "content": {
                "application/json": {
                    "schema": _error_schema("error", "saml_unavailable")
                }
            },
        },
        500: {
            "description": "Internal processing or response-generation error",
            "content": {
                "application/json": {
                    "schema": _error_schema("error", "Internal server error")
                }
            },
        },
    },
    tags=["SAML Services"],
    description="""
Accept a base64-encoded SOAP 1.1 or 1.2 message in saml_response, with a TVS
ArtifactResponse as the only element in the SOAP Body.
Verify the required signatures with locally provisioned trusted metadata and
decrypt ActingSubjectID using the RSA private key configured in app.conf.

This is an internal endpoint: only the PRS may reach this service.
The authentication owner handles original request correlation and replay
prevention. No artifact resolution is performed here.
""",
)
def post_decrypt(
    payload: DecryptRequest,
    service: Annotated[SamlService | None, Depends(get_saml_service)],
) -> DecryptResult:
    if service is None:
        raise SamlDisabled("SAML service is disabled")
    try:
        result = service.decrypt(payload.saml_response)
        if not isinstance(result, DecryptResult):
            raise TypeError("SAML service must return a DecryptResult")
    except (SamlRejected, SamlUnavailable):
        debug_active_exception()
        raise
    except ValueError:
        raise_sanitized(SamlRejected(SamlFailureReason.UNKNOWN))
    except Exception:  # noqa: BLE001 - do not expose service exceptions to the server
        raise_sanitized(SamlProcessingError("SAML processing failed"))
    logger.info("SAML response processed")
    return result
