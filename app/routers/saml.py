import logging
from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import APIRouter, Request
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field
from starlette.responses import JSONResponse, Response

from app.saml.service import DecryptResult, SamlService, SamlUnavailable

logger = logging.getLogger(__name__)


def _error(status: int, code: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": code},
        headers={"Cache-Control": "no-store"},
    )


class SamlRoute(APIRoute):
    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        handler = super().get_route_handler()

        async def bounded_handler(request: Request) -> Response:
            service: SamlService | None = getattr(
                request.app.state, "saml_service", None
            )
            if service is None:
                return _error(503, "saml_unavailable")
            # Bound the encoded field plus a small allowance for JSON/context.
            limit = 4 * ((service.config.max_xml_bytes + 2) // 3) + 4096
            chunks: list[bytes] = []
            size = 0
            async for chunk in request.stream():
                size += len(chunk)
                if size > limit:
                    return _error(413, "request_too_large")
                chunks.append(chunk)
            request._body = b"".join(chunks)
            try:
                response = await handler(request)
            except RequestValidationError:
                # FastAPI's standard detail includes the rejected input.
                return _error(422, "invalid_request")
            response.headers["Cache-Control"] = "no-store"
            return response

        return bounded_handler


router = APIRouter(route_class=SamlRoute)


class DecryptRequest(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    samlResponse: str = Field(min_length=1, max_length=13981016, repr=False)


_ENDPOINT = "/saml/decrypt"


@router.post(
    _ENDPOINT,
    summary="Verify and decrypt a TVS SAML response for the PRS",
    response_model=DecryptResult,
    response_model_exclude_none=True,
    tags=["SAML Services"],
    description="""
Accept a base64-encoded TVS ArtifactResponse, optionally inside a SOAP envelope.
Verify the required signatures with locally provisioned trusted metadata and
decrypt ActingSubjectID using the RSA private key configured in app.conf.
Return the personal ID and authentication level strictly in memory.

This is an internal endpoint: only the PRS may reach this service.
The authentication owner handles original request correlation and replay
prevention. No artifact resolution is performed here.
""",
)
def post_decrypt(
    payload: DecryptRequest, request: Request
) -> DecryptResult | JSONResponse:
    service: SamlService | None = getattr(request.app.state, "saml_service", None)
    if service is None:
        return _error(503, "saml_unavailable")
    try:
        result = service.decrypt(payload.samlResponse)
    except SamlUnavailable:
        logger.warning("SAML processing unavailable")
        return _error(503, "saml_unavailable")
    except ValueError:
        logger.warning("SAML response rejected")
        return _error(400, "invalid_saml_response")
    logger.info("SAML response processed")
    return result
