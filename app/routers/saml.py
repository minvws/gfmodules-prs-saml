import logging
from typing import Annotated, Any

from fastapi import APIRouter, Body
from fastapi.encoders import jsonable_encoder
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)
router = APIRouter()

_ENDPOINT = "/saml/decrypt"


@router.post(
    _ENDPOINT,
    summary="MOCK: process a DigiD SAML response for the PRS",
    tags=["SAML Services"],
    description="""
**This endpoint is a mock.** It accepts any JSON body from the PRS and returns
that body unchanged. No XML parsing, signature verification, or decryption is
performed yet.

The real implementation will parse the SAML response with a hardened XML
parser, verify the DigiD signature, decrypt the assertion via the
crypto-service (HSM), and return the persoonsnummer and betrouwbaarheidsniveau
(strictly in-memory) to the PRS.

This is an internal endpoint: only the PRS may reach this service.
""",
)
def post_decrypt(payload: Annotated[Any, Body()]) -> JSONResponse:
    logger.info("SAML decrypt requested (mock: request echoed)")
    return JSONResponse(jsonable_encoder(payload))
