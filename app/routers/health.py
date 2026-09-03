import logging

from fastapi import APIRouter
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get(
    "/health",
    summary="Health Check",
    description="Health check for the service. The service has no dependencies yet; "
    "the crypto-service will be added here once real SAML decryption lands.",
    status_code=200,
    tags=["Health"],
)
def health() -> JSONResponse:
    logger.info("Checking application health")
    return JSONResponse(content={"status": "ok", "components": {}})
