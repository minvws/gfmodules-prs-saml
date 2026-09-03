import json
import logging
from pathlib import Path

from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse, PlainTextResponse

logger = logging.getLogger(__name__)
router = APIRouter()

# https://www.patorjk.com/software/taag/#p=display&f=Doom&t=PRS-SAML
LOGO = r"""
______ ______  _____         _____   ___  ___  ___ _
| ___ \| ___ \/  ___|       /  ___| / _ \ |  \/  || |
| |_/ /| |_/ /\ `--.  ______\ `--. / /_\ \| .  . || |
|  __/ |    /  `--. \|______|`--. \|  _  || |\/| || |
| |    | |\ \ /\__/ /       /\__/ /| | | || |  | || |____
\_|    \_| \_|\____/        \____/ \_| |_/\_|  |_/\_____/
"""


@router.get(
    "/",
    summary="Service banner and version information",
    tags=["Service Information"],
)
def index() -> Response:
    content = LOGO

    try:
        with open(Path(__file__).parent.parent.parent / "version.json", "r") as file:
            data = json.load(file)
            content += f"\nVersion: {data['version']}\nCommit: {data['git_ref']}"
    except (OSError, json.JSONDecodeError, KeyError) as e:
        content += "\nNo version information found"
        logger.info("version info could not be loaded: %s", e)

    return PlainTextResponse(content)


@router.get(
    "/version.json",
    summary="Service version as JSON",
    tags=["Service Information"],
)
def version_json() -> Response:
    try:
        with open(Path(__file__).parent.parent.parent / "version.json", "r") as file:
            content = json.load(file)
    except (OSError, json.JSONDecodeError) as e:
        logger.info("version info could not be loaded: %s", e)
        return Response(status_code=404)

    return JSONResponse(content)
