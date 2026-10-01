from collections.abc import Callable
from dataclasses import dataclass

from pydantic import BaseModel

from app.config import Config


class FeatureInfo(BaseModel):
    id: str
    title: str
    description: str


@dataclass(frozen=True)
class Feature:
    info: FeatureInfo
    enabled: Callable[[Config], bool]


FEATURES: list[Feature] = [
    Feature(
        info=FeatureInfo(
            id="saml_decrypt",
            title="SAML decrypt (mock)",
            description=(
                "Process a DigiD SAML response for the PRS; currently a mock that "
                "echoes the request"
            ),
        ),
        enabled=lambda _: True,
    ),
]


def enabled_features(config: Config) -> list[FeatureInfo]:
    return [feature.info for feature in FEATURES if feature.enabled(config)]
