from pydantic import BaseModel, ConfigDict, Field


class DecryptRequest(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True, hide_input_in_errors=True)

    saml_response: str = Field(min_length=1, repr=False)


class DecryptResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    personalId: str
    authnContextClassRef: str
    representedPersonalId: str | None = None
