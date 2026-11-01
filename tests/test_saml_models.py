import pytest
from pydantic import ValidationError

from app.models.saml import DecryptRequest, DecryptResult


def test_request_model_has_no_former_max_length() -> None:
    value = "A" * 13_981_017
    payload = DecryptRequest.model_validate({"saml_response": value})
    assert payload.saml_response == value
    assert value not in repr(payload)


def test_decrypt_request_hides_input_in_pydantic_error_text() -> None:
    payload = {"saml_response": {"value": "SYNTHETIC-PYDANTIC-INPUT"}}
    with pytest.raises(ValidationError) as caught:
        DecryptRequest.model_validate(payload)

    assert caught.value.errors()[0]["type"] == "string_type"
    assert "SYNTHETIC-PYDANTIC-INPUT" not in str(caught.value)


def test_decrypt_result_is_frozen() -> None:
    result = DecryptResult(
        personalId="synthetic-id", authnContextClassRef="synthetic-context"
    )

    with pytest.raises(ValidationError) as caught:
        result.personalId = "changed-id"

    assert caught.value.errors()[0]["type"] == "frozen_instance"
