from app.config import get_config
from app.features import FEATURES, enabled_features


def test_saml_feature_is_disabled_when_saml_is_disabled() -> None:
    config = get_config()
    disabled = config.model_copy(
        update={"saml": config.saml.model_copy(update={"enabled": False})}
    )

    assert enabled_features(disabled) == []


def test_saml_feature_is_enabled_when_saml_is_enabled() -> None:
    config = get_config()
    enabled = config.model_copy(
        update={"saml": config.saml.model_copy(update={"enabled": True})}
    )
    ids = [feature.id for feature in enabled_features(enabled)]

    assert ids == ["saml_decrypt"]


def test_feature_ids_are_unique() -> None:
    ids = [feature.info.id for feature in FEATURES]

    assert len(ids) == len(set(ids))
