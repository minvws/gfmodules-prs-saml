from app.config import get_config
from app.features import FEATURES, enabled_features


def test_all_features_are_enabled() -> None:
    ids = [feature.id for feature in enabled_features(get_config())]

    assert ids == [feature.info.id for feature in FEATURES]


def test_feature_ids_are_unique() -> None:
    ids = [feature.info.id for feature in FEATURES]

    assert len(ids) == len(set(ids))
