from soc.ml.detector import DummyDetector
from soc.ml.features import ATTACK_HINT_CLASS_LABELS, binary_feature_contract
from soc.ml.detector import XGBoostDetector


def test_dummy_detector_uses_mock_prob() -> None:
    result = DummyDetector().predict({"mock_prob": "0.25"})

    assert result.prob == 0.25
    assert result.category_hint == "mock"
    assert result.shap_top5[0][0] == "mock_prob"


def test_dummy_detector_defaults_to_middle_probability() -> None:
    result = DummyDetector().predict({})

    assert result.prob == 0.5


def test_dummy_detector_category_hint_is_available_for_route_enrichment() -> None:
    assert DummyDetector().predict_category_hint({}) == ("mock", 0.5)


def test_xgboost_category_metadata_validation_rejects_wrong_class_labels() -> None:
    metadata = {
        **binary_feature_contract().to_dict(),
        "categorical_encoders": {"PROTOCOL": {"6": 0}},
        "class_labels": [*ATTACK_HINT_CLASS_LABELS, "Extra"],
    }

    try:
        XGBoostDetector._validate_category_metadata(metadata)
    except ValueError as exc:
        assert "class_labels" in str(exc)
    else:
        raise AssertionError("expected category metadata validation failure")
