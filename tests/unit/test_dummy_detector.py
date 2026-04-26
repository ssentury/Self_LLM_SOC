from soc.ml.detector import DummyDetector


def test_dummy_detector_uses_mock_prob() -> None:
    result = DummyDetector().predict({"mock_prob": "0.25"})

    assert result.prob == 0.25
    assert result.category_hint == "mock"
    assert result.shap_top5[0][0] == "mock_prob"


def test_dummy_detector_defaults_to_middle_probability() -> None:
    result = DummyDetector().predict({})

    assert result.prob == 0.5
