from typing import Any

from soc.cli.pipeline import _enrich_ml_after_route
from soc.ml.detector import MLDetector
from soc.models import MLResult


class CountingDetector(MLDetector):
    def __init__(self) -> None:
        self.category_calls = 0
        self.explain_calls = 0

    def predict(self, flow_features: dict[str, Any]) -> MLResult:
        return MLResult(prob=0.5, category_hint="binary", category_confidence=0.5)

    def explain(self, flow_features: dict[str, Any]) -> list[tuple[str, float, float]]:
        self.explain_calls += 1
        return [("feature", 1.0, 2.0)]

    def predict_category_hint(self, flow_features: dict[str, Any]) -> tuple[str, float]:
        self.category_calls += 1
        return "DDoS", 0.9


def test_category_hint_is_not_evaluated_for_auto_dismiss() -> None:
    detector = CountingDetector()

    ml = _enrich_ml_after_route(
        detector,
        {},
        MLResult(prob=0.1, category_hint="benign", category_confidence=0.9),
        "auto_dismiss",
    )

    assert ml.category_hint == "not_evaluated"
    assert ml.category_confidence == 0.0
    assert ml.shap_top5 == []
    assert detector.category_calls == 0
    assert detector.explain_calls == 0


def test_category_hint_runs_for_auto_alert_without_shap() -> None:
    detector = CountingDetector()

    ml = _enrich_ml_after_route(
        detector,
        {},
        MLResult(prob=0.99, category_hint="malicious", category_confidence=0.99),
        "auto_alert",
    )

    assert ml.category_hint == "DDoS"
    assert ml.category_confidence == 0.9
    assert ml.shap_top5 == []
    assert detector.category_calls == 1
    assert detector.explain_calls == 0


def test_category_hint_and_shap_run_for_tier1() -> None:
    detector = CountingDetector()

    ml = _enrich_ml_after_route(
        detector,
        {},
        MLResult(prob=0.5, category_hint="malicious", category_confidence=0.5),
        "tier1_llm",
    )

    assert ml.category_hint == "DDoS"
    assert ml.shap_top5 == [("feature", 1.0, 2.0)]
    assert detector.category_calls == 1
    assert detector.explain_calls == 1
