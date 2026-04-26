from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from soc.models import MLResult


class MLDetector(ABC):
    @abstractmethod
    def predict(self, flow_features: dict[str, Any]) -> MLResult:
        raise NotImplementedError

    @abstractmethod
    def explain(self, flow_features: dict[str, Any]) -> list[tuple[str, float, float]]:
        raise NotImplementedError


class DummyDetector(MLDetector):
    """Offline detector for smoke tests before the real XGBoost model exists."""

    def predict(self, flow_features: dict[str, Any]) -> MLResult:
        prob = float(flow_features.get("mock_prob") or 0.5)
        return MLResult(
            prob=max(0.0, min(1.0, prob)),
            category_hint="mock",
            category_confidence=0.5,
            shap_top5=self.explain(flow_features),
        )

    def explain(self, flow_features: dict[str, Any]) -> list[tuple[str, float, float]]:
        if "mock_prob" not in flow_features:
            return []
        return [("mock_prob", float(flow_features["mock_prob"]), 1.0)]


class XGBoostDetector(MLDetector):
    def __init__(self, model_path: str) -> None:
        self.model_path = model_path
        raise NotImplementedError(
            "XGBoostDetector is intentionally not wired in the scaffold. "
            "Use --detector dummy for end-to-end smoke tests."
        )

    def predict(self, flow_features: dict[str, Any]) -> MLResult:
        raise NotImplementedError

    def explain(self, flow_features: dict[str, Any]) -> list[tuple[str, float, float]]:
        raise NotImplementedError
