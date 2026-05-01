from __future__ import annotations

from abc import ABC, abstractmethod
import json
import math
from pathlib import Path
from typing import Any

from soc.ml.features import ATTACK_HINT_CLASS_LABELS, binary_feature_contract
from soc.models import MLResult


class MLDetector(ABC):
    @abstractmethod
    def predict(self, flow_features: dict[str, Any]) -> MLResult:
        raise NotImplementedError

    @abstractmethod
    def explain(self, flow_features: dict[str, Any]) -> list[tuple[str, float, float]]:
        raise NotImplementedError

    @abstractmethod
    def predict_category_hint(self, flow_features: dict[str, Any]) -> tuple[str, float]:
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

    def predict_category_hint(self, flow_features: dict[str, Any]) -> tuple[str, float]:
        return "mock", 0.5


class XGBoostDetector(MLDetector):
    def __init__(
        self,
        model_path: str,
        metadata_path: str | None = None,
        category_model_path: str | None = None,
        category_metadata_path: str | None = None,
    ) -> None:
        self.model_path = Path(model_path)
        self.metadata_path = (
            Path(metadata_path) if metadata_path else self.model_path.with_name(
                f"{self.model_path.stem}_metadata.json"
            )
        )
        self.metadata = self._load_metadata(self.metadata_path)
        self.feature_order: list[str] = self.metadata["feature_order"]
        self.categorical_encoders: dict[str, dict[str, int]] = self.metadata[
            "categorical_encoders"
        ]
        self._validate_metadata()

        try:
            import xgboost as xgb
        except ImportError as exc:
            raise RuntimeError(
                "XGBoostDetector requires xgboost. Install ML dependencies with "
                "`python -m pip install -r requirements-ml.txt` or include .ml_deps "
                "on PYTHONPATH."
            ) from exc

        self.model = xgb.XGBClassifier()
        self.model.load_model(self.model_path)
        self.category_model = None
        self.category_metadata: dict[str, Any] | None = None
        self.category_feature_order: list[str] = []
        self.category_categorical_encoders: dict[str, dict[str, int]] = {}
        self.category_class_labels: list[str] = []
        self._load_optional_category_model(
            xgb,
            category_model_path=category_model_path,
            category_metadata_path=category_metadata_path,
        )

    def predict(self, flow_features: dict[str, Any]) -> MLResult:
        frame = self._to_frame(flow_features)
        prob = float(self.model.predict_proba(frame)[0, 1])
        return MLResult(
            prob=max(0.0, min(1.0, prob)),
            category_hint="malicious" if prob >= 0.5 else "benign",
            category_confidence=max(prob, 1.0 - prob),
            shap_top5=[],
        )

    def predict_category_hint(self, flow_features: dict[str, Any]) -> tuple[str, float]:
        if self.category_model is None:
            return "not_evaluated", 0.0

        frame = self._to_frame(
            flow_features,
            feature_order=self.category_feature_order,
            categorical_encoders=self.category_categorical_encoders,
        )
        probabilities = self.category_model.predict_proba(frame)[0]
        best_index = max(range(len(probabilities)), key=lambda index: float(probabilities[index]))
        label = self.category_class_labels[best_index]
        confidence = max(0.0, min(1.0, float(probabilities[best_index])))
        return label, confidence

    def explain(self, flow_features: dict[str, Any]) -> list[tuple[str, float, float]]:
        try:
            import xgboost as xgb

            frame = self._to_frame(flow_features)
            dmatrix = xgb.DMatrix(frame, feature_names=self.feature_order)
            contributions = self.model.get_booster().predict(
                dmatrix,
                pred_contribs=True,
            )[0][:-1]
        except Exception:
            return []

        raw_values = self._raw_numeric_values(flow_features)
        ranked = sorted(
            zip(self.feature_order, contributions, strict=True),
            key=lambda item: abs(float(item[1])),
            reverse=True,
        )
        return [
            (feature, raw_values[feature], float(contribution))
            for feature, contribution in ranked[:5]
        ]

    def _to_frame(
        self,
        flow_features: dict[str, Any],
        feature_order: list[str] | None = None,
        categorical_encoders: dict[str, dict[str, int]] | None = None,
    ) -> Any:
        import pandas as pd

        order = feature_order or self.feature_order
        encoders = categorical_encoders or self.categorical_encoders
        return pd.DataFrame(
            [self._vectorize(flow_features, order, encoders)],
            columns=order,
        )

    def _vectorize(
        self,
        flow_features: dict[str, Any],
        feature_order: list[str] | None = None,
        categorical_encoders: dict[str, dict[str, int]] | None = None,
    ) -> dict[str, float]:
        order = feature_order or self.feature_order
        encoders = categorical_encoders or self.categorical_encoders
        row: dict[str, float] = {}
        missing = [feature for feature in order if feature not in flow_features]
        if missing:
            raise ValueError(f"missing ML features for XGBoostDetector: {missing}")

        for feature in order:
            value = flow_features[feature]
            if feature in encoders:
                mapping = encoders[feature]
                row[feature] = float(mapping.get(str(value), -1))
            else:
                row[feature] = float(value)
            if not math.isfinite(row[feature]):
                raise ValueError(f"non-finite ML feature {feature}={value!r}")
        return row

    def _raw_numeric_values(self, flow_features: dict[str, Any]) -> dict[str, float]:
        values: dict[str, float] = {}
        for feature in self.feature_order:
            try:
                values[feature] = float(flow_features[feature])
            except (TypeError, ValueError):
                values[feature] = self._vectorize(flow_features)[feature]
        return values

    @staticmethod
    def _load_metadata(path: Path) -> dict[str, Any]:
        if not path.exists():
            raise FileNotFoundError(f"XGBoost metadata file not found: {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    def _validate_metadata(self) -> None:
        contract = binary_feature_contract().to_dict()
        checks = {
            "feature_order": self.metadata.get("feature_order") == contract["feature_order"],
            "feature_types": self.metadata.get("feature_types") == contract["feature_types"],
            "categorical_features": self.metadata.get("categorical_features")
            == contract["categorical_features"],
            "excluded_features": self.metadata.get("excluded_features")
            == contract["excluded_features"],
        }
        failed = [name for name, ok in checks.items() if not ok]
        if failed:
            raise ValueError(
                "XGBoost metadata does not match current feature contract: "
                + ", ".join(failed)
            )
        if not self.metadata.get("categorical_encoders"):
            raise ValueError("XGBoost metadata is missing categorical_encoders")

    def _load_optional_category_model(
        self,
        xgb: Any,
        category_model_path: str | None,
        category_metadata_path: str | None,
    ) -> None:
        if not category_model_path and not category_metadata_path:
            return

        model_path = Path(category_model_path) if category_model_path else None
        metadata_path = Path(category_metadata_path) if category_metadata_path else None
        if model_path is None and metadata_path is not None:
            model_path = metadata_path.with_name(
                metadata_path.name.replace("_metadata.json", ".json")
            )
        if metadata_path is None and model_path is not None:
            metadata_path = model_path.with_name(f"{model_path.stem}_metadata.json")
        if model_path is None or metadata_path is None:
            return
        if not model_path.exists() or not metadata_path.exists():
            return

        category_metadata = self._load_metadata(metadata_path)
        self._validate_category_metadata(category_metadata)
        category_model = xgb.XGBClassifier()
        category_model.load_model(model_path)

        self.category_model = category_model
        self.category_metadata = category_metadata
        self.category_feature_order = category_metadata["feature_order"]
        self.category_categorical_encoders = category_metadata["categorical_encoders"]
        self.category_class_labels = category_metadata["class_labels"]

    @staticmethod
    def _validate_category_metadata(metadata: dict[str, Any]) -> None:
        contract = binary_feature_contract().to_dict()
        checks = {
            "feature_order": metadata.get("feature_order") == contract["feature_order"],
            "feature_types": metadata.get("feature_types") == contract["feature_types"],
            "categorical_features": metadata.get("categorical_features")
            == contract["categorical_features"],
            "excluded_features": metadata.get("excluded_features")
            == contract["excluded_features"],
        }
        failed = [name for name, ok in checks.items() if not ok]
        if failed:
            raise ValueError(
                "XGBoost category metadata does not match current feature contract: "
                + ", ".join(failed)
            )
        if not metadata.get("categorical_encoders"):
            raise ValueError("XGBoost category metadata is missing categorical_encoders")
        if metadata.get("class_labels") != ATTACK_HINT_CLASS_LABELS:
            raise ValueError(
                "XGBoost category metadata class_labels must be "
                f"{ATTACK_HINT_CLASS_LABELS}"
            )
