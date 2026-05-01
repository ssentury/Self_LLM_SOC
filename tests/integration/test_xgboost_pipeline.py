from pathlib import Path
import subprocess
import sys

import pytest

from soc.io import read_flows_csv
from soc.ml.detector import XGBoostDetector
from soc.ml.features import build_ml_feature_dict


MODEL_PATH = Path("output/models/xgb_binary_v1.json")
METADATA_PATH = Path("output/models/xgb_binary_v1_metadata.json")
THRESHOLDS_PATH = Path("output/models/xgb_binary_v1_thresholds_routing_default.json")
CATEGORY_MODEL_PATH = Path("output/models/xgb_attack_hint_v1.json")
CATEGORY_METADATA_PATH = Path("output/models/xgb_attack_hint_v1_metadata.json")


@pytest.mark.skipif(
    not MODEL_PATH.exists() or not METADATA_PATH.exists() or not THRESHOLDS_PATH.exists(),
    reason="trained XGBoost artifacts are not available",
)
def test_xgboost_pipeline_renders_shap_for_tier1_route(tmp_path: Path) -> None:
    pytest.importorskip("pandas")
    pytest.importorskip("xgboost")

    output_dir = tmp_path / "reports_xgb"
    result = subprocess.run(
        [
            sys.executable,
            "scripts/pipeline_run.py",
            "--input",
            "data/sample/xgb_route_sample.csv",
            "--output",
            str(output_dir),
            "--detector",
            "xgboost",
            "--model",
            str(MODEL_PATH),
            "--metadata",
            str(METADATA_PATH),
            "--thresholds",
            str(THRESHOLDS_PATH),
            "--no-storage",
            "--llm",
            "fake",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "processed=9" in result.stdout

    summary = (output_dir / "summary.html").read_text(encoding="utf-8")
    assert "auto_dismiss" in summary
    assert "tier1_llm" in summary
    assert "auto_alert" in summary

    tier1_report = (output_dir / "tier1_llm-1.html").read_text(encoding="utf-8")
    assert "SHAP top5:" in tier1_report
    assert "LONGEST_FLOW_PKT" in tier1_report

    auto_alert_report = (output_dir / "auto_alert-1.html").read_text(encoding="utf-8")
    assert "SHAP top5:</strong> n/a" in auto_alert_report
    if CATEGORY_MODEL_PATH.exists() and CATEGORY_METADATA_PATH.exists():
        assert "Category hint:</strong> not_evaluated" not in auto_alert_report
    else:
        assert "Category hint:</strong> not_evaluated" in auto_alert_report

    auto_dismiss_report = (output_dir / "auto_dismiss-1.html").read_text(encoding="utf-8")
    assert "Category hint:</strong> not_evaluated" in auto_dismiss_report


@pytest.mark.skipif(
    not MODEL_PATH.exists() or not METADATA_PATH.exists(),
    reason="trained XGBoost artifacts are not available",
)
def test_xgboost_category_hint_falls_back_when_optional_model_is_missing() -> None:
    pytest.importorskip("pandas")
    pytest.importorskip("xgboost")

    detector = XGBoostDetector(
        str(MODEL_PATH),
        str(METADATA_PATH),
        category_model_path="output/models/does_not_exist.json",
        category_metadata_path="output/models/does_not_exist_metadata.json",
    )
    flow = read_flows_csv("data/sample/xgb_route_sample.csv")[0]

    assert detector.predict_category_hint(build_ml_feature_dict(flow)) == (
        "not_evaluated",
        0.0,
    )
