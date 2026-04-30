from pathlib import Path
import subprocess
import sys

import pytest


MODEL_PATH = Path("output/models/xgb_binary_v1.json")
METADATA_PATH = Path("output/models/xgb_binary_v1_metadata.json")
THRESHOLDS_PATH = Path("output/models/xgb_binary_v1_thresholds_routing_default.json")


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
