import json
import sqlite3
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
def test_xgboost_pipeline_persists_shap_for_tier1_route(tmp_path: Path) -> None:
    pytest.importorskip("pandas")
    pytest.importorskip("xgboost")

    output_dir = tmp_path / "reports_xgb"
    db_path = tmp_path / "soc_events.sqlite"
    result = subprocess.run(
        [
            sys.executable,
            "scripts/pipeline_run.py",
            "--input",
            "data/sample/xgb_route_sample.csv",
            "--output",
            str(output_dir),
            "--sqlite",
            str(db_path),
            "--detector",
            "xgboost",
            "--model",
            str(MODEL_PATH),
            "--metadata",
            str(METADATA_PATH),
            "--thresholds",
            str(THRESHOLDS_PATH),
            "--llm",
            "fake",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "processed=9" in result.stdout
    assert not output_dir.exists()
    with sqlite3.connect(db_path) as conn:
        routes = {
            row[0]
            for row in conn.execute("SELECT DISTINCT route FROM route_decisions").fetchall()
        }
        tier1_shap = json.loads(
            conn.execute(
                "SELECT shap_top5_json FROM ml_results WHERE flow_id = 'tier1_llm-1'"
            ).fetchone()[0]
        )
        auto_alert_hint = conn.execute(
            "SELECT category_hint FROM ml_results WHERE flow_id = 'auto_alert-1'"
        ).fetchone()[0]
        auto_dismiss_hint = conn.execute(
            "SELECT category_hint FROM ml_results WHERE flow_id = 'auto_dismiss-1'"
        ).fetchone()[0]

    assert routes == {"auto_dismiss", "tier1_llm", "auto_alert"}
    assert any(item[0] == "LONGEST_FLOW_PKT" for item in tier1_shap)
    if CATEGORY_MODEL_PATH.exists() and CATEGORY_METADATA_PATH.exists():
        assert auto_alert_hint != "not_evaluated"
    else:
        assert auto_alert_hint == "not_evaluated"
    assert auto_dismiss_hint == "not_evaluated"


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
