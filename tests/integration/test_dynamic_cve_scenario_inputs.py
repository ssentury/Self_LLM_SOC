import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from soc.io import read_flows_csv
from soc.ml.features import binary_feature_contract, build_ml_feature_dict
from soc.tier2.batch import _load_config
from soc.tier2.input_collectors import Tier2InputCollector
from scripts.evaluate_dynamic_cve_memory_cycle import (
    SOURCE_NAMES,
    _dynamic_day_config,
    _load_manifest_by_flow_id,
    _validate_generated_sources,
)


ROOT = Path(__file__).resolve().parents[2]
SCENARIO_DIR = ROOT / "config" / "scenarios" / "regional_care_dynamic_cve"


def test_dynamic_cve_base_sources_are_connected() -> None:
    config = _load_config("config/settings.regional_care_dynamic_cve_xgb.yaml")

    snapshots = Tier2InputCollector(config).collect()
    statuses = {snapshot.name: snapshot.status for snapshot in snapshots}

    assert statuses["organization"] == "used"
    assert statuses["assets"] == "used"
    assert statuses["policy"] == "used"
    assert statuses["cve_feed"] == "used"
    assert statuses["threat_feed"] == "used"


def test_dynamic_cve_xgb_flow_set_has_expected_shape() -> None:
    flows = read_flows_csv("data/sample/regional_care_dynamic_cve_flows_xgb.csv")
    feature_order = binary_feature_contract().feature_order
    kst = timezone(timedelta(hours=9))

    assert len(flows) == 1000
    assert sum(1 for flow in flows if flow.raw_label == "Malicious") == 100
    assert sum(1 for flow in flows if flow.raw_label == "Benign") == 900
    assert all("mock_prob" not in flow.features for flow in flows)

    days = Counter(
        datetime.fromtimestamp(flow.start_ms / 1000, timezone.utc)
        .astimezone(kst)
        .date()
        for flow in flows
        if flow.start_ms is not None
    )
    assert sorted(days.values()) == [200, 200, 200, 200, 200]

    for flow in flows:
        features = build_ml_feature_dict(flow)
        assert all(feature in features for feature in feature_order)
        for feature in feature_order:
            float(features[feature])

    attacks = Counter(flow.raw_attack for flow in flows if flow.raw_label == "Malicious")
    assert attacks["Brute_Force_-Web"] == 21
    assert attacks["SSH-Bruteforce"] == 19
    assert attacks["SQL_Injection"] == 15
    assert attacks["Infilteration"] == 40
    assert attacks["DDOS_attack-HOIC"] == 5


def test_dynamic_cve_manifest_and_daily_sources_match_timeline() -> None:
    manifest = json.loads(
        (ROOT / "data" / "sample" / "regional_care_dynamic_cve_flows_xgb_manifest.json")
        .read_text(encoding="utf-8")
    )
    generated = SCENARIO_DIR / "generated"

    assert manifest["row_count"] == 1000
    assert manifest["label_counts"] == {"Benign": 900, "Malicious": 100}
    assert manifest["schema"]["mock_prob_present"] is False
    assert manifest["cve_counts"] == {"CVE-2025-24813": 13, "CVE-2024-47575": 7}
    assert manifest["projection_override_count"] > 0

    for day in range(1, 6):
        day_dir = generated / f"day{day:02d}"
        for name in ("organization", "assets", "policy", "cve_feed", "threat_feed"):
            assert (day_dir / f"{name}.yaml").exists()

    assert "CVE-2025-24813" not in _day_cves(1)
    assert "CVE-2025-24813" not in _day_cves(2)
    assert "CVE-2025-24813" in _day_cves(3)
    assert "CVE-2025-24813" in _day_cves(4)
    assert "CVE-2024-47575" not in _day_cves(4)
    assert "CVE-2024-47575" in _day_cves(5)


def test_dynamic_cve_runner_uses_day_specific_generated_sources(tmp_path: Path) -> None:
    base_config = yaml.safe_load(
        (ROOT / "config" / "settings.regional_care_dynamic_cve_xgb.yaml").read_text(
            encoding="utf-8"
        )
    )
    generated = SCENARIO_DIR / "generated"

    _validate_generated_sources(generated, expected_days=5)
    config = _dynamic_day_config(
        base_config=base_config,
        sqlite_path=tmp_path / "events.sqlite",
        generated_sources=generated,
        day_index=3,
        tier1_model="gemma4:e4b",
        ollama_url="http://host.docker.internal:11434",
        ollama_timeout=180.0,
        tier2_model="gemini-3-flash-preview",
        tier2_max_tokens=4096,
        tier2_temperature=0.7,
    )

    assert config["storage"]["enabled"] is True
    assert config["storage"]["sqlite_path"] == str(tmp_path / "events.sqlite")
    for name in SOURCE_NAMES:
        assert config["tier2"]["sources"][name]["enabled"] is True
        assert config["tier2"]["sources"][name]["path"] == str(
            generated / "day03" / f"{name}.yaml"
        )


def test_dynamic_cve_runner_reads_manifest_trace() -> None:
    trace = _load_manifest_by_flow_id(
        ROOT / "data" / "sample" / "regional_care_dynamic_cve_flows_xgb_manifest.json"
    )

    assert len(trace) == 1000
    assert trace["xgb-d03-attack-tomcat-lab-api-probe-007"]["cve_id"] == "CVE-2025-24813"
    assert trace["xgb-d05-attack-fortimanager-541-probe-169"]["cve_id"] == "CVE-2024-47575"


def _day_cves(day: int) -> set[str]:
    data = yaml.safe_load(
        (SCENARIO_DIR / "generated" / f"day{day:02d}" / "cve_feed.yaml")
        .read_text(encoding="utf-8")
    )
    return {
        str(item.get("cve_id"))
        for item in data.get("advisories", []) + data.get("cves", [])
        if item.get("cve_id")
    }
