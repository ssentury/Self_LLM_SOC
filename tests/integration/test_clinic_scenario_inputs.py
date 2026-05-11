from collections import Counter
from datetime import datetime, timedelta, timezone

from soc.io import read_flows_csv
from soc.ml.features import binary_feature_contract, build_ml_feature_dict
from soc.tier2.batch import _load_config
from soc.tier2.input_collectors import Tier2InputCollector


def test_clinic_scenario_inputs_are_connected() -> None:
    config = _load_config("config/settings.clinic_scenario.yaml")

    snapshots = Tier2InputCollector(config).collect()
    statuses = {snapshot.name: snapshot.status for snapshot in snapshots}

    assert statuses["organization"] == "used"
    assert statuses["assets"] == "used"
    assert statuses["policy"] == "used"
    assert statuses["cve_feed"] == "used"
    assert statuses["threat_feed"] == "used"


def test_clinic_scenario_flow_set_has_expected_shape() -> None:
    flows = read_flows_csv("data/sample/clinic_telehealth_flows.csv")
    kst = timezone(timedelta(hours=9))

    assert len(flows) == 300
    assert sum(1 for flow in flows if flow.raw_label == "Malicious") == 30
    assert sum(1 for flow in flows if flow.raw_label == "Benign") == 270
    assert all("mock_prob" in flow.features for flow in flows)

    days = Counter(
        datetime.fromtimestamp(flow.start_ms / 1000, timezone.utc)
        .astimezone(kst)
        .date()
        for flow in flows
        if flow.start_ms is not None
    )
    assert sorted(days.values()) == [100, 100, 100]

    attacks = [flow for flow in flows if flow.raw_label == "Malicious"]
    obvious_attacks = [
        flow for flow in attacks if float(flow.features["mock_prob"]) > 0.95
    ]
    contextual_attacks = [
        flow
        for flow in attacks
        if 0.30 <= float(flow.features["mock_prob"]) <= 0.95
    ]
    assert len(obvious_attacks) == 15
    assert len(contextual_attacks) == 15


def test_clinic_xgb_flow_set_has_model_feature_contract() -> None:
    flows = read_flows_csv("data/sample/clinic_telehealth_flows_xgb.csv")
    feature_order = binary_feature_contract().feature_order
    kst = timezone(timedelta(hours=9))

    assert len(flows) == 300
    assert sum(1 for flow in flows if flow.raw_label == "Malicious") == 30
    assert sum(1 for flow in flows if flow.raw_label == "Benign") == 270
    assert all("mock_prob" not in flow.features for flow in flows)

    for flow in flows:
        features = build_ml_feature_dict(flow)
        assert all(feature in features for feature in feature_order)
        for feature in feature_order:
            float(features[feature])

    days = Counter(
        datetime.fromtimestamp(flow.start_ms / 1000, timezone.utc)
        .astimezone(kst)
        .date()
        for flow in flows
        if flow.start_ms is not None
    )
    assert sorted(days.values()) == [100, 100, 100]

    attacks = Counter(flow.raw_attack for flow in flows if flow.raw_label == "Malicious")
    assert attacks["Brute_Force_-Web"] == 6
    assert attacks["SQL_Injection"] == 6
    assert attacks["SSH-Bruteforce"] == 3
    assert attacks["Infilteration"] == 12
    assert attacks["DDOS_attack-HOIC"] == 3
