from pathlib import Path

import pytest

from soc.demo.flow_injector import (
    filter_flows_by_day,
    flow_to_payload,
    inject_flows,
    normalize_flow_endpoint,
    resolve_source_csv,
)
from soc.models import Flow


def test_normalize_flow_endpoint_accepts_base_or_endpoint() -> None:
    assert normalize_flow_endpoint("http://127.0.0.1:8080") == "http://127.0.0.1:8080/api/flows"
    assert (
        normalize_flow_endpoint("http://127.0.0.1:8080/api")
        == "http://127.0.0.1:8080/api/flows"
    )
    assert (
        normalize_flow_endpoint("http://127.0.0.1:8080/api/flows?x=1")
        == "http://127.0.0.1:8080/api/flows"
    )


def test_filter_flows_by_day_matches_flow_id_token() -> None:
    flows = [
        _flow("xgb-d01-benign-001"),
        _flow("xgb-d02-alert-001"),
    ]

    assert [flow.flow_id for flow in filter_flows_by_day(flows, "day02")] == [
        "xgb-d02-alert-001"
    ]


def test_filter_flows_by_day_rejects_empty_match() -> None:
    with pytest.raises(ValueError, match="no flows matched"):
        filter_flows_by_day([_flow("xgb-d01-benign-001")], "day05")


def test_inject_flows_posts_payloads_in_order_without_sleep(tmp_path: Path) -> None:
    sent: list[dict] = []

    def sender(url, payload, timeout):
        sent.append({"url": url, "payload": payload, "timeout": timeout})
        return {"flow_id": payload["flow_id"]}

    summary = inject_flows(
        flows=[_flow("f1"), _flow("f2")],
        source_path=tmp_path / "flows.csv",
        target_url="http://api.local/api/flows",
        interval_seconds=0,
        timeout_seconds=7,
        dry_run=False,
        continue_on_error=False,
        sender=sender,
    )

    assert summary.attempted == 2
    assert summary.succeeded == 2
    assert summary.failed == 0
    assert [item["payload"]["flow_id"] for item in sent] == ["f1", "f2"]
    assert sent[0]["timeout"] == 7


def test_inject_flows_stops_on_first_error_by_default(tmp_path: Path) -> None:
    def sender(url, payload, timeout):
        raise RuntimeError("boom")

    summary = inject_flows(
        flows=[_flow("f1"), _flow("f2")],
        source_path=tmp_path / "flows.csv",
        target_url="http://api.local/api/flows",
        interval_seconds=0,
        timeout_seconds=7,
        dry_run=False,
        continue_on_error=False,
        sender=sender,
    )

    assert summary.attempted == 1
    assert summary.succeeded == 0
    assert summary.failed == 1
    assert summary.flows[0].flow_id == "f1"


def test_flow_to_payload_keeps_features_separate() -> None:
    payload = flow_to_payload(_flow("f1", features={"mock_prob": "0.95"}))

    assert payload["flow_id"] == "f1"
    assert payload["src_ip"] == "10.0.0.1"
    assert payload["features"] == {"mock_prob": "0.95"}


def test_resolve_source_csv_rejects_missing_input(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        resolve_source_csv(tmp_path / "missing.csv", "sample")


def _flow(flow_id: str, features=None) -> Flow:
    return Flow(
        flow_id=flow_id,
        start_ms=1,
        end_ms=2,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=12345,
        dst_port=443,
        protocol="6",
        features=features or {},
        raw_label="1",
        raw_attack="Test",
    )

