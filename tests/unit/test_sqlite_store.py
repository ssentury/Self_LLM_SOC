import sqlite3
from pathlib import Path

from soc.models import Flow, MLResult, RouteDecision, Verdict
from soc.storage.sqlite import SQLiteEventStore


def test_initialize_creates_tables(tmp_path: Path) -> None:
    db_path = tmp_path / "events.sqlite"
    store = SQLiteEventStore(db_path)

    store.initialize()

    with sqlite3.connect(db_path) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }

    assert {
        "flows",
        "ml_results",
        "route_decisions",
        "verdicts",
        "tier1_calls",
    }.issubset(tables)


def test_save_flow_result_and_source_activity(tmp_path: Path) -> None:
    db_path = tmp_path / "events.sqlite"
    store = SQLiteEventStore(db_path)
    store.initialize()

    first = Flow(
        flow_id="flow-1",
        start_ms=1_000,
        end_ms=2_000,
        src_ip="10.0.0.1",
        dst_ip="192.168.0.10",
        src_port=40000,
        dst_port=443,
        protocol="6",
        features={"mock_prob": "0.5"},
        raw_label="1",
        raw_attack="Test",
    )
    second = Flow(
        flow_id="flow-2",
        start_ms=60_000,
        end_ms=61_000,
        src_ip="10.0.0.1",
        dst_ip="192.168.0.20",
        src_port=40001,
        dst_port=22,
        protocol="6",
    )
    ml = MLResult(prob=0.5, category_hint="mock", category_confidence=0.5)
    route = RouteDecision(
        route="tier1_llm",
        reason="review band",
        threshold_low=0.3,
        threshold_high=0.95,
        adjusted_by_watchlist=False,
        ml_prob=0.5,
    )
    verdict = Verdict(
        verdict="uncertain",
        severity="medium",
        rationale_ko="review",
        recommended_action_ko="check",
        confidence=0.6,
    )

    store.save_flow(first)
    store.save_ml_result(first.flow_id, ml)
    store.save_route_decision(first.flow_id, route)
    store.save_verdict(first.flow_id, verdict)
    store.save_tier1_call(first.flow_id, provider="fake", model_name="fake-llm")
    store.save_flow(second)

    with sqlite3.connect(db_path) as conn:
        flow_row = conn.execute(
            "SELECT flow_id, src_ip, features_json FROM flows WHERE flow_id = ?",
            ("flow-1",),
        ).fetchone()
        verdict_count = conn.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0]
        tier1_count = conn.execute("SELECT COUNT(*) FROM tier1_calls").fetchone()[0]

    assert flow_row[0] == "flow-1"
    assert flow_row[1] == "10.0.0.1"
    assert '"mock_prob": "0.5"' in flow_row[2]
    assert verdict_count == 1
    assert tier1_count == 1

    activity = store.summarize_source_activity(
        src_ip="10.0.0.1",
        before_time=60_000,
        window_minutes=10,
    )

    assert activity.flow_count == 1
    assert activity.distinct_dst_count == 1
    assert activity.top_dst_ports == [443]
    assert activity.recent_verdicts == ["uncertain"]
