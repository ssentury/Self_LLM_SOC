import asyncio
import sqlite3
from pathlib import Path

from soc.llm.provider import FakeLLMProvider
from soc.ml.detector import DummyDetector
from soc.models import Flow, MLResult, RouteDecision, Verdict, WatchlistMatch
from soc.realtime.service import (
    PreparedRealtimeFlow,
    RealtimeIngestService,
    Tier1RuntimeInfo,
    apply_verdict_floor,
)
from soc.storage.sqlite import SQLiteEventStore


def test_realtime_service_ingests_one_flow_and_persists_tier1_result(tmp_path: Path) -> None:
    db_path = tmp_path / "events.sqlite"
    store = SQLiteEventStore(db_path)
    store.initialize()
    service = _service(store)

    flow = _flow("tier1-1", mock_prob="0.50")

    result = asyncio.run(service.ingest_flow(flow))

    assert result.event["flow_id"] == "tier1-1"
    assert result.event["route"] == "tier1_llm"
    assert result.tier1_path is True
    with sqlite3.connect(db_path) as conn:
        counts = {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("flows", "ml_results", "route_decisions", "verdicts", "tier1_calls")
        }

    assert counts == {
        "flows": 1,
        "ml_results": 1,
        "route_decisions": 1,
        "verdicts": 1,
        "tier1_calls": 1,
    }


def test_realtime_service_uses_prior_flow_context_without_storage() -> None:
    service = _service(store=None)
    first = _flow("first", src_ip="10.0.0.8", dst_ip="172.31.69.28", mock_prob="0.10")
    second = _flow("second", src_ip="10.0.0.8", dst_ip="172.31.69.29", mock_prob="0.10")

    asyncio.run(service.ingest_flow(first))
    prepared = service.prepare_flow(second)

    assert prepared.tier1_input.source_activity.flow_count == 1
    assert prepared.tier1_input.source_activity.distinct_dst_count == 1
    assert prepared.tier1_input.source_activity.window_minutes == 180


def test_realtime_service_uses_configured_activity_window_with_storage(tmp_path: Path) -> None:
    db_path = tmp_path / "events.sqlite"
    store = SQLiteEventStore(db_path)
    store.initialize()
    service = _service(store, activity_window_minutes=180)

    first = _flow("first", src_ip="10.0.0.8", dst_ip="172.31.69.28", mock_prob="0.10")
    second = _flow(
        "second",
        src_ip="10.0.0.8",
        dst_ip="172.31.69.28",
        mock_prob="0.10",
        start_ms=90 * 60 * 1000,
    )

    asyncio.run(service.ingest_flow(first))
    prepared = service.prepare_flow(second)

    assert prepared.tier1_input.source_activity.flow_count == 1
    assert prepared.tier1_input.source_activity.same_src_same_dst_count == 1
    assert prepared.tier1_input.source_activity.same_src_same_dst_port_count == 1


def test_verdict_floor_raises_strong_uncertain_low_to_medium() -> None:
    prepared = PreparedRealtimeFlow(
        flow=_flow("floor", mock_prob="0.40"),
        ml=MLResult(prob=0.40, category_hint="not_evaluated", category_confidence=0.0),
        route=RouteDecision(
            route="tier1_llm",
            reason="review",
            threshold_low=0.30,
            threshold_high=0.95,
            adjusted_by_watchlist=True,
            ml_prob=0.40,
        ),
        match=WatchlistMatch(
            matched=True,
            priority="priority_1",
            item_id="P1-db",
            match_strength="policy_violation",
            trigger_matched=True,
        ),
        tier1_input=None,  # type: ignore[arg-type]
    )
    verdict = Verdict(
        verdict="uncertain",
        severity="low",
        rationale_ko="Needs review.",
        recommended_action_ko="Check source.",
    )

    adjusted = apply_verdict_floor(prepared, verdict)

    assert adjusted.verdict == "uncertain"
    assert adjusted.severity == "medium"


def _service(
    store: SQLiteEventStore | None,
    *,
    activity_window_minutes: int = 180,
) -> RealtimeIngestService:
    return RealtimeIngestService(
        detector=DummyDetector(),
        provider=FakeLLMProvider(),
        store=store,
        watchlist={},
        brief_context="",
        threshold_low=0.30,
        threshold_high=0.95,
        priority_1_llm_threshold=0.20,
        tier1_runtime=Tier1RuntimeInfo(provider="fake", model_name="fake-llm"),
        activity_window_minutes=activity_window_minutes,
    )


def _flow(
    flow_id: str,
    *,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "172.31.69.28",
    mock_prob: str,
    start_ms: int = 1,
) -> Flow:
    return Flow(
        flow_id=flow_id,
        start_ms=start_ms,
        end_ms=start_ms + 1,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=40000,
        dst_port=443,
        protocol="6",
        features={
            "IN_BYTES": "100",
            "IN_PKTS": "1",
            "OUT_BYTES": "100",
            "OUT_PKTS": "1",
            "mock_prob": mock_prob,
        },
        raw_label="1",
        raw_attack="Test",
    )
