from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from soc.models import Flow, MLResult, RouteDecision, Verdict
from soc.storage.sqlite import SQLiteEventStore
from soc.summary.daily import build_daily_summary, run_daily_summary


def test_daily_summary_uses_local_flow_day_and_writes_latest_files(tmp_path: Path) -> None:
    db_path = tmp_path / "soc_events.sqlite"
    output_dir = tmp_path / "daily_summaries"
    store = SQLiteEventStore(db_path)
    store.initialize()
    _save_event(
        store,
        flow_id="dismiss-day",
        local_time="2026-05-06T00:05:00+09:00",
        route="auto_dismiss",
        verdict="benign",
        severity="low",
        ml_prob=0.02,
    )
    _save_event(
        store,
        flow_id="alert-day",
        local_time="2026-05-06T23:55:00+09:00",
        route="tier1_llm",
        verdict="alert",
        severity="high",
        ml_prob=0.66,
        watchlist="P1-demo",
        tier1_call=True,
    )
    _save_event(
        store,
        flow_id="other-day",
        local_time="2026-05-07T00:01:00+09:00",
        route="auto_alert",
        verdict="alert",
        severity="high",
        ml_prob=0.99,
    )

    summary = run_daily_summary(
        db_path,
        output_dir,
        summary_date="2026-05-06",
        timezone_name="Asia/Seoul",
    )

    assert summary["flow_count"] == 2
    assert summary["route_counts"] == {"auto_dismiss": 1, "tier1_llm": 1}
    assert summary["verdict_counts"] == {"alert": 1, "benign": 1}
    assert summary["watchlist_hit_count"] == 1
    assert summary["tier1_calls"]["total"] == 1
    assert summary["top_alerts"][0]["flow_id"] == "alert-day"
    assert (output_dir / "summary_2026-05-06.json").exists()
    assert (output_dir / "summary_2026-05-06.md").exists()
    assert (output_dir / "latest.json").exists()
    assert "Daily Easy Summary - 2026-05-06" in (output_dir / "latest.md").read_text(
        encoding="utf-8"
    )


def test_daily_summary_marks_empty_day_quiet(tmp_path: Path) -> None:
    db_path = tmp_path / "soc_events.sqlite"
    SQLiteEventStore(db_path).initialize()

    summary = build_daily_summary(db_path, summary_date="2026-05-06")

    assert summary["flow_count"] == 0
    assert summary["risk_level"] == "quiet"
    assert "저장된 realtime flow 결과가 없습니다" in summary["easy_summary_ko"]


def _save_event(
    store: SQLiteEventStore,
    *,
    flow_id: str,
    local_time: str,
    route: str,
    verdict: str,
    severity: str,
    ml_prob: float,
    watchlist: str | None = None,
    tier1_call: bool = False,
) -> None:
    timestamp = datetime.fromisoformat(local_time).astimezone(ZoneInfo("UTC"))
    flow = Flow(
        flow_id=flow_id,
        start_ms=int(timestamp.timestamp() * 1000),
        end_ms=int(timestamp.timestamp() * 1000) + 1000,
        src_ip="198.51.100.10",
        dst_ip="203.0.113.10",
        src_port=54000,
        dst_port=443,
        protocol="6",
    )
    ml = MLResult(
        prob=ml_prob,
        category_hint="demo",
        category_confidence=0.5,
    )
    decision = RouteDecision(
        route=route,
        reason="test",
        threshold_low=0.30,
        threshold_high=0.95,
        adjusted_by_watchlist=watchlist is not None,
        ml_prob=ml_prob,
    )
    result = Verdict(
        verdict=verdict,
        severity=severity,
        rationale_ko="테스트 근거",
        recommended_action_ko="테스트 조치",
        watchlist_matched=watchlist,
    )
    store.save_flow(flow)
    store.save_ml_result(flow.flow_id, ml)
    store.save_route_decision(flow.flow_id, decision)
    store.save_verdict(flow.flow_id, result)
    if tier1_call:
        store.save_tier1_call(
            flow_id=flow.flow_id,
            provider="fake",
            model_name="fake-llm",
            latency_ms=12.0,
            tokens_used=25,
        )
