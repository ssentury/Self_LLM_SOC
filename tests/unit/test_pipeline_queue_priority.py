import asyncio
from types import SimpleNamespace

from soc.cli.pipeline import _queue_priority, _run_queue_mode, _run_sequential_mode
from soc.models import Flow, MLResult, RouteDecision, Verdict, WatchlistMatch
from soc.realtime.service import PreparedRealtimeFlow


def test_queue_priority_promotes_middle_strength_watchlist_review() -> None:
    priority = _queue_priority(
        3,
        0.13,
        WatchlistMatch(
            matched=True,
            priority="priority_1",
            match_strength="behavioral_review",
            trigger_matched=True,
        ),
        "watchlist_first",
    )

    assert priority == (0.0, -0.13, 3)


def test_queue_priority_promotes_critical_forbidden_watchlist_review() -> None:
    priority = _queue_priority(
        4,
        0.05,
        WatchlistMatch(
            matched=True,
            priority="priority_1",
            match_strength="critical_forbidden",
            trigger_matched=True,
        ),
        "watchlist_first",
    )

    assert priority == (0.0, -0.05, 4)


def test_queue_priority_does_not_promote_context_only_match() -> None:
    priority = _queue_priority(
        5,
        0.22,
        WatchlistMatch(
            matched=True,
            priority="priority_1",
            match_strength="behavioral_review",
            trigger_matched=True,
            context_only=True,
        ),
        "watchlist_first",
    )

    assert priority == (1.0, -0.22, 5)


def test_queue_priority_does_not_promote_scope_only_match() -> None:
    priority = _queue_priority(
        6,
        0.25,
        WatchlistMatch(
            matched=True,
            priority="priority_1",
            match_strength="asset_service",
            trigger_matched=False,
        ),
        "watchlist_first",
    )

    assert priority == (1.0, -0.25, 6)


def test_queue_mode_applies_verdict_floor_before_completion() -> None:
    events, _stats = asyncio.run(
        _run_queue_mode(
            [_flow("queue-floor")],
            _LowSeverityRealtime(),
            _args("queue"),
        )
    )

    assert events[0]["severity"] == "medium"


def test_sequential_mode_applies_verdict_floor_before_completion() -> None:
    events, _stats = asyncio.run(
        _run_sequential_mode(
            [_flow("sequential-floor")],
            _LowSeverityRealtime(),
            _args("sequential"),
        )
    )

    assert events[0]["severity"] == "medium"


class _LowSeverityRealtime:
    store = None

    def prepare_flow(self, flow: Flow, _previous_flows=None) -> PreparedRealtimeFlow:
        return PreparedRealtimeFlow(
            flow=flow,
            ml=MLResult(prob=0.12, category_hint="not_evaluated", category_confidence=0.0),
            route=RouteDecision(
                route="tier1_llm",
                reason="review",
                threshold_low=0.30,
                threshold_high=0.95,
                adjusted_by_watchlist=True,
                ml_prob=0.12,
            ),
            match=WatchlistMatch(
                matched=True,
                priority="priority_1",
                item_id="P1-dns",
                match_strength="behavioral_review",
                trigger_matched=True,
            ),
            tier1_input=None,  # type: ignore[arg-type]
        )

    async def judge_tier1(self, _prepared: PreparedRealtimeFlow) -> Verdict:
        return Verdict(
            verdict="uncertain",
            severity="low",
            rationale_ko="Needs review.",
            recommended_action_ko="Check source activity.",
        )

    def auto_verdict(self, _prepared: PreparedRealtimeFlow) -> Verdict:
        raise AssertionError("test flow should go through Tier 1")

    def complete(
        self,
        _prepared: PreparedRealtimeFlow,
        verdict: Verdict,
        *,
        tier1_path: bool,
    ) -> SimpleNamespace:
        return SimpleNamespace(
            event={
                "severity": verdict.severity,
                "verdict": verdict.verdict,
                "tier1_path": tier1_path,
            }
        )


def _args(mode: str) -> SimpleNamespace:
    return SimpleNamespace(
        tier1_mode=mode,
        tier1_workers=1,
        tier1_queue_max_size=10,
        tier1_queue_timeout=60.0,
        tier1_overflow_policy="fallback",
        tier1_priority_policy="watchlist_first",
        tier1_max_calls_per_run=0,
    )


def _flow(flow_id: str) -> Flow:
    return Flow(
        flow_id=flow_id,
        start_ms=1,
        end_ms=2,
        src_ip="10.0.0.8",
        dst_ip="172.31.69.28",
        src_port=40000,
        dst_port=443,
        protocol="6",
        features={"mock_prob": "0.12"},
    )
