from soc.models import MLResult, WatchlistMatch
from soc.routing.router import route_flow


def test_router_auto_dismisses_low_probability() -> None:
    decision = route_flow(MLResult(0.1, "mock", 0.5), WatchlistMatch(False))

    assert decision.route == "auto_dismiss"


def test_router_auto_alerts_high_probability() -> None:
    decision = route_flow(MLResult(0.99, "mock", 0.5), WatchlistMatch(False))

    assert decision.route == "auto_alert"


def test_router_sends_priority_1_match_to_tier1() -> None:
    decision = route_flow(
        MLResult(0.25, "mock", 0.5),
        WatchlistMatch(
            True,
            priority="priority_1",
            item_id="P1",
            match_strength="threat_source",
            trigger_matched=True,
        ),
    )

    assert decision.route == "tier1_llm"
    assert decision.adjusted_by_watchlist is True


def test_router_does_not_lower_threshold_for_asset_only_watchlist_match() -> None:
    decision = route_flow(
        MLResult(0.25, "mock", 0.5),
        WatchlistMatch(
            True,
            priority="priority_1",
            item_id="P1",
            match_strength="asset_only",
            scope_matched=True,
        ),
    )

    assert decision.route == "auto_dismiss"
    assert decision.adjusted_by_watchlist is False


def test_router_applies_dynamic_review_threshold_for_strong_trigger() -> None:
    decision = route_flow(
        MLResult(0.12, "mock", 0.5),
        WatchlistMatch(
            True,
            priority="priority_1",
            item_id="P1",
            match_strength="threat_source",
            trigger_matched=True,
            routing_policy={
                "review_threshold": 0.10,
                "max_threshold_drop": 0.20,
                "action": "tier1_llm",
                "reason": "source-backed low-score review",
            },
        ),
    )

    assert decision.route == "tier1_llm"
    assert decision.adjusted_by_watchlist is True
    assert decision.dynamic_threshold_applied is True
    assert decision.effective_review_threshold == 0.10
    assert decision.dynamic_threshold_reason == "source-backed low-score review"


def test_router_applies_default_behavioral_review_threshold_without_policy() -> None:
    decision = route_flow(
        MLResult(0.13, "mock", 0.5),
        WatchlistMatch(
            True,
            priority="priority_1",
            item_id="P1-egress",
            match_strength="behavioral_review",
            trigger_matched=True,
        ),
    )

    assert decision.route == "tier1_llm"
    assert decision.adjusted_by_watchlist is True
    assert decision.dynamic_threshold_applied is True
    assert decision.effective_review_threshold == 0.12


def test_router_applies_default_critical_forbidden_floor() -> None:
    decision = route_flow(
        MLResult(0.041, "mock", 0.5),
        WatchlistMatch(
            True,
            priority="priority_1",
            item_id="P1-metadata",
            match_strength="critical_forbidden",
            trigger_matched=True,
        ),
    )

    assert decision.route == "tier1_llm"
    assert decision.dynamic_threshold_applied is True
    assert decision.effective_review_threshold == 0.04


def test_router_keeps_auto_dismiss_below_dynamic_review_threshold() -> None:
    decision = route_flow(
        MLResult(0.04, "mock", 0.5),
        WatchlistMatch(
            True,
            priority="priority_1",
            item_id="P1",
            match_strength="threat_source",
            trigger_matched=True,
            routing_policy={"review_threshold": 0.10, "action": "tier1_llm"},
        ),
    )

    assert decision.route == "auto_dismiss"
    assert decision.dynamic_threshold_applied is False


def test_router_ignores_dynamic_threshold_for_context_only_match() -> None:
    decision = route_flow(
        MLResult(0.12, "mock", 0.5),
        WatchlistMatch(
            True,
            priority="priority_1",
            item_id="P1",
            match_strength="asset_service",
            trigger_matched=False,
            context_only=True,
            routing_policy={"review_threshold": 0.10, "action": "tier1_llm"},
        ),
    )

    assert decision.route == "auto_dismiss"
    assert decision.dynamic_threshold_applied is False
    assert decision.effective_review_threshold == 0.20


def test_router_keeps_auto_alert_above_high_threshold() -> None:
    decision = route_flow(
        MLResult(0.99, "mock", 0.5),
        WatchlistMatch(
            True,
            priority="priority_1",
            item_id="P1",
            match_strength="threat_source",
            trigger_matched=True,
            routing_policy={"review_threshold": 0.10, "action": "tier1_llm"},
        ),
    )

    assert decision.route == "auto_alert"
    assert decision.dynamic_threshold_applied is False
