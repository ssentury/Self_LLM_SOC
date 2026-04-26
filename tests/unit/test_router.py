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
        WatchlistMatch(True, priority="priority_1", item_id="P1"),
    )

    assert decision.route == "tier1_llm"
    assert decision.adjusted_by_watchlist is True
