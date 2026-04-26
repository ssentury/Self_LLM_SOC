from __future__ import annotations

from soc.models import MLResult, RouteDecision, WatchlistMatch


def route_flow(
    ml: MLResult,
    watchlist_match: WatchlistMatch,
    threshold_low: float = 0.30,
    threshold_high: float = 0.95,
    priority_1_llm_threshold: float = 0.20,
) -> RouteDecision:
    if ml.prob > threshold_high:
        return RouteDecision(
            route="auto_alert",
            reason=f"ML probability {ml.prob:.2f} is above alert threshold.",
            threshold_low=threshold_low,
            threshold_high=threshold_high,
            adjusted_by_watchlist=False,
            ml_prob=ml.prob,
        )

    p1_adjusted = (
        watchlist_match.matched
        and watchlist_match.priority == "priority_1"
        and ml.prob >= priority_1_llm_threshold
    )
    if p1_adjusted:
        return RouteDecision(
            route="tier1_llm",
            reason="Priority 1 watchlist match lowered the Tier 1 review threshold.",
            threshold_low=threshold_low,
            threshold_high=threshold_high,
            adjusted_by_watchlist=True,
            ml_prob=ml.prob,
        )

    if ml.prob < threshold_low:
        return RouteDecision(
            route="auto_dismiss",
            reason=f"ML probability {ml.prob:.2f} is below dismiss threshold.",
            threshold_low=threshold_low,
            threshold_high=threshold_high,
            adjusted_by_watchlist=False,
            ml_prob=ml.prob,
        )

    return RouteDecision(
        route="tier1_llm",
        reason="ML probability is in the review band.",
        threshold_low=threshold_low,
        threshold_high=threshold_high,
        adjusted_by_watchlist=False,
        ml_prob=ml.prob,
    )
