from __future__ import annotations

from soc.context.watchlist import REVIEWABLE_MATCH_STRENGTHS
from soc.models import MLResult, RouteDecision, WatchlistMatch


_DEFAULT_REVIEW_THRESHOLDS = {
    "review_candidate": 0.20,
    "behavioral_review": 0.12,
    "behavior": 0.12,
    "threat_source": 0.08,
    "policy_violation": 0.08,
    "critical_forbidden": 0.04,
}
_MIN_DYNAMIC_REVIEW_THRESHOLD = 0.04


def route_flow(
    ml: MLResult,
    watchlist_match: WatchlistMatch,
    threshold_low: float = 0.30,
    threshold_high: float = 0.95,
    priority_1_llm_threshold: float = 0.20,
) -> RouteDecision:
    review_threshold, dynamic_reason = _effective_review_threshold(
        watchlist_match,
        threshold_low=threshold_low,
        default_review_threshold=priority_1_llm_threshold,
    )
    if ml.prob > threshold_high:
        return RouteDecision(
            route="auto_alert",
            reason=f"ML probability {ml.prob:.2f} is above alert threshold.",
            threshold_low=threshold_low,
            threshold_high=threshold_high,
            adjusted_by_watchlist=False,
            ml_prob=ml.prob,
            effective_review_threshold=review_threshold,
        )

    if _is_critical_forbidden_force_review(watchlist_match):
        return RouteDecision(
            route="tier1_llm",
            reason=(
                "Priority 1 critical-forbidden watchlist trigger bypassed the ML "
                "dismiss floor for Tier 1 review."
            ),
            threshold_low=threshold_low,
            threshold_high=threshold_high,
            adjusted_by_watchlist=True,
            ml_prob=ml.prob,
            effective_review_threshold=0.0,
            dynamic_threshold_applied=ml.prob < priority_1_llm_threshold,
            dynamic_threshold_reason=(
                "Critical-forbidden Tier 2 trigger is a hard policy/security condition."
            ),
        )

    p1_adjusted = (
        watchlist_match.matched
        and watchlist_match.priority == "priority_1"
        and watchlist_match.match_strength in REVIEWABLE_MATCH_STRENGTHS
        and watchlist_match.trigger_matched
        and watchlist_match.trigger_completeness in {"none", "required_met", "strong"}
        and not watchlist_match.context_only
        and ml.prob >= review_threshold
    )
    if p1_adjusted:
        dynamic_applied = dynamic_reason is not None and ml.prob < priority_1_llm_threshold
        return RouteDecision(
            route="tier1_llm",
            reason=(
                "Priority 1 watchlist trigger match met the Tier 1 review threshold "
                f"{review_threshold:.2f} (match_strength={watchlist_match.match_strength})."
            ),
            threshold_low=threshold_low,
            threshold_high=threshold_high,
            adjusted_by_watchlist=True,
            ml_prob=ml.prob,
            effective_review_threshold=review_threshold,
            dynamic_threshold_applied=dynamic_applied,
            dynamic_threshold_reason=dynamic_reason if dynamic_applied else None,
        )

    if ml.prob < threshold_low:
        return RouteDecision(
            route="auto_dismiss",
            reason=f"ML probability {ml.prob:.2f} is below dismiss threshold.",
            threshold_low=threshold_low,
            threshold_high=threshold_high,
            adjusted_by_watchlist=False,
            ml_prob=ml.prob,
            effective_review_threshold=review_threshold,
        )

    return RouteDecision(
        route="tier1_llm",
        reason="ML probability is in the review band.",
        threshold_low=threshold_low,
        threshold_high=threshold_high,
        adjusted_by_watchlist=False,
        ml_prob=ml.prob,
        effective_review_threshold=review_threshold,
    )


def _effective_review_threshold(
    watchlist_match: WatchlistMatch,
    *,
    threshold_low: float,
    default_review_threshold: float,
) -> tuple[float, str | None]:
    if not _can_apply_watchlist_review_threshold(watchlist_match):
        return default_review_threshold, None

    strength_threshold = _DEFAULT_REVIEW_THRESHOLDS.get(
        watchlist_match.match_strength,
        default_review_threshold,
    )
    strength_threshold = max(_MIN_DYNAMIC_REVIEW_THRESHOLD, min(strength_threshold, threshold_low))

    policy = watchlist_match.routing_policy or {}
    if policy and policy.get("action") != "tier1_llm":
        return _threshold_with_reason(
            strength_threshold,
            default_review_threshold,
            watchlist_match.match_strength,
            policy_reason=None,
        )

    review_threshold = None
    if policy:
        try:
            review_threshold = float(policy.get("review_threshold"))
        except (TypeError, ValueError):
            review_threshold = None

    if review_threshold is None:
        return _threshold_with_reason(
            strength_threshold,
            default_review_threshold,
            watchlist_match.match_strength,
            policy_reason=None,
        )

    if not (_MIN_DYNAMIC_REVIEW_THRESHOLD <= review_threshold <= threshold_low):
        review_threshold = strength_threshold

    max_drop = _optional_float(policy.get("max_threshold_drop"))
    if max_drop is not None and default_review_threshold - review_threshold > max_drop:
        review_threshold = strength_threshold

    if review_threshold >= default_review_threshold:
        return default_review_threshold, None

    reason = str(policy.get("reason") or "Tier 2 dynamic review threshold.")
    return review_threshold, reason


def _threshold_with_reason(
    review_threshold: float,
    default_review_threshold: float,
    match_strength: str,
    *,
    policy_reason: str | None,
) -> tuple[float, str | None]:
    if review_threshold >= default_review_threshold:
        return default_review_threshold, None
    reason = policy_reason or f"Default Tier 2 review threshold for {match_strength} match."
    return review_threshold, reason


def _can_apply_watchlist_review_threshold(match: WatchlistMatch) -> bool:
    return (
        match.matched
        and match.priority == "priority_1"
        and match.match_strength in REVIEWABLE_MATCH_STRENGTHS
        and match.trigger_matched
        and match.trigger_completeness in {"none", "required_met", "strong"}
        and not match.context_only
    )


def _is_critical_forbidden_force_review(match: WatchlistMatch) -> bool:
    return (
        _can_apply_watchlist_review_threshold(match)
        and match.match_strength == "critical_forbidden"
        and not match.matched_benign_hints
    )


def _optional_float(value) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
