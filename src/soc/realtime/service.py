from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from soc.context.activity import summarize_source_activity, summarize_source_activity_from_store
from soc.context.watchlist import load_watchlist, match_watchlist
from soc.llm.provider import LLMProvider
from soc.llm.tier1 import judge_flow
from soc.ml.detector import MLDetector
from soc.ml.features import build_ml_feature_dict
from soc.models import Flow, MLResult, RouteDecision, Tier1Input, Verdict, WatchlistMatch
from soc.routing.router import route_flow
from soc.storage.sqlite import SQLiteEventStore


@dataclass(frozen=True)
class Tier1RuntimeInfo:
    provider: str
    model_name: str
    max_tokens: int = 4096
    retry_attempts: int = 1
    retry_backoff_seconds: float = 2.0


@dataclass(frozen=True)
class PreparedRealtimeFlow:
    flow: Flow
    ml: MLResult
    route: RouteDecision
    match: WatchlistMatch
    tier1_input: Tier1Input


@dataclass(frozen=True)
class RealtimeIngestResult:
    flow: Flow
    ml: MLResult
    route: RouteDecision
    match: WatchlistMatch
    verdict: Verdict
    tier1_path: bool
    event: dict[str, Any]


class RealtimeIngestService:
    """Reusable product boundary for processing one flow through the realtime loop."""

    def __init__(
        self,
        *,
        detector: MLDetector,
        provider: LLMProvider,
        store: SQLiteEventStore | None,
        watchlist: dict[str, Any],
        brief_context: str,
        threshold_low: float,
        threshold_high: float,
        priority_1_llm_threshold: float,
        tier1_runtime: Tier1RuntimeInfo,
    ) -> None:
        self.detector = detector
        self.provider = provider
        self.store = store
        self.watchlist = watchlist
        self.brief_context = brief_context
        self.threshold_low = threshold_low
        self.threshold_high = threshold_high
        self.priority_1_llm_threshold = priority_1_llm_threshold
        self.tier1_runtime = tier1_runtime
        self._previous_flows: list[Flow] = []

    @classmethod
    def from_artifacts(
        cls,
        *,
        detector: MLDetector,
        provider: LLMProvider,
        store: SQLiteEventStore | None,
        watchlist_path: str,
        brief_context: str,
        threshold_low: float,
        threshold_high: float,
        priority_1_llm_threshold: float,
        tier1_runtime: Tier1RuntimeInfo,
    ) -> RealtimeIngestService:
        return cls(
            detector=detector,
            provider=provider,
            store=store,
            watchlist=load_watchlist(watchlist_path),
            brief_context=brief_context,
            threshold_low=threshold_low,
            threshold_high=threshold_high,
            priority_1_llm_threshold=priority_1_llm_threshold,
            tier1_runtime=tier1_runtime,
        )

    def prepare_flow(
        self,
        flow: Flow,
        previous_flows: list[Flow] | None = None,
    ) -> PreparedRealtimeFlow:
        ml_features = build_ml_feature_dict(flow)
        ml = self.detector.predict(ml_features)
        activity = self._summarize_activity(flow, previous_flows)
        match = match_watchlist(
            flow,
            self.watchlist,
            ml_prob=ml.prob,
            source_activity=activity,
        )
        route = route_flow(
            ml,
            match,
            threshold_low=self.threshold_low,
            threshold_high=self.threshold_high,
            priority_1_llm_threshold=self.priority_1_llm_threshold,
        )
        ml = enrich_ml_after_route(self.detector, ml_features, ml, route.route)
        return PreparedRealtimeFlow(
            flow=flow,
            ml=ml,
            route=route,
            match=match,
            tier1_input=Tier1Input(
                flow=flow,
                ml=ml,
                source_activity=activity,
                watchlist_match=match,
                brief_context_excerpt=self.brief_context,
                route=route,
            ),
        )

    async def ingest_flow(
        self,
        flow: Flow,
        previous_flows: list[Flow] | None = None,
    ) -> RealtimeIngestResult:
        prepared = self.prepare_flow(flow, previous_flows)
        # Save early so GUI can show XGBoost routing immediately
        if self.store is not None:
            self.store.save_flow(prepared.flow)
            self.store.save_ml_result(prepared.flow.flow_id, prepared.ml)
            self.store.save_route_decision(prepared.flow.flow_id, prepared.route)
            
        return await self.process_prepared(prepared)

    async def process_prepared(self, prepared: PreparedRealtimeFlow) -> RealtimeIngestResult:
        if prepared.route.route == "tier1_llm":
            verdict = await self.judge_tier1(prepared)
            tier1_path = True
        else:
            verdict = self.auto_verdict(prepared)
            tier1_path = False
        return self.complete(prepared, verdict, tier1_path=tier1_path)

    async def judge_tier1(self, prepared: PreparedRealtimeFlow) -> Verdict:
        return await judge_flow(
            prepared.tier1_input,
            self.provider,
            max_tokens=self.tier1_runtime.max_tokens,
            retry_attempts=self.tier1_runtime.retry_attempts,
            retry_backoff_seconds=self.tier1_runtime.retry_backoff_seconds,
        )

    def auto_verdict(self, prepared: PreparedRealtimeFlow) -> Verdict:
        if prepared.route.route == "auto_dismiss":
            return auto_dismiss_verdict()
        if prepared.route.route == "auto_alert":
            return auto_alert_verdict(prepared.ml)
        raise ValueError(f"route requires Tier 1 verdict: {prepared.route.route}")

    def complete(
        self,
        prepared: PreparedRealtimeFlow,
        verdict: Verdict,
        *,
        tier1_path: bool,
    ) -> RealtimeIngestResult:
        self.save_result(prepared, verdict, tier1_path=tier1_path)
        self._previous_flows.append(prepared.flow)
        event = event_from_verdict(
            prepared.flow,
            prepared.route,
            prepared.ml,
            verdict,
            prepared.match,
        )
        return RealtimeIngestResult(
            flow=prepared.flow,
            ml=prepared.ml,
            route=prepared.route,
            match=prepared.match,
            verdict=verdict,
            tier1_path=tier1_path,
            event=event,
        )

    def save_result(
        self,
        prepared: PreparedRealtimeFlow,
        verdict: Verdict,
        *,
        tier1_path: bool,
    ) -> None:
        if self.store is None:
            return

        effective_verdict = replace(
            verdict,
            watchlist_matched=verdict.watchlist_matched or prepared.match.item_id,
        )
        self.store.save_verdict(prepared.flow.flow_id, effective_verdict)
        if tier1_path:
            self.store.save_tier1_call(
                flow_id=prepared.flow.flow_id,
                provider=self.tier1_runtime.provider,
                model_name=verdict.llm_model_name or self.tier1_runtime.model_name,
                latency_ms=verdict.llm_latency_ms,
                tokens_used=verdict.llm_tokens_used,
                prompt_tokens=verdict.llm_prompt_tokens,
                completion_tokens=verdict.llm_completion_tokens,
                success=verdict.fallback_source is None,
                fallback_reason=verdict.fallback_reason,
            )

    def _summarize_activity(
        self,
        flow: Flow,
        previous_flows: list[Flow] | None,
    ):
        if self.store is not None:
            return summarize_source_activity_from_store(self.store, flow)
        in_memory_flows = previous_flows if previous_flows is not None else self._previous_flows
        return summarize_source_activity(flow, in_memory_flows)


def enrich_ml_after_route(
    detector: MLDetector,
    ml_features: dict[str, Any],
    ml: MLResult,
    route: str,
) -> MLResult:
    if route == "auto_dismiss":
        return replace(
            ml,
            category_hint="not_evaluated",
            category_confidence=0.0,
            shap_top5=[],
        )

    category_hint, category_confidence = detector.predict_category_hint(ml_features)
    return replace(
        ml,
        category_hint=category_hint,
        category_confidence=category_confidence,
        shap_top5=detector.explain(ml_features) if route == "tier1_llm" else [],
    )


def queue_fallback_verdict(match: WatchlistMatch, reason: str) -> Verdict:
    return Verdict(
        verdict="uncertain",
        severity="medium",
        rationale_ko=f"Tier 1 LLM queue fallback was applied. Reason: {reason}",
        recommended_action_ko=(
            "Review this flow manually because automated Tier 1 processing did not complete."
        ),
        watchlist_matched=match.item_id,
        confidence=0.5,
        fallback_source="queue",
        fallback_reason=reason,
    )


def auto_dismiss_verdict() -> Verdict:
    return Verdict(
        verdict="benign",
        severity="low",
        rationale_ko="ML probability is low, so the flow was auto-dismissed.",
        recommended_action_ko="Continue monitoring; no immediate action is required.",
        confidence=0.8,
    )


def auto_alert_verdict(ml: MLResult) -> Verdict:
    hint_text = ""
    if ml.category_hint != "not_evaluated" and ml.category_confidence > 0:
        hint_text = (
            f" ML attack-family hint is {ml.category_hint} "
            f"(confidence {ml.category_confidence:.2f}); this is supporting evidence, "
            "not a final category label."
        )
    verdict = Verdict(
        verdict="alert",
        severity="high",
        rationale_ko="ML probability is high, so the flow was classified as an automatic alert.",
        recommended_action_ko="Review the affected asset and source immediately.",
        confidence=0.8,
    )
    if hint_text:
        return replace(verdict, rationale_ko=verdict.rationale_ko + hint_text)
    return verdict


def event_from_verdict(
    flow: Flow,
    route: RouteDecision,
    ml: MLResult,
    verdict: Verdict,
    match: WatchlistMatch,
) -> dict[str, Any]:
    return {
        "flow_id": flow.flow_id,
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "route": route.route,
        "route_reason": route.reason,
        "adjusted_by_watchlist": route.adjusted_by_watchlist,
        "effective_review_threshold": route.effective_review_threshold,
        "dynamic_threshold_applied": route.dynamic_threshold_applied,
        "dynamic_threshold_reason": route.dynamic_threshold_reason,
        "ml_prob": ml.prob,
        "category_hint": ml.category_hint,
        "category_confidence": ml.category_confidence,
        "shap_top5": ml.shap_top5,
        "verdict": verdict.verdict,
        "severity": verdict.severity,
        "rationale_ko": verdict.rationale_ko,
        "recommended_action_ko": verdict.recommended_action_ko,
        "watchlist_matched": verdict.watchlist_matched or match.item_id,
        "watchlist_priority": match.priority,
        "watchlist_reason": match.reason,
        "watchlist_conditions": match.matched_conditions,
        "watchlist_scope_conditions": match.scope_conditions,
        "watchlist_matched_trigger_hints": match.matched_trigger_hints,
        "watchlist_unmatched_trigger_hints": match.unmatched_trigger_hints,
        "watchlist_matched_benign_hints": match.matched_benign_hints,
        "watchlist_trigger_completeness": match.trigger_completeness,
        "watchlist_match_strength": match.match_strength,
        "watchlist_scope_match": match.scope_matched,
        "watchlist_trigger_match": match.trigger_matched,
        "watchlist_context_only": match.context_only,
        "watchlist_linter_warnings": match.linter_warnings,
        "fallback_source": verdict.fallback_source,
        "fallback_reason": verdict.fallback_reason,
    }
