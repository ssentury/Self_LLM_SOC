from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
import json
from pathlib import Path
import time
from typing import Any

from soc.config.settings import (
    PipelineSettings,
    apply_pipeline_overrides,
    load_pipeline_settings,
    validate_pipeline_settings,
)
from soc.context.watchlist import REVIEWABLE_MATCH_STRENGTHS
from soc.io import read_flows_csv
from soc.llm.provider import FakeLLMProvider, GeminiProvider, LLMProvider, OllamaProvider
from soc.ml.detector import DummyDetector, MLDetector, XGBoostDetector
from soc.models import Verdict, WatchlistMatch
from soc.realtime.service import (
    PreparedRealtimeFlow,
    RealtimeIngestService,
    Tier1RuntimeInfo,
    auto_alert_verdict,
    auto_dismiss_verdict,
    enrich_ml_after_route,
    event_from_verdict,
    queue_fallback_verdict,
)
from soc.report.renderer import HTMLRenderer
from soc.storage.sqlite import SQLiteEventStore


@dataclass(frozen=True)
class PendingTier1Job:
    index: int
    priority: tuple[float, float, int]
    enqueued_at: float
    prepared: PreparedRealtimeFlow
    match: WatchlistMatch


QueueItem = tuple[tuple[float, float, int], int, PendingTier1Job | None]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the mini LLM SOC real-time loop scaffold.")
    parser.add_argument("--config", default="config/settings.example.yaml")
    parser.add_argument("--input", help="Input flow CSV path.")
    parser.add_argument("--output", help="Report output directory.")
    parser.add_argument("--sqlite", dest="sqlite_path", help="SQLite event store path.")
    parser.add_argument("--no-storage", dest="storage_enabled", action="store_false", default=None)
    parser.add_argument("--detector", choices=["dummy", "xgboost"])
    parser.add_argument("--model")
    parser.add_argument("--metadata")
    parser.add_argument("--category-model")
    parser.add_argument("--category-metadata")
    parser.add_argument(
        "--thresholds",
    )
    parser.add_argument("--llm", choices=["fake", "ollama", "gemini"])
    parser.add_argument("--llm-model")
    parser.add_argument("--ollama-url")
    parser.add_argument("--ollama-timeout", type=float)
    parser.add_argument("--tier1-max-tokens", type=int)
    parser.add_argument("--tier1-retry-attempts", type=int)
    parser.add_argument("--tier1-retry-backoff-seconds", type=float)
    parser.add_argument("--tier1-mode", choices=["sequential", "queue"])
    parser.add_argument("--tier1-workers", type=int)
    parser.add_argument("--tier1-queue-max-size", type=int)
    parser.add_argument("--tier1-queue-timeout", type=float)
    parser.add_argument("--tier1-overflow-policy", choices=["fallback"])
    parser.add_argument(
        "--tier1-priority-policy",
        choices=["fifo", "watchlist_first"],
    )
    parser.add_argument("--tier1-max-calls-per-run", type=int)
    parser.add_argument("--watchlist")
    parser.add_argument("--brief")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    asyncio.run(_run(args))
    return 0


def _effective_args(cli_args: argparse.Namespace) -> argparse.Namespace:
    settings = load_pipeline_settings(cli_args.config)
    settings = apply_pipeline_overrides(settings, _override_values(cli_args))
    validate_pipeline_settings(settings)
    return _settings_to_namespace(settings)


def _override_values(cli_args: argparse.Namespace) -> dict[str, Any]:
    return {
        key: value
        for key, value in vars(cli_args).items()
        if key != "config" and value is not None
    }


def _settings_to_namespace(settings: PipelineSettings) -> argparse.Namespace:
    return argparse.Namespace(
        input=settings.runtime.input,
        output=settings.runtime.output,
        storage_enabled=settings.storage.enabled,
        sqlite_path=settings.storage.sqlite_path,
        detector=settings.detector.provider,
        model=settings.detector.model,
        metadata=settings.detector.metadata,
        category_model=settings.detector.category_model,
        category_metadata=settings.detector.category_metadata,
        thresholds=settings.detector.thresholds,
        llm=settings.tier1.llm.provider,
        llm_model=settings.tier1.llm.model,
        ollama_url=settings.tier1.llm.ollama_url,
        ollama_timeout=settings.tier1.llm.timeout_seconds,
        tier1_max_tokens=settings.tier1.llm.max_tokens,
        tier1_retry_attempts=settings.tier1.llm.retry_attempts,
        tier1_retry_backoff_seconds=settings.tier1.llm.retry_backoff_seconds,
        tier1_mode=settings.tier1.queue.mode,
        tier1_workers=settings.tier1.queue.workers,
        tier1_queue_max_size=settings.tier1.queue.max_size,
        tier1_queue_timeout=settings.tier1.queue.timeout_seconds,
        tier1_overflow_policy=settings.tier1.queue.overflow_policy,
        tier1_priority_policy=settings.tier1.queue.priority_policy,
        tier1_max_calls_per_run=settings.tier1.queue.max_calls_per_run,
        watchlist=settings.tier2.watchlist,
        brief=settings.tier2.brief,
        threshold_low=settings.routing.threshold_low,
        threshold_high=settings.routing.threshold_high,
        priority_1_llm_threshold=settings.routing.priority_1_llm_threshold,
    )


async def _run(args: argparse.Namespace) -> None:
    args = _effective_args(args)
    flows = read_flows_csv(args.input)
    detector = _build_detector(args)
    threshold_low, threshold_high = _load_thresholds(
        args.thresholds,
        default_low=args.threshold_low,
        default_high=args.threshold_high,
    )
    provider = _build_llm_provider(args)
    store = _build_event_store(args)
    renderer = HTMLRenderer()
    brief = _read_optional_text(args.brief)
    realtime = RealtimeIngestService.from_artifacts(
        detector=detector,
        provider=provider,
        store=store,
        watchlist_path=args.watchlist,
        brief_context=brief,
        threshold_low=threshold_low,
        threshold_high=threshold_high,
        priority_1_llm_threshold=args.priority_1_llm_threshold,
        tier1_runtime=Tier1RuntimeInfo(
            provider=args.llm,
            model_name=_tier1_model_name(args),
            max_tokens=args.tier1_max_tokens,
            retry_attempts=args.tier1_retry_attempts,
            retry_backoff_seconds=args.tier1_retry_backoff_seconds,
        ),
    )
    output_dir = Path(args.output)

    if args.tier1_mode == "queue":
        events, queue_stats = await _run_queue_mode(
            flows=flows,
            realtime=realtime,
            args=args,
        )
    else:
        events, queue_stats = await _run_sequential_mode(
            flows=flows,
            realtime=realtime,
            args=args,
        )

    for event in events:
        renderer.render_event(event, output_dir / f"{event['flow_id']}.html")

    renderer.render_summary(
        {"events": events, "tier1_queue": queue_stats},
        output_dir / "summary.html",
    )
    print(f"processed={len(events)} reports={output_dir}")


async def _run_sequential_mode(
    flows,
    realtime: RealtimeIngestService,
    args: argparse.Namespace,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    events: list[dict[str, Any]] = []
    previous_flows = []
    stats = _new_queue_stats(args)
    stats["tier1_mode"] = "sequential"

    for flow in flows:
        prepared = realtime.prepare_flow(flow, previous_flows)
        if realtime.store is not None:
            realtime.store.save_flow(prepared.flow)
            realtime.store.save_ml_result(prepared.flow.flow_id, prepared.ml)
            realtime.store.save_route_decision(prepared.flow.flow_id, prepared.route)

        if prepared.route.route == "tier1_llm":
            verdict = await realtime.judge_tier1(prepared)
            stats["tier1_calls"] += 1
            _record_llm_fallback_if_needed(stats, verdict)
            result = realtime.complete(prepared, verdict, tier1_path=True)
        else:
            result = realtime.complete(
                prepared,
                realtime.auto_verdict(prepared),
                tier1_path=False,
            )

        events.append(result.event)
        previous_flows.append(flow)

    return events, stats


async def _run_queue_mode(
    flows,
    realtime: RealtimeIngestService,
    args: argparse.Namespace,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    events: list[dict[str, Any] | None] = [None] * len(flows)
    queue: asyncio.PriorityQueue[QueueItem] = asyncio.PriorityQueue(
        maxsize=max(1, int(args.tier1_queue_max_size))
    )
    workers = max(1, int(args.tier1_workers))
    call_limit = int(args.tier1_max_calls_per_run)
    call_lock = asyncio.Lock()
    stats = _new_queue_stats(args)
    waits_ms: list[float] = []

    async def producer() -> None:
        previous_flows = []
        for index, flow in enumerate(flows):
            prepared = realtime.prepare_flow(flow, previous_flows)
            if realtime.store is not None:
                realtime.store.save_flow(prepared.flow)
                realtime.store.save_ml_result(prepared.flow.flow_id, prepared.ml)
                realtime.store.save_route_decision(prepared.flow.flow_id, prepared.route)

            if prepared.route.route in {"auto_dismiss", "auto_alert"}:
                result = realtime.complete(
                    prepared,
                    realtime.auto_verdict(prepared),
                    tier1_path=False,
                )
                events[index] = result.event
            else:
                job = PendingTier1Job(
                    index=index,
                    priority=_queue_priority(
                        index,
                        prepared.ml.prob,
                        prepared.match,
                        args.tier1_priority_policy,
                    ),
                    enqueued_at=time.perf_counter(),
                    prepared=prepared,
                    match=prepared.match,
                )
                try:
                    queue.put_nowait((job.priority, job.index, job))
                    stats["tier1_queued"] += 1
                except asyncio.QueueFull:
                    stats["tier1_overflow_count"] += 1
                    _record_queue_fallback(stats)
                    verdict = queue_fallback_verdict(
                        prepared.match,
                        "Tier 1 queue is full; overflow policy=fallback.",
                    )
                    result = realtime.complete(prepared, verdict, tier1_path=True)
                    events[index] = result.event

            previous_flows.append(flow)
            await asyncio.sleep(0)

        sentinel_priority = (float("inf"), float("inf"), 10**12)
        for worker_index in range(workers):
            await queue.put((sentinel_priority, worker_index, None))

    async def worker() -> None:
        while True:
            _, _, job = await queue.get()
            try:
                if job is None:
                    return

                wait_ms = (time.perf_counter() - job.enqueued_at) * 1000
                waits_ms.append(wait_ms)
                if wait_ms > args.tier1_queue_timeout * 1000:
                    stats["tier1_queue_timeouts"] += 1
                    _record_queue_fallback(stats)
                    verdict = queue_fallback_verdict(
                        job.match,
                        f"Tier 1 queue wait exceeded {args.tier1_queue_timeout:.1f}s.",
                    )
                else:
                    async with call_lock:
                        if call_limit > 0 and stats["tier1_calls"] >= call_limit:
                            stats["tier1_skipped_by_call_limit"] += 1
                            _record_queue_fallback(stats)
                            verdict = queue_fallback_verdict(
                                job.match,
                                f"Tier 1 max calls per run reached ({call_limit}).",
                            )
                        else:
                            stats["tier1_calls"] += 1
                            verdict = None

                    if verdict is None:
                        verdict = await realtime.judge_tier1(job.prepared)
                        _record_llm_fallback_if_needed(stats, verdict)

                result = realtime.complete(job.prepared, verdict, tier1_path=True)
                events[job.index] = result.event
            finally:
                queue.task_done()

    worker_tasks = [asyncio.create_task(worker()) for _ in range(workers)]
    await producer()
    await asyncio.gather(*worker_tasks)

    if waits_ms:
        stats["avg_wait_ms"] = sum(waits_ms) / len(waits_ms)
        stats["max_wait_ms"] = max(waits_ms)

    completed_events = [event for event in events if event is not None]
    return completed_events, stats


def _new_queue_stats(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "tier1_mode": args.tier1_mode,
        "tier1_workers": max(1, int(args.tier1_workers)),
        "tier1_queue_max_size": int(args.tier1_queue_max_size),
        "tier1_queue_timeout": float(args.tier1_queue_timeout),
        "tier1_overflow_policy": args.tier1_overflow_policy,
        "tier1_priority_policy": args.tier1_priority_policy,
        "tier1_max_calls_per_run": int(args.tier1_max_calls_per_run),
        "tier1_calls": 0,
        "tier1_queued": 0,
        "tier1_fallbacks": 0,
        "tier1_queue_fallbacks": 0,
        "tier1_llm_fallbacks": 0,
        "tier1_queue_timeouts": 0,
        "tier1_overflow_count": 0,
        "tier1_skipped_by_call_limit": 0,
        "avg_wait_ms": 0.0,
        "max_wait_ms": 0.0,
    }


def _record_queue_fallback(stats: dict[str, Any]) -> None:
    stats["tier1_fallbacks"] += 1
    stats["tier1_queue_fallbacks"] += 1


def _record_llm_fallback_if_needed(stats: dict[str, Any], verdict: Verdict) -> None:
    if verdict.fallback_source == "llm":
        stats["tier1_fallbacks"] += 1
        stats["tier1_llm_fallbacks"] += 1


_enrich_ml_after_route = enrich_ml_after_route


def _queue_priority(
    original_index: int,
    ml_prob: float,
    match: WatchlistMatch,
    priority_policy: str,
) -> tuple[float, float, int]:
    if priority_policy == "fifo":
        return (0.0, 0.0, original_index)

    watchlist_rank = (
        0.0
        if (
            match.matched
            and match.priority == "priority_1"
            and match.match_strength in REVIEWABLE_MATCH_STRENGTHS
            and match.trigger_matched
            and not match.context_only
        )
        else 1.0
    )
    return (watchlist_rank, -float(ml_prob), original_index)


def _queue_fallback_verdict(match: WatchlistMatch, reason: str) -> Verdict:
    return Verdict(
        verdict="uncertain",
        severity="medium",
        rationale_ko=f"Tier 1 LLM queue에서 자동 fallback 처리했습니다. 원인: {reason}",
        recommended_action_ko="큐 정책상 자동 Tier 1 판단이 완료되지 않았으므로 보안 담당자가 수동으로 확인하세요.",
        watchlist_matched=match.item_id,
        confidence=0.5,
        fallback_source="queue",
        fallback_reason=reason,
    )


def _auto_dismiss_verdict() -> Verdict:
    return Verdict(
        verdict="benign",
        severity="low",
        rationale_ko="ML 확률이 낮아 자동 기각했습니다.",
        recommended_action_ko="추가 조치 없이 모니터링합니다.",
        confidence=0.8,
    )


def _auto_alert_verdict(_ml) -> Verdict:
    hint_text = ""
    if _ml.category_hint != "not_evaluated" and _ml.category_confidence > 0:
        hint_text = (
            f" ML attack-family hint is {_ml.category_hint} "
            f"(confidence {_ml.category_confidence:.2f}); this is supporting evidence, "
            "not a final category label."
        )
    verdict = Verdict(
        verdict="alert",
        severity="high",
        rationale_ko="ML 확률이 높아 자동 경보로 분류했습니다.",
        recommended_action_ko="보안 담당자가 즉시 대상 자산과 출발지를 확인하세요.",
        confidence=0.8,
    )
    if hint_text:
        return replace(verdict, rationale_ko=verdict.rationale_ko + hint_text)
    return verdict


def _event_from_verdict(
    flow,
    route,
    ml,
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


_queue_fallback_verdict = queue_fallback_verdict
_auto_dismiss_verdict = auto_dismiss_verdict
_auto_alert_verdict = auto_alert_verdict
_event_from_verdict = event_from_verdict


def _build_detector(args: argparse.Namespace) -> MLDetector:
    if args.detector == "dummy":
        return DummyDetector()
    if args.detector == "xgboost":
        return XGBoostDetector(
            args.model,
            args.metadata,
            category_model_path=args.category_model,
            category_metadata_path=args.category_metadata,
        )
    raise ValueError(f"unsupported detector: {args.detector}")


def _build_llm_provider(args: argparse.Namespace) -> LLMProvider:
    if args.llm == "fake":
        return FakeLLMProvider()
    if args.llm == "ollama":
        return OllamaProvider(
            model=args.llm_model,
            base_url=args.ollama_url,
            timeout_seconds=args.ollama_timeout,
        )
    if args.llm == "gemini":
        return GeminiProvider(
            model=args.llm_model,
            timeout_seconds=args.ollama_timeout,
        )
    raise ValueError(f"unsupported LLM provider: {args.llm}")


def _build_event_store(args: argparse.Namespace) -> SQLiteEventStore | None:
    if not args.storage_enabled:
        return None
    store = SQLiteEventStore(args.sqlite_path)
    store.initialize()
    return store


def _tier1_model_name(args: argparse.Namespace) -> str:
    if args.llm == "fake":
        return "fake-llm"
    return str(args.llm_model)


def _load_thresholds(
    path: str | Path,
    default_low: float = 0.30,
    default_high: float = 0.95,
) -> tuple[float, float]:
    threshold_path = Path(path)
    if not threshold_path.exists():
        return default_low, default_high
    data = json.loads(threshold_path.read_text(encoding="utf-8"))
    return float(data["low_threshold"]), float(data["high_threshold"])


def _read_optional_text(path: str | Path) -> str:
    file_path = Path(path)
    if not file_path.exists():
        return ""
    return file_path.read_text(encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
