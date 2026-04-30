from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass, replace
import json
from pathlib import Path
import time
from typing import Any

from soc.context.activity import summarize_source_activity
from soc.context.watchlist import load_watchlist, match_watchlist
from soc.io import read_flows_csv
from soc.llm.provider import FakeLLMProvider, LLMProvider, OllamaProvider
from soc.llm.tier1 import judge_flow
from soc.ml.detector import DummyDetector, MLDetector, XGBoostDetector
from soc.ml.features import build_ml_feature_dict
from soc.models import Tier1Input, Verdict, WatchlistMatch
from soc.report.renderer import HTMLRenderer
from soc.routing.router import route_flow


@dataclass(frozen=True)
class PendingTier1Job:
    index: int
    priority: tuple[float, float, int]
    enqueued_at: float
    tier1_input: Tier1Input
    match: WatchlistMatch


QueueItem = tuple[tuple[float, float, int], int, PendingTier1Job | None]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the mini LLM SOC real-time loop scaffold.")
    parser.add_argument("--input", required=True, help="Input flow CSV path.")
    parser.add_argument("--output", required=True, help="Report output directory.")
    parser.add_argument("--detector", default="dummy", choices=["dummy", "xgboost"])
    parser.add_argument("--model", default="output/models/xgb_binary_v1.json")
    parser.add_argument("--metadata", default="output/models/xgb_binary_v1_metadata.json")
    parser.add_argument(
        "--thresholds",
        default="output/models/xgb_binary_v1_thresholds_routing_default.json",
    )
    parser.add_argument("--llm", default="fake", choices=["fake", "ollama"])
    parser.add_argument("--llm-model", default="gemma4:e4b")
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    parser.add_argument("--ollama-timeout", type=float, default=180.0)
    parser.add_argument("--tier1-mode", default="sequential", choices=["sequential", "queue"])
    parser.add_argument("--tier1-workers", type=int, default=1)
    parser.add_argument("--tier1-queue-max-size", type=int, default=100)
    parser.add_argument("--tier1-queue-timeout", type=float, default=300.0)
    parser.add_argument("--tier1-overflow-policy", default="fallback", choices=["fallback"])
    parser.add_argument(
        "--tier1-priority-policy",
        default="watchlist_first",
        choices=["fifo", "watchlist_first"],
    )
    parser.add_argument("--tier1-max-calls-per-run", type=int, default=0)
    parser.add_argument("--watchlist", default="output/watchlists/latest.yaml")
    parser.add_argument("--brief", default="output/briefs/latest.md")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    asyncio.run(_run(args))
    return 0


async def _run(args: argparse.Namespace) -> None:
    flows = read_flows_csv(args.input)
    detector = _build_detector(args)
    threshold_low, threshold_high = _load_thresholds(args.thresholds)
    provider = _build_llm_provider(args)
    renderer = HTMLRenderer()
    watchlist = load_watchlist(args.watchlist)
    brief = _read_optional_text(args.brief)
    output_dir = Path(args.output)

    if args.tier1_mode == "queue":
        events, queue_stats = await _run_queue_mode(
            flows=flows,
            detector=detector,
            threshold_low=threshold_low,
            threshold_high=threshold_high,
            provider=provider,
            watchlist=watchlist,
            brief=brief,
            args=args,
        )
    else:
        events, queue_stats = await _run_sequential_mode(
            flows=flows,
            detector=detector,
            threshold_low=threshold_low,
            threshold_high=threshold_high,
            provider=provider,
            watchlist=watchlist,
            brief=brief,
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
    detector: MLDetector,
    threshold_low: float,
    threshold_high: float,
    provider: LLMProvider,
    watchlist: dict[str, Any],
    brief: str,
    args: argparse.Namespace,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    events: list[dict[str, Any]] = []
    previous_flows = []
    stats = _new_queue_stats(args)
    stats["tier1_mode"] = "sequential"

    for flow in flows:
        ml_features = build_ml_feature_dict(flow)
        ml = detector.predict(ml_features)
        match = match_watchlist(flow, watchlist)
        route = route_flow(
            ml,
            match,
            threshold_low=threshold_low,
            threshold_high=threshold_high,
        )
        if route.route == "tier1_llm":
            ml = replace(ml, shap_top5=detector.explain(ml_features))
        else:
            ml = replace(ml, shap_top5=[])
        activity = summarize_source_activity(flow, previous_flows)

        if route.route == "auto_dismiss":
            verdict = _auto_dismiss_verdict()
        elif route.route == "auto_alert":
            verdict = _auto_alert_verdict()
        else:
            verdict = await judge_flow(
                Tier1Input(
                    flow=flow,
                    ml=ml,
                    source_activity=activity,
                    watchlist_match=match,
                    brief_context_excerpt=brief,
                    route=route,
                ),
                provider,
            )
            stats["tier1_calls"] += 1
            _record_llm_fallback_if_needed(stats, verdict)

        events.append(_event_from_verdict(flow, route, ml, verdict, match))
        previous_flows.append(flow)

    return events, stats


async def _run_queue_mode(
    flows,
    detector: MLDetector,
    threshold_low: float,
    threshold_high: float,
    provider: LLMProvider,
    watchlist: dict[str, Any],
    brief: str,
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
            ml_features = build_ml_feature_dict(flow)
            ml = detector.predict(ml_features)
            match = match_watchlist(flow, watchlist)
            route = route_flow(
                ml,
                match,
                threshold_low=threshold_low,
                threshold_high=threshold_high,
            )
            if route.route == "tier1_llm":
                ml = replace(ml, shap_top5=detector.explain(ml_features))
            else:
                ml = replace(ml, shap_top5=[])
            activity = summarize_source_activity(flow, previous_flows)

            if route.route == "auto_dismiss":
                events[index] = _event_from_verdict(
                    flow,
                    route,
                    ml,
                    _auto_dismiss_verdict(),
                    match,
                )
            elif route.route == "auto_alert":
                events[index] = _event_from_verdict(
                    flow,
                    route,
                    ml,
                    _auto_alert_verdict(),
                    match,
                )
            else:
                job = PendingTier1Job(
                    index=index,
                    priority=_queue_priority(index, ml.prob, match, args.tier1_priority_policy),
                    enqueued_at=time.perf_counter(),
                    tier1_input=Tier1Input(
                        flow=flow,
                        ml=ml,
                        source_activity=activity,
                        watchlist_match=match,
                        brief_context_excerpt=brief,
                        route=route,
                    ),
                    match=match,
                )
                try:
                    queue.put_nowait((job.priority, job.index, job))
                    stats["tier1_queued"] += 1
                except asyncio.QueueFull:
                    stats["tier1_overflow_count"] += 1
                    _record_queue_fallback(stats)
                    verdict = _queue_fallback_verdict(
                        match,
                        "Tier 1 queue is full; overflow policy=fallback.",
                    )
                    events[index] = _event_from_verdict(flow, route, ml, verdict, match)

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
                    verdict = _queue_fallback_verdict(
                        job.match,
                        f"Tier 1 queue wait exceeded {args.tier1_queue_timeout:.1f}s.",
                    )
                else:
                    async with call_lock:
                        if call_limit > 0 and stats["tier1_calls"] >= call_limit:
                            stats["tier1_skipped_by_call_limit"] += 1
                            _record_queue_fallback(stats)
                            verdict = _queue_fallback_verdict(
                                job.match,
                                f"Tier 1 max calls per run reached ({call_limit}).",
                            )
                        else:
                            stats["tier1_calls"] += 1
                            verdict = None

                    if verdict is None:
                        verdict = await judge_flow(job.tier1_input, provider)
                        _record_llm_fallback_if_needed(stats, verdict)

                events[job.index] = _event_from_verdict(
                    job.tier1_input.flow,
                    job.tier1_input.route,
                    job.tier1_input.ml,
                    verdict,
                    job.match,
                )
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


def _queue_priority(
    original_index: int,
    ml_prob: float,
    match: WatchlistMatch,
    priority_policy: str,
) -> tuple[float, float, int]:
    if priority_policy == "fifo":
        return (0.0, 0.0, original_index)

    watchlist_rank = 0.0 if match.matched and match.priority == "priority_1" else 1.0
    return (watchlist_rank, -float(ml_prob), original_index)


def _queue_fallback_verdict(match: WatchlistMatch, reason: str) -> Verdict:
    return Verdict(
        verdict="uncertain",
        severity="medium",
        rationale_ko=f"Tier 1 LLM queue에서 자동 fallback 처리했습니다. 원인: {reason}",
        recommended_action_ko="큐 대기 또는 용량 제한 때문에 보안 담당자가 수동으로 확인하세요.",
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


def _auto_alert_verdict() -> Verdict:
    return Verdict(
        verdict="alert",
        severity="high",
        rationale_ko="ML 확률이 높아 자동 경보로 분류했습니다.",
        recommended_action_ko="보안 담당자가 즉시 대상 자산과 출발지를 확인하세요.",
        confidence=0.8,
    )


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
        "ml_prob": ml.prob,
        "shap_top5": ml.shap_top5,
        "verdict": verdict.verdict,
        "severity": verdict.severity,
        "rationale_ko": verdict.rationale_ko,
        "recommended_action_ko": verdict.recommended_action_ko,
        "watchlist_matched": verdict.watchlist_matched or match.item_id,
        "fallback_source": verdict.fallback_source,
        "fallback_reason": verdict.fallback_reason,
    }


def _build_detector(args: argparse.Namespace) -> MLDetector:
    if args.detector == "dummy":
        return DummyDetector()
    if args.detector == "xgboost":
        return XGBoostDetector(args.model, args.metadata)
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
    raise ValueError(f"unsupported LLM provider: {args.llm}")


def _load_thresholds(path: str | Path) -> tuple[float, float]:
    threshold_path = Path(path)
    if not threshold_path.exists():
        return 0.30, 0.95
    data = json.loads(threshold_path.read_text(encoding="utf-8"))
    return float(data["low_threshold"]), float(data["high_threshold"])


def _read_optional_text(path: str | Path) -> str:
    file_path = Path(path)
    if not file_path.exists():
        return ""
    return file_path.read_text(encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
