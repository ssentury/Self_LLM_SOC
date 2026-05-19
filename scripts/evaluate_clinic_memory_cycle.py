from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib import request

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc.context.watchlist import load_watchlist, match_watchlist
from soc.io import read_flows_csv
from soc.tier2.batch import run_tier2_from_config


KST = timezone(timedelta(hours=9))
DEFAULT_GEMINI_INPUT_USD_PER_1M = 0.50
DEFAULT_GEMINI_OUTPUT_USD_PER_1M = 3.00


def main() -> int:
    args = _parse_args()
    os.chdir(ROOT)
    _preflight(args)

    output_dir = args.output
    if output_dir.exists() and args.clean:
        shutil.rmtree(output_dir)
    if output_dir.exists() and any(output_dir.iterdir()):
        raise RuntimeError(f"output directory is not empty; pass --clean to replace it: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    all_rows = _read_flow_rows(args.flows)
    day_groups = _split_days(all_rows)
    if len(day_groups) != 3:
        raise RuntimeError(f"expected 3 KST days in {args.flows}, got {len(day_groups)}")

    sqlite_path = output_dir / "soc_events.sqlite"
    base_config = _load_yaml(args.config)
    day_results: list[dict[str, Any]] = []

    for day_index, (day, rows) in enumerate(day_groups, start=1):
        day_dir = output_dir / f"day{day_index:02d}_{day}"
        day_dir.mkdir(parents=True, exist_ok=True)
        day_csv = day_dir / "flows.csv"
        _write_flow_rows(day_csv, rows)

        day_config = _day_config(
            base_config=base_config,
            sqlite_path=sqlite_path,
            tier1_model=args.tier1_model,
            ollama_url=args.ollama_url,
            ollama_timeout=args.ollama_timeout,
            tier2_model=args.tier2_model,
            tier2_max_tokens=args.tier2_max_tokens,
            tier2_temperature=args.tier2_temperature,
        )
        day_config_path = day_dir / "settings.yaml"
        day_config_path.write_text(
            yaml.safe_dump(day_config, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )

        tier2_dir = day_dir / "tier2"
        tier2_started = time.perf_counter()
        tier2_output = run_tier2_from_config(
            config_path=day_config_path,
            output_dir=tier2_dir,
            overrides={"provider": "gemini", "response_format": "json"},
        )
        tier2_elapsed_ms = (time.perf_counter() - tier2_started) * 1000
        if tier2_output.metadata.get("fallback") and not args.allow_tier2_fallback:
            raise RuntimeError(
                "Gemini Batch Loop fell back to deterministic output: "
                f"{tier2_output.metadata.get('fallback_reason')}"
            )

        pipeline_started = time.perf_counter()
        pipeline = _run_pipeline(
            config_path=day_config_path,
            day_csv=day_csv,
            reports_dir=day_dir / "reports",
            sqlite_path=sqlite_path,
            watchlist=tier2_dir / "watchlists" / "latest.yaml",
            brief=tier2_dir / "briefs" / "latest.md",
            args=args,
        )
        pipeline_elapsed_ms = (time.perf_counter() - pipeline_started) * 1000

        flow_ids = [row["flow_id"] for row in rows]
        day_metrics = _collect_day_metrics(
            day=str(day),
            day_index=day_index,
            rows=rows,
            flow_ids=flow_ids,
            day_csv=day_csv,
            watchlist_path=tier2_dir / "watchlists" / "latest.yaml",
            sqlite_path=sqlite_path,
            tier2_metadata=tier2_output.metadata,
            tier2_elapsed_ms=tier2_elapsed_ms,
            pipeline_elapsed_ms=pipeline_elapsed_ms,
            pipeline_stdout=pipeline.stdout,
            pipeline_stderr=pipeline.stderr,
            input_usd_per_1m=args.gemini_input_usd_per_1m,
            output_usd_per_1m=args.gemini_output_usd_per_1m,
        )
        day_results.append(day_metrics)
        (day_dir / "metrics.json").write_text(
            json.dumps(day_metrics, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(
            f"day={day_index} flows={len(rows)} "
            f"tier2_prompt={day_metrics['tier2_tokens']['prompt']} "
            f"tier2_completion={day_metrics['tier2_tokens']['completion']} "
            f"tier1_calls={day_metrics['tier1_tokens']['calls']} "
            f"alerts={day_metrics['final_alert_metrics']['tp'] + day_metrics['final_alert_metrics']['fp']}"
        )

    summary = _aggregate_results(
        day_results,
        input_usd_per_1m=args.gemini_input_usd_per_1m,
        output_usd_per_1m=args.gemini_output_usd_per_1m,
    )
    summary_path = output_dir / "summary_metrics.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    _write_markdown_report(output_dir / "summary.md", summary)
    print(f"summary={summary_path}")
    return 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the 3-day clinic Batch Loop/Realtime Loop memory-cycle evaluation."
    )
    parser.add_argument("--config", type=Path, default=ROOT / "config" / "settings.clinic_scenario.yaml")
    parser.add_argument("--flows", type=Path, default=ROOT / "data" / "sample" / "clinic_telehealth_flows.csv")
    parser.add_argument("--output", type=Path, default=ROOT / "output" / "clinic_memory_cycle_eval")
    parser.add_argument("--clean", action="store_true")
    parser.add_argument("--allow-tier2-fallback", action="store_true")
    parser.add_argument("--tier2-model", default="gemini-3-flash-preview")
    parser.add_argument("--tier2-max-tokens", type=int, default=8192)
    parser.add_argument("--tier2-temperature", type=float, default=0.4)
    parser.add_argument("--tier1-model", default="gemma4:e4b")
    parser.add_argument("--ollama-url", default="http://host.docker.internal:11434")
    parser.add_argument("--ollama-timeout", type=float, default=180.0)
    parser.add_argument("--tier1-mode", choices=["sequential", "queue"], default="queue")
    parser.add_argument("--tier1-workers", type=int, default=1)
    parser.add_argument("--tier1-queue-max-size", type=int, default=100)
    parser.add_argument("--tier1-queue-timeout", type=float, default=600.0)
    parser.add_argument("--gemini-input-usd-per-1m", type=float, default=DEFAULT_GEMINI_INPUT_USD_PER_1M)
    parser.add_argument("--gemini-output-usd-per-1m", type=float, default=DEFAULT_GEMINI_OUTPUT_USD_PER_1M)
    return parser.parse_args()


def _preflight(args: argparse.Namespace) -> None:
    if not _gemini_api_key_present():
        raise RuntimeError(
            "Gemini API key is not available in the process environment. "
            "Set 26_AISecApp_Project_GEMINI_API_KEY, GEMINI_API_KEY, or GOOGLE_API_KEY."
        )
    _check_ollama(args.ollama_url, args.tier1_model)


def _gemini_api_key_present() -> bool:
    return any(
        os.environ.get(name)
        for name in (
            "26_AISecApp_Project_GEMINI_API_KEY",
            "GEMINI_API_KEY",
            "GOOGLE_API_KEY",
        )
    )


def _check_ollama(base_url: str, model: str) -> None:
    url = f"{base_url.rstrip('/')}/api/tags"
    try:
        with request.urlopen(url, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise RuntimeError(f"Ollama preflight failed for {url}: {exc}") from exc
    models = data.get("models") if isinstance(data, dict) else []
    names = {str(item.get("name")) for item in models if isinstance(item, dict)}
    bare_names = {name.split(":", 1)[0] for name in names}
    if model not in names and model.split(":", 1)[0] not in bare_names:
        raise RuntimeError(f"Ollama model {model!r} was not found in /api/tags: {sorted(names)}")


def _load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise RuntimeError(f"settings file must be a mapping: {path}")
    return data


def _read_flow_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _split_days(rows: list[dict[str, str]]) -> list[tuple[str, list[dict[str, str]]]]:
    groups: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        start_ms = int(row["FLOW_START_MILLISECONDS"])
        day = datetime.fromtimestamp(start_ms / 1000, timezone.utc).astimezone(KST).date()
        groups.setdefault(day.isoformat(), []).append(row)
    return [(day, groups[day]) for day in sorted(groups)]


def _write_flow_rows(path: Path, rows: list[dict[str, str]]) -> None:
    if not rows:
        raise RuntimeError("cannot write an empty day flow file")
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _day_config(
    *,
    base_config: dict[str, Any],
    sqlite_path: Path,
    tier1_model: str,
    ollama_url: str,
    ollama_timeout: float,
    tier2_model: str,
    tier2_max_tokens: int,
    tier2_temperature: float,
) -> dict[str, Any]:
    config = json.loads(json.dumps(base_config))
    config.setdefault("storage", {})["enabled"] = True
    config["storage"]["sqlite_path"] = str(sqlite_path)
    config.setdefault("tier1", {}).setdefault("llm", {})["provider"] = "ollama"
    config["tier1"]["llm"]["model"] = tier1_model
    config["tier1"]["llm"]["ollama_url"] = ollama_url
    config["tier1"]["llm"]["timeout_seconds"] = ollama_timeout
    config.setdefault("tier2", {})["provider"] = "gemini"
    config["tier2"]["model"] = tier2_model
    config["tier2"]["max_tokens"] = tier2_max_tokens
    config["tier2"]["temperature"] = tier2_temperature
    config["tier2"]["response_format"] = "json"
    return config


def _run_pipeline(
    *,
    config_path: Path,
    day_csv: Path,
    reports_dir: Path,
    sqlite_path: Path,
    watchlist: Path,
    brief: Path,
    args: argparse.Namespace,
) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        "scripts/pipeline_run.py",
        "--config",
        str(config_path),
        "--input",
        str(day_csv),
        "--output",
        str(reports_dir),
        "--sqlite",
        str(sqlite_path),
        "--llm",
        "ollama",
        "--llm-model",
        args.tier1_model,
        "--ollama-url",
        args.ollama_url,
        "--ollama-timeout",
        str(args.ollama_timeout),
        "--tier1-mode",
        args.tier1_mode,
        "--tier1-workers",
        str(args.tier1_workers),
        "--tier1-queue-max-size",
        str(args.tier1_queue_max_size),
        "--tier1-queue-timeout",
        str(args.tier1_queue_timeout),
        "--watchlist",
        str(watchlist),
        "--brief",
        str(brief),
    ]
    return subprocess.run(command, check=True, capture_output=True, text=True)


def _collect_day_metrics(
    *,
    day: str,
    day_index: int,
    rows: list[dict[str, str]],
    flow_ids: list[str],
    day_csv: Path,
    watchlist_path: Path,
    sqlite_path: Path,
    tier2_metadata: dict[str, Any],
    tier2_elapsed_ms: float,
    pipeline_elapsed_ms: float,
    pipeline_stdout: str,
    pipeline_stderr: str,
    input_usd_per_1m: float,
    output_usd_per_1m: float,
) -> dict[str, Any]:
    placeholders = ",".join("?" for _ in flow_ids)
    with sqlite3.connect(sqlite_path) as conn:
        conn.row_factory = sqlite3.Row
        records = conn.execute(
            f"""
            SELECT
              f.flow_id, f.raw_label, f.raw_attack,
              r.route, r.adjusted_by_watchlist, r.ml_prob,
              r.effective_review_threshold, r.dynamic_threshold_applied,
              r.dynamic_threshold_reason,
              v.verdict, v.severity, v.watchlist_matched,
              v.fallback_source, v.fallback_reason,
              c.provider, c.model_name, c.latency_ms, c.tokens_used,
              c.prompt_tokens, c.completion_tokens, c.success
            FROM flows f
            JOIN route_decisions r ON r.flow_id = f.flow_id
            JOIN verdicts v ON v.flow_id = f.flow_id
            LEFT JOIN tier1_calls c ON c.flow_id = f.flow_id
            WHERE f.flow_id IN ({placeholders})
            ORDER BY f.start_ms
            """,
            flow_ids,
        ).fetchall()

    if len(records) != len(flow_ids):
        raise RuntimeError(f"day {day_index} expected {len(flow_ids)} DB rows, got {len(records)}")

    final_alert = _confusion(records, positive_fn=lambda row: row["verdict"] == "alert")
    final_review = _confusion(records, positive_fn=lambda row: row["verdict"] != "benign")
    context_attack = _context_attack_metrics(records)
    baseline_high = _baseline_metrics(records, threshold=0.95)
    baseline_050 = _baseline_metrics(records, threshold=0.50)

    route_counts = Counter(str(row["route"]) for row in records)
    verdict_counts = Counter(str(row["verdict"]) for row in records)
    fallback_counts = Counter(
        str(row["fallback_source"]) for row in records if row["fallback_source"]
    )
    watchlist_hits = sum(1 for row in records if row["watchlist_matched"])
    adjusted_by_watchlist = sum(1 for row in records if int(row["adjusted_by_watchlist"] or 0))
    dynamic_threshold = _dynamic_threshold_metrics(records)
    watchlist_breakdown = _watchlist_fp_breakdown(
        records=records,
        day_csv=day_csv,
        watchlist_path=watchlist_path,
    )

    tier1_call_rows = [row for row in records if row["provider"]]
    tier1_prompt = sum(int(row["prompt_tokens"] or 0) for row in tier1_call_rows)
    tier1_completion = sum(int(row["completion_tokens"] or 0) for row in tier1_call_rows)
    tier1_total = sum(int(row["tokens_used"] or 0) for row in tier1_call_rows)
    tier1_latencies = [float(row["latency_ms"]) for row in tier1_call_rows if row["latency_ms"] is not None]

    tier2_prompt = int(tier2_metadata.get("prompt_tokens") or 0)
    tier2_completion = int(tier2_metadata.get("completion_tokens") or 0)
    tier2_cost = _gemini_cost(tier2_prompt, tier2_completion, input_usd_per_1m, output_usd_per_1m)

    return {
        "day": day,
        "day_index": day_index,
        "flow_count": len(records),
        "labels": dict(Counter(str(row["raw_label"]) for row in records)),
        "route_counts": dict(route_counts),
        "verdict_counts": dict(verdict_counts),
        "fallback_counts": dict(fallback_counts),
        "watchlist_hits": watchlist_hits,
        "adjusted_by_watchlist": adjusted_by_watchlist,
        **dynamic_threshold,
        **watchlist_breakdown,
        "final_alert_metrics": final_alert,
        "final_review_metrics": final_review,
        "context_attack_metrics": context_attack,
        "baseline_ml_only_high_threshold": baseline_high,
        "baseline_ml_only_050_threshold": baseline_050,
        "tier2": {
            "runner": tier2_metadata.get("runner"),
            "model": tier2_metadata.get("model"),
            "fallback": bool(tier2_metadata.get("fallback")),
            "fallback_reason": tier2_metadata.get("fallback_reason"),
            "latency_ms_reported": tier2_metadata.get("latency_ms"),
            "elapsed_ms": tier2_elapsed_ms,
            "snapshot_stats": tier2_metadata.get("snapshot_stats", {}),
        },
        "tier2_tokens": {
            "prompt": tier2_prompt,
            "completion": tier2_completion,
            "total": int(tier2_metadata.get("tokens_used") or tier2_prompt + tier2_completion),
            "estimated_cost_usd": tier2_cost,
        },
        "tier1_tokens": {
            "calls": len(tier1_call_rows),
            "prompt": tier1_prompt,
            "completion": tier1_completion,
            "total": tier1_total or tier1_prompt + tier1_completion,
            "api_cost_usd": 0.0,
            "avg_latency_ms": (sum(tier1_latencies) / len(tier1_latencies)) if tier1_latencies else 0.0,
            "max_latency_ms": max(tier1_latencies) if tier1_latencies else 0.0,
        },
        "pipeline": {
            "elapsed_ms": pipeline_elapsed_ms,
            "stdout": pipeline_stdout.strip(),
            "stderr": pipeline_stderr.strip(),
        },
    }


def _confusion(records: list[sqlite3.Row], positive_fn) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    for row in records:
        actual = row["raw_label"] == "Malicious"
        predicted = bool(positive_fn(row))
        if actual and predicted:
            tp += 1
        elif not actual and predicted:
            fp += 1
        elif not actual and not predicted:
            tn += 1
        else:
            fn += 1
    return _rates(tp, fp, tn, fn)


def _dynamic_threshold_metrics(records: list[sqlite3.Row]) -> dict[str, int]:
    dynamic_rows = [row for row in records if int(row["dynamic_threshold_applied"] or 0)]
    return {
        "dynamic_threshold_applied_count": len(dynamic_rows),
        "dynamic_threshold_fp_count": sum(
            1
            for row in dynamic_rows
            if row["raw_label"] != "Malicious" and row["verdict"] == "alert"
        ),
        "dynamic_threshold_fn_recovered_count": sum(
            1
            for row in dynamic_rows
            if row["raw_label"] == "Malicious" and row["verdict"] != "benign"
        ),
    }


def _context_attack_metrics(records: list[sqlite3.Row]) -> dict[str, Any]:
    context_rows = [
        row
        for row in records
        if row["raw_label"] == "Malicious" and "attack-context-" in str(row["flow_id"])
    ]
    alert_count = sum(1 for row in context_rows if row["verdict"] == "alert")
    review_count = sum(1 for row in context_rows if row["verdict"] != "benign")
    return {
        "total": len(context_rows),
        "alert_count": alert_count,
        "review_count": review_count,
        "alert_rate": alert_count / len(context_rows) if context_rows else 0.0,
        "review_rate": review_count / len(context_rows) if context_rows else 0.0,
    }


def _watchlist_fp_breakdown(
    *,
    records: list[sqlite3.Row],
    day_csv: Path,
    watchlist_path: Path,
) -> dict[str, Any]:
    watchlist = load_watchlist(watchlist_path)
    flows = {flow.flow_id: flow for flow in read_flows_csv(day_csv)}
    fp_by_match_strength: Counter[str] = Counter()
    fp_by_watchlist_item: Counter[str] = Counter()
    fp_adjusted_by_watchlist = 0
    for row in records:
        if row["raw_label"] == "Malicious" or row["verdict"] != "alert":
            continue
        flow = flows.get(str(row["flow_id"]))
        if flow is None:
            continue
        match = match_watchlist(flow, watchlist, ml_prob=float(row["ml_prob"] or 0.0))
        fp_by_match_strength.update([match.match_strength])
        fp_by_watchlist_item.update([match.item_id or "none"])
        if int(row["adjusted_by_watchlist"] or 0):
            fp_adjusted_by_watchlist += 1
    return {
        "fp_by_match_strength": dict(fp_by_match_strength),
        "fp_by_watchlist_item": dict(fp_by_watchlist_item),
        "fp_adjusted_by_watchlist": fp_adjusted_by_watchlist,
        "watchlist_linter_warnings": watchlist.get("linter_warnings", []),
    }


def _baseline_metrics(records: list[sqlite3.Row], threshold: float) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    for row in records:
        actual = row["raw_label"] == "Malicious"
        predicted = float(row["ml_prob"] or 0.0) > threshold
        if actual and predicted:
            tp += 1
        elif not actual and predicted:
            fp += 1
        elif not actual and not predicted:
            tn += 1
        else:
            fn += 1
    result = _rates(tp, fp, tn, fn)
    result["threshold"] = threshold
    return result


def _rates(tp: int, fp: int, tn: int, fn: int) -> dict[str, Any]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    fnr = fn / (fn + tp) if fn + tp else 0.0
    accuracy = (tp + tn) / (tp + fp + tn + fn) if tp + fp + tn + fn else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "accuracy": accuracy,
    }


def _gemini_cost(
    prompt_tokens: int,
    completion_tokens: int,
    input_usd_per_1m: float,
    output_usd_per_1m: float,
) -> float:
    return (prompt_tokens / 1_000_000 * input_usd_per_1m) + (
        completion_tokens / 1_000_000 * output_usd_per_1m
    )


def _aggregate_results(
    days: list[dict[str, Any]],
    *,
    input_usd_per_1m: float,
    output_usd_per_1m: float,
) -> dict[str, Any]:
    all_alert = _sum_metric(days, "final_alert_metrics")
    all_review = _sum_metric(days, "final_review_metrics")
    context_attack_total = sum(day["context_attack_metrics"]["total"] for day in days)
    context_attack_alert = sum(day["context_attack_metrics"]["alert_count"] for day in days)
    context_attack_review = sum(day["context_attack_metrics"]["review_count"] for day in days)
    all_baseline_high = _sum_metric(days, "baseline_ml_only_high_threshold")
    all_baseline_050 = _sum_metric(days, "baseline_ml_only_050_threshold")

    tier2_prompt = sum(day["tier2_tokens"]["prompt"] for day in days)
    tier2_completion = sum(day["tier2_tokens"]["completion"] for day in days)
    tier1_prompt = sum(day["tier1_tokens"]["prompt"] for day in days)
    tier1_completion = sum(day["tier1_tokens"]["completion"] for day in days)
    route_counts: Counter[str] = Counter()
    verdict_counts: Counter[str] = Counter()
    fallback_counts: Counter[str] = Counter()
    fp_by_match_strength: Counter[str] = Counter()
    fp_by_watchlist_item: Counter[str] = Counter()
    watchlist_linter_warnings: list[str] = []
    for day in days:
        route_counts.update(day["route_counts"])
        verdict_counts.update(day["verdict_counts"])
        fallback_counts.update(day["fallback_counts"])
        fp_by_match_strength.update(day.get("fp_by_match_strength", {}))
        fp_by_watchlist_item.update(day.get("fp_by_watchlist_item", {}))
        watchlist_linter_warnings.extend(day.get("watchlist_linter_warnings", []))

    return {
        "scenario": {
            "name": "clinic_telehealth_3day_memory_cycle",
            "days": len(days),
            "flows": sum(day["flow_count"] for day in days),
            "gemini_pricing_source": "https://ai.google.dev/pricing",
            "gemini_input_usd_per_1m": input_usd_per_1m,
            "gemini_output_usd_per_1m": output_usd_per_1m,
            "tier1_api_cost_usd": 0.0,
        },
        "topology": _topology_text(),
        "daily": days,
        "aggregate": {
            "route_counts": dict(route_counts),
            "verdict_counts": dict(verdict_counts),
            "fallback_counts": dict(fallback_counts),
            "watchlist_hits": sum(day["watchlist_hits"] for day in days),
            "adjusted_by_watchlist": sum(day["adjusted_by_watchlist"] for day in days),
            "dynamic_threshold_applied_count": sum(
                day.get("dynamic_threshold_applied_count", 0) for day in days
            ),
            "dynamic_threshold_fp_count": sum(
                day.get("dynamic_threshold_fp_count", 0) for day in days
            ),
            "dynamic_threshold_fn_recovered_count": sum(
                day.get("dynamic_threshold_fn_recovered_count", 0) for day in days
            ),
            "fp_by_match_strength": dict(fp_by_match_strength),
            "fp_by_watchlist_item": dict(fp_by_watchlist_item),
            "fp_adjusted_by_watchlist": sum(day.get("fp_adjusted_by_watchlist", 0) for day in days),
            "watchlist_linter_warnings": watchlist_linter_warnings,
            "final_alert_metrics": all_alert,
            "final_review_metrics": all_review,
            "context_attack_metrics": {
                "total": context_attack_total,
                "alert_count": context_attack_alert,
                "review_count": context_attack_review,
                "alert_rate": (
                    context_attack_alert / context_attack_total if context_attack_total else 0.0
                ),
                "review_rate": (
                    context_attack_review / context_attack_total if context_attack_total else 0.0
                ),
            },
            "baseline_ml_only_high_threshold": all_baseline_high,
            "baseline_ml_only_050_threshold": all_baseline_050,
            "tier2_tokens": {
                "prompt": tier2_prompt,
                "completion": tier2_completion,
                "total": tier2_prompt + tier2_completion,
                "estimated_cost_usd": _gemini_cost(
                    tier2_prompt,
                    tier2_completion,
                    input_usd_per_1m,
                    output_usd_per_1m,
                ),
            },
            "tier1_tokens": {
                "calls": sum(day["tier1_tokens"]["calls"] for day in days),
                "prompt": tier1_prompt,
                "completion": tier1_completion,
                "total": tier1_prompt + tier1_completion,
                "api_cost_usd": 0.0,
            },
        },
    }


def _sum_metric(days: list[dict[str, Any]], key: str) -> dict[str, Any]:
    tp = sum(day[key]["tp"] for day in days)
    fp = sum(day[key]["fp"] for day in days)
    tn = sum(day[key]["tn"] for day in days)
    fn = sum(day[key]["fn"] for day in days)
    return _rates(tp, fp, tn, fn)


def _topology_text() -> str:
    return """Internet patients/staff/scanners
        |
        v
  203.0.113.10 patient portal (HTTP/HTTPS)     203.0.113.20 VPN gateway
        |                                              |
        +---------------- DMZ public -------------------+
                               |
                               v
  10.42.20.15 EHR API ---> 10.42.30.25 billing Postgres
        |                         ^
        |                         |
  clinic workstations        admin/jumpbox 10.42.50.8
  10.42.100.0/24                 |
        |                         v
        +-----> 10.42.40.12 backup NAS (SMB/SSH)
        |
        +-----> 10.42.60.5 internal DNS
        |
        +-----> 169.254.169.254 cloud metadata (should not be queried)
"""


def _write_markdown_report(path: Path, summary: dict[str, Any]) -> None:
    aggregate = summary["aggregate"]
    lines = [
        "# Clinic Memory Cycle Evaluation",
        "",
        "## Topology",
        "",
        "```text",
        summary["topology"].rstrip(),
        "```",
        "",
        "## Aggregate Metrics",
        "",
        f"- Flows: {summary['scenario']['flows']}",
        f"- Routes: {aggregate['route_counts']}",
        f"- Verdicts: {aggregate['verdict_counts']}",
        f"- Fallbacks: {aggregate['fallback_counts']}",
        f"- Final alert recall: {aggregate['final_alert_metrics']['recall']:.3f}",
        f"- Final alert precision: {aggregate['final_alert_metrics']['precision']:.3f}",
        (
            "- Context attack alerts: "
            f"{aggregate['context_attack_metrics']['alert_count']}/"
            f"{aggregate['context_attack_metrics']['total']}"
        ),
        f"- Review recall: {aggregate['final_review_metrics']['recall']:.3f}",
        f"- FP by watchlist match strength: {aggregate.get('fp_by_match_strength', {})}",
        f"- FP adjusted by watchlist: {aggregate.get('fp_adjusted_by_watchlist', 0)}",
        f"- Dynamic threshold applied: {aggregate.get('dynamic_threshold_applied_count', 0)}",
        f"- Dynamic threshold FP: {aggregate.get('dynamic_threshold_fp_count', 0)}",
        f"- Dynamic threshold FN recovered: {aggregate.get('dynamic_threshold_fn_recovered_count', 0)}",
        f"- Watchlist linter warnings: {len(aggregate.get('watchlist_linter_warnings', []))}",
        f"- ML-only high-threshold recall: {aggregate['baseline_ml_only_high_threshold']['recall']:.3f}",
        f"- Tier 2 Gemini tokens: {aggregate['tier2_tokens']}",
        f"- Tier 1 Ollama tokens: {aggregate['tier1_tokens']}",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
