from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from evaluate_clinic_memory_cycle import (  # noqa: E402
    DEFAULT_GEMINI_INPUT_USD_PER_1M,
    DEFAULT_GEMINI_OUTPUT_USD_PER_1M,
    ROOT,
    _aggregate_results as _clinic_aggregate_results,
    _collect_day_metrics as _clinic_collect_day_metrics,
    _day_config as _clinic_day_config,
    _gemini_cost,
    _load_yaml,
    _preflight,
    _rates,
    _read_flow_rows,
    _run_pipeline,
    _split_days,
    _sum_metric,
    _write_flow_rows,
)
from soc.tier2.batch import run_tier2_from_config  # noqa: E402


SOURCE_NAMES = ("organization", "assets", "policy", "cve_feed", "threat_feed")
CVE_CONTROL_SCENARIOS = {
    "CVE-2025-24813": {"lab-results-api-access", "appointment-api"},
    "CVE-2024-47575": {"admin-management", "monitoring-scrape"},
}


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
    if len(day_groups) != 5:
        raise RuntimeError(f"expected 5 KST days in {args.flows}, got {len(day_groups)}")

    manifest_by_flow_id = _load_manifest_by_flow_id(args.manifest)
    _validate_generated_sources(args.generated_sources, expected_days=len(day_groups))

    sqlite_path = output_dir / "soc_events.sqlite"
    base_config = _load_yaml(args.config)
    day_results: list[dict[str, Any]] = []

    for day_index, (day, rows) in enumerate(day_groups, start=1):
        day_dir = output_dir / f"day{day_index:02d}_{day}"
        day_dir.mkdir(parents=True, exist_ok=True)
        day_csv = day_dir / "flows.csv"
        _write_flow_rows(day_csv, rows)

        day_config = _dynamic_day_config(
            base_config=base_config,
            sqlite_path=sqlite_path,
            generated_sources=args.generated_sources,
            day_index=day_index,
            tier1_provider=args.tier1_provider,
            tier1_model=args.tier1_model,
            ollama_url=args.ollama_url,
            ollama_timeout=args.ollama_timeout,
            activity_window_minutes=args.activity_window_minutes,
            tier2_provider=args.tier2_provider,
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
            overrides={"provider": args.tier2_provider, "response_format": "json"},
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
        day_metrics = _clinic_collect_day_metrics(
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
        records = _records_for_flow_ids(sqlite_path, flow_ids)
        _add_dynamic_day_slices(day_metrics, records, manifest_by_flow_id)

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
            f"alerts={day_metrics['final_alert_metrics']['tp'] + day_metrics['final_alert_metrics']['fp']} "
            f"dynamic_threshold={day_metrics.get('dynamic_threshold_applied_count', 0)}"
        )

    summary = _aggregate_dynamic_results(
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
        description="Run the 5-day regional-care dynamic CVE Batch/Realtime evaluation."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=ROOT / "config" / "settings.regional_care_dynamic_cve_xgb.yaml",
    )
    parser.add_argument(
        "--flows",
        type=Path,
        default=ROOT / "data" / "sample" / "regional_care_dynamic_cve_flows_xgb.csv",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / "data" / "sample" / "regional_care_dynamic_cve_flows_xgb_manifest.json",
    )
    parser.add_argument(
        "--generated-sources",
        type=Path,
        default=ROOT / "config" / "scenarios" / "regional_care_dynamic_cve" / "generated",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "output" / "regional_care_dynamic_cve_memory_cycle_eval",
    )
    parser.add_argument("--clean", action="store_true")
    parser.add_argument("--allow-tier2-fallback", action="store_true")
    parser.add_argument("--tier2-provider", choices=["deterministic", "gemini"], default="gemini")
    parser.add_argument("--tier2-model", default="gemini-3.5-flash")
    parser.add_argument("--tier2-max-tokens", type=int, default=8192)
    parser.add_argument("--tier2-temperature", type=float, default=0.7)
    parser.add_argument("--tier1-provider", choices=["fake", "ollama", "gemini"], default="ollama")
    parser.add_argument("--tier1-model", default="gemma4:e4b")
    parser.add_argument("--ollama-url", default="http://host.docker.internal:11434")
    parser.add_argument("--ollama-timeout", type=float, default=180.0)
    parser.add_argument("--activity-window-minutes", type=int, default=180)
    parser.add_argument("--tier1-mode", choices=["sequential", "queue"], default="queue")
    parser.add_argument("--tier1-workers", type=int, default=1)
    parser.add_argument("--tier1-queue-max-size", type=int, default=200)
    parser.add_argument("--tier1-queue-timeout", type=float, default=600.0)
    parser.add_argument("--gemini-input-usd-per-1m", type=float, default=DEFAULT_GEMINI_INPUT_USD_PER_1M)
    parser.add_argument("--gemini-output-usd-per-1m", type=float, default=DEFAULT_GEMINI_OUTPUT_USD_PER_1M)
    return parser.parse_args()


def _dynamic_day_config(
    *,
    base_config: dict[str, Any],
    sqlite_path: Path,
    generated_sources: Path,
    day_index: int,
    tier1_model: str,
    ollama_url: str,
    ollama_timeout: float,
    tier2_model: str,
    tier2_max_tokens: int,
    tier2_temperature: float,
    tier1_provider: str = "ollama",
    activity_window_minutes: int = 180,
    tier2_provider: str = "gemini",
) -> dict[str, Any]:
    config = _clinic_day_config(
        base_config=base_config,
        sqlite_path=sqlite_path,
        tier1_provider=tier1_provider,
        tier1_model=tier1_model,
        ollama_url=ollama_url,
        ollama_timeout=ollama_timeout,
        activity_window_minutes=activity_window_minutes,
        tier2_provider=tier2_provider,
        tier2_model=tier2_model,
        tier2_max_tokens=tier2_max_tokens,
        tier2_temperature=tier2_temperature,
    )
    day_dir = generated_sources / f"day{day_index:02d}"
    sources = config.setdefault("tier2", {}).setdefault("sources", {})
    for name in SOURCE_NAMES:
        path = day_dir / f"{name}.yaml"
        sources.setdefault(name, {})["enabled"] = True
        sources[name]["path"] = str(path)
    return config


def _validate_generated_sources(generated_sources: Path, *, expected_days: int) -> None:
    for day_index in range(1, expected_days + 1):
        day_dir = generated_sources / f"day{day_index:02d}"
        missing = [name for name in SOURCE_NAMES if not (day_dir / f"{name}.yaml").exists()]
        if missing:
            raise RuntimeError(f"missing generated source files for {day_dir}: {missing}")


def _load_manifest_by_flow_id(path: Path) -> dict[str, dict[str, Any]]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    trace = manifest.get("source_trace")
    if not isinstance(trace, list):
        raise RuntimeError(f"manifest does not contain source_trace list: {path}")
    by_flow_id: dict[str, dict[str, Any]] = {}
    for item in trace:
        if isinstance(item, dict) and item.get("flow_id"):
            by_flow_id[str(item["flow_id"])] = item
    if not by_flow_id:
        raise RuntimeError(f"manifest source_trace is empty: {path}")
    return by_flow_id


def _records_for_flow_ids(sqlite_path: Path, flow_ids: list[str]) -> list[sqlite3.Row]:
    placeholders = ",".join("?" for _ in flow_ids)
    with sqlite3.connect(sqlite_path) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(
            f"""
            SELECT
              f.flow_id, f.raw_label, f.raw_attack,
              r.route, r.adjusted_by_watchlist, r.ml_prob,
              r.dynamic_threshold_applied,
              v.verdict, v.severity, v.watchlist_matched
            FROM flows f
            JOIN route_decisions r ON r.flow_id = f.flow_id
            JOIN verdicts v ON v.flow_id = f.flow_id
            WHERE f.flow_id IN ({placeholders})
            ORDER BY f.start_ms
            """,
            flow_ids,
        ).fetchall()


def _add_dynamic_day_slices(
    day_metrics: dict[str, Any],
    records: list[sqlite3.Row],
    manifest_by_flow_id: dict[str, dict[str, Any]],
) -> None:
    metadata = {str(row["flow_id"]): manifest_by_flow_id.get(str(row["flow_id"]), {}) for row in records}
    scenarios = Counter(str(item.get("scenario") or "unknown") for item in metadata.values())
    cves = Counter(str(item.get("cve_id")) for item in metadata.values() if item.get("cve_id"))
    source_attacks = Counter(str(item.get("source_attack") or "unknown") for item in metadata.values())

    day_metrics["scenario_counts"] = dict(scenarios)
    day_metrics["cve_counts"] = dict(cves)
    day_metrics["source_attack_counts"] = dict(source_attacks)
    day_metrics["slice_metrics"] = {
        "cve": {
            cve_id: _cve_slice_metrics(records, metadata, cve_id)
            for cve_id in ("CVE-2025-24813", "CVE-2024-47575")
        },
        "low_ml_contextual_attacks": _flow_slice_metrics(
            records,
            lambda row: row["raw_label"] == "Malicious" and float(row["ml_prob"] or 0.0) < 0.30,
        ),
        "infilteration_family": _flow_slice_metrics(
            records,
            lambda row: str(row["raw_attack"]) == "Infilteration",
        ),
    }


def _cve_slice_metrics(
    records: list[sqlite3.Row],
    metadata: dict[str, dict[str, Any]],
    cve_id: str,
) -> dict[str, Any]:
    attack_metrics = _flow_slice_metrics(
        records,
        lambda row: metadata[str(row["flow_id"])].get("cve_id") == cve_id,
    )
    control_scenarios = CVE_CONTROL_SCENARIOS[cve_id]
    benign_controls = [
        row
        for row in records
        if row["raw_label"] != "Malicious"
        and metadata[str(row["flow_id"])].get("scenario") in control_scenarios
    ]
    return {
        "attack_metrics": attack_metrics,
        "benign_control_count": len(benign_controls),
        "benign_control_alert_fpr": _false_positive_rate(benign_controls),
    }


def _flow_slice_metrics(records: list[sqlite3.Row], predicate) -> dict[str, Any]:
    selected = [row for row in records if predicate(row)]
    return {
        "flow_count": len(selected),
        "alert_metrics": _confusion(selected, positive_fn=lambda row: row["verdict"] == "alert"),
        "review_metrics": _confusion(selected, positive_fn=lambda row: row["verdict"] != "benign"),
        "dynamic_threshold_applied_count": sum(
            1 for row in selected if int(row["dynamic_threshold_applied"] or 0)
        ),
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


def _false_positive_rate(records: list[sqlite3.Row]) -> float:
    if not records:
        return 0.0
    false_positives = sum(1 for row in records if row["verdict"] == "alert")
    return false_positives / len(records)


def _aggregate_dynamic_results(
    days: list[dict[str, Any]],
    *,
    input_usd_per_1m: float,
    output_usd_per_1m: float,
) -> dict[str, Any]:
    summary = _clinic_aggregate_results(
        days,
        input_usd_per_1m=input_usd_per_1m,
        output_usd_per_1m=output_usd_per_1m,
    )
    summary["scenario"]["name"] = "regional_care_dynamic_cve_5day"
    summary["topology"] = _topology_text()

    pre_change = [day for day in days if day["day_index"] <= 2]
    post_change = [day for day in days if day["day_index"] >= 3]
    summary["aggregate"]["change_window_metrics"] = {
        "pre_change_days_1_2": _window_metrics(pre_change),
        "post_change_days_3_5": _window_metrics(post_change),
    }
    summary["aggregate"]["dynamic_cve_slices"] = _aggregate_slice_metrics(days)
    summary["aggregate"]["tier2_tokens"]["estimated_cost_usd"] = _gemini_cost(
        summary["aggregate"]["tier2_tokens"]["prompt"],
        summary["aggregate"]["tier2_tokens"]["completion"],
        input_usd_per_1m,
        output_usd_per_1m,
    )
    return summary


def _window_metrics(days: list[dict[str, Any]]) -> dict[str, Any]:
    if not days:
        return {}
    return {
        "days": [day["day_index"] for day in days],
        "flows": sum(day["flow_count"] for day in days),
        "final_alert_metrics": _sum_metric(days, "final_alert_metrics"),
        "final_review_metrics": _sum_metric(days, "final_review_metrics"),
        "watchlist_hits": sum(day["watchlist_hits"] for day in days),
        "adjusted_by_watchlist": sum(day["adjusted_by_watchlist"] for day in days),
        "dynamic_threshold_applied_count": sum(
            day.get("dynamic_threshold_applied_count", 0) for day in days
        ),
    }


def _aggregate_slice_metrics(days: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "cve": {
            cve_id: _aggregate_cve_slice(days, cve_id)
            for cve_id in ("CVE-2025-24813", "CVE-2024-47575")
        },
        "low_ml_contextual_attacks": _aggregate_named_slice(days, "low_ml_contextual_attacks"),
        "infilteration_family": _aggregate_named_slice(days, "infilteration_family"),
    }


def _aggregate_cve_slice(days: list[dict[str, Any]], cve_id: str) -> dict[str, Any]:
    slices = [day["slice_metrics"]["cve"][cve_id] for day in days]
    attack_slices = [item["attack_metrics"] for item in slices]
    benign_count = sum(item["benign_control_count"] for item in slices)
    benign_alerts = sum(
        round(item["benign_control_alert_fpr"] * item["benign_control_count"]) for item in slices
    )
    return {
        "attack_metrics": _aggregate_flow_slice(attack_slices),
        "benign_control_count": benign_count,
        "benign_control_alert_fpr": benign_alerts / benign_count if benign_count else 0.0,
    }


def _aggregate_named_slice(days: list[dict[str, Any]], name: str) -> dict[str, Any]:
    return _aggregate_flow_slice([day["slice_metrics"][name] for day in days])


def _aggregate_flow_slice(slices: list[dict[str, Any]]) -> dict[str, Any]:
    flow_count = sum(item["flow_count"] for item in slices)
    alert = _sum_slice_confusion(slices, "alert_metrics")
    review = _sum_slice_confusion(slices, "review_metrics")
    return {
        "flow_count": flow_count,
        "alert_metrics": alert,
        "review_metrics": review,
        "dynamic_threshold_applied_count": sum(
            item.get("dynamic_threshold_applied_count", 0) for item in slices
        ),
    }


def _sum_slice_confusion(slices: list[dict[str, Any]], key: str) -> dict[str, Any]:
    tp = sum(item[key]["tp"] for item in slices)
    fp = sum(item[key]["fp"] for item in slices)
    tn = sum(item[key]["tn"] for item in slices)
    fn = sum(item[key]["fn"] for item in slices)
    return _rates(tp, fp, tn, fn)


def _topology_text() -> str:
    return """Internet patients/staff/scanners
        |
        v
  203.0.113.10 patient portal       203.0.113.20 VPN gateway
  203.0.113.30 appointment API      203.0.113.40 partner SFTP
        |                                      |
        +------------- DMZ public -------------+
                       |
                       v
  10.60.20.15 EHR API          10.60.20.30 lab-results API
  10.60.30.20 EHR Postgres     10.60.30.25 billing MSSQL
  10.60.30.30 lab MySQL        10.60.40.12 backup NAS
  10.60.50.8 admin jumpbox     10.60.50.30 firewall manager
  10.60.60.5 internal DNS      10.60.100.0/24 workstation pool
"""


def _write_markdown_report(path: Path, summary: dict[str, Any]) -> None:
    aggregate = summary["aggregate"]
    slices = aggregate["dynamic_cve_slices"]
    lines = [
        "# Regional Care Dynamic CVE Evaluation",
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
        f"- Final alert recall: {aggregate['final_alert_metrics']['recall']:.3f}",
        f"- Final alert precision: {aggregate['final_alert_metrics']['precision']:.3f}",
        f"- Review recall: {aggregate['final_review_metrics']['recall']:.3f}",
        f"- Dynamic threshold applied: {aggregate.get('dynamic_threshold_applied_count', 0)}",
        f"- Dynamic threshold FP: {aggregate.get('dynamic_threshold_fp_count', 0)}",
        f"- Dynamic threshold FN recovered: {aggregate.get('dynamic_threshold_fn_recovered_count', 0)}",
        f"- Day 1-2 alert recall: {aggregate['change_window_metrics']['pre_change_days_1_2']['final_alert_metrics']['recall']:.3f}",
        f"- Day 3-5 alert recall: {aggregate['change_window_metrics']['post_change_days_3_5']['final_alert_metrics']['recall']:.3f}",
        f"- CVE-2025-24813 attack recall: {slices['cve']['CVE-2025-24813']['attack_metrics']['alert_metrics']['recall']:.3f}",
        f"- CVE-2025-24813 benign control FPR: {slices['cve']['CVE-2025-24813']['benign_control_alert_fpr']:.3f}",
        f"- CVE-2024-47575 attack recall: {slices['cve']['CVE-2024-47575']['attack_metrics']['alert_metrics']['recall']:.3f}",
        f"- CVE-2024-47575 benign control FPR: {slices['cve']['CVE-2024-47575']['benign_control_alert_fpr']:.3f}",
        f"- Low-ML contextual attack review recall: {slices['low_ml_contextual_attacks']['review_metrics']['recall']:.3f}",
        f"- Infilteration alert recall: {slices['infilteration_family']['alert_metrics']['recall']:.3f}",
        f"- Watchlist linter warnings: {len(aggregate.get('watchlist_linter_warnings', []))}",
        f"- Tier 2 Gemini tokens: {aggregate['tier2_tokens']}",
        f"- Tier 1 Ollama tokens: {aggregate['tier1_tokens']}",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
