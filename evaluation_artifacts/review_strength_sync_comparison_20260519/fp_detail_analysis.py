from __future__ import annotations

import csv
import json
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from soc.context.watchlist import load_watchlist, match_watchlist
from soc.io import read_flows_csv


RUN_DIR = ROOT / "evaluation_artifacts" / "eval_dynamic_cve_v2_review_strength_sync_8192"
OUT_DIR = ROOT / "evaluation_artifacts" / "review_strength_sync_comparison_20260519"


def main() -> int:
    sqlite_path = RUN_DIR / "soc_events.sqlite"
    fp_rows = _load_false_positive_rows(sqlite_path)
    match_by_flow = _watchlist_matches_by_flow()
    details = [_enrich(row, match_by_flow.get(row["flow_id"])) for row in fp_rows]

    summary = {
        "run_dir": str(RUN_DIR.relative_to(ROOT)),
        "false_positive_alert_count": len(details),
        "by_day": _count(details, "day"),
        "by_flow_family": _count(details, "flow_family"),
        "by_route": _count(details, "route"),
        "by_dynamic_threshold_applied": _count(details, "dynamic_threshold_applied"),
        "by_adjusted_by_watchlist": _count(details, "adjusted_by_watchlist"),
        "by_match_strength": _count(details, "match_strength"),
        "by_watchlist_item": _count(details, "watchlist_item"),
        "by_verdict_severity": _count(details, "severity"),
        "by_ml_prob_band": _count(details, "ml_prob_band"),
        "by_effective_review_threshold": _count(details, "effective_review_threshold"),
        "top_dst_ip": _top(details, "dst_ip", limit=20),
        "top_src_ip": _top(details, "src_ip", limit=20),
        "top_dynamic_threshold_reason": _top(details, "dynamic_threshold_reason", limit=10),
        "top_matched_conditions": _top_conditions(details, limit=20),
        "ml_prob": _numeric_summary(details, "ml_prob"),
        "dynamic_threshold_false_positive_count": sum(
            1 for item in details if item["dynamic_threshold_applied"]
        ),
        "non_dynamic_false_positive_count": sum(
            1 for item in details if not item["dynamic_threshold_applied"]
        ),
        "samples": details[:20],
    }

    (OUT_DIR / "dynamic_fp_detail.json").write_text(
        json.dumps({"summary": summary, "false_positives": details}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    _write_csv(OUT_DIR / "dynamic_fp_detail.csv", details)
    _write_markdown(OUT_DIR / "dynamic_fp_root_cause_deep_dive.md", summary)
    return 0


def _load_false_positive_rows(sqlite_path: Path) -> list[dict]:
    with sqlite3.connect(sqlite_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT
              f.flow_id, f.start_ms, f.src_ip, f.dst_ip, f.src_port, f.dst_port,
              f.protocol, f.raw_label, f.raw_attack,
              r.route, r.reason AS route_reason, r.adjusted_by_watchlist,
              r.ml_prob, r.effective_review_threshold,
              r.dynamic_threshold_applied, r.dynamic_threshold_reason,
              v.verdict, v.severity, v.rationale_ko, v.recommended_action_ko,
              v.watchlist_matched, v.confidence, v.fallback_source, v.fallback_reason
            FROM flows f
            JOIN route_decisions r ON r.flow_id = f.flow_id
            JOIN verdicts v ON v.flow_id = f.flow_id
            WHERE f.raw_label != 'Malicious' AND v.verdict = 'alert'
            ORDER BY f.start_ms, f.flow_id
            """
        ).fetchall()
    return [dict(row) for row in rows]


def _watchlist_matches_by_flow() -> dict[str, dict]:
    matches: dict[str, dict] = {}
    for day_dir in sorted(RUN_DIR.glob("day*_2026-*")):
        flow_csv = day_dir / "flows.csv"
        watchlist_path = day_dir / "tier2" / "watchlists" / "latest.yaml"
        if not flow_csv.exists() or not watchlist_path.exists():
            continue
        watchlist = load_watchlist(watchlist_path)
        for flow in read_flows_csv(flow_csv):
            match = match_watchlist(flow, watchlist)
            matches[flow.flow_id] = {
                "watchlist_item": match.item_id or "none",
                "match_strength": match.match_strength,
                "trigger_matched": match.trigger_matched,
                "context_only": match.context_only,
                "matched_conditions": match.matched_conditions,
                "alert_when": match.alert_when,
                "likely_benign_when": match.likely_benign_when,
                "routing_policy": match.routing_policy,
            }
    return matches


def _enrich(row: dict, match: dict | None) -> dict:
    flow_id = str(row["flow_id"])
    parts = flow_id.split("-")
    day = parts[1] if len(parts) > 1 else "unknown"
    flow_family = "unknown"
    if "-benign-" in flow_id:
        flow_family = flow_id.split("-benign-", 1)[1].rsplit("-", 1)[0]
    ml_prob = float(row["ml_prob"] or 0.0)
    threshold = float(row["effective_review_threshold"] or 0.0)
    enriched = {
        **row,
        "day": day,
        "flow_family": flow_family,
        "ml_prob": ml_prob,
        "ml_prob_band": _prob_band(ml_prob),
        "effective_review_threshold": round(threshold, 3),
        "adjusted_by_watchlist": bool(row["adjusted_by_watchlist"]),
        "dynamic_threshold_applied": bool(row["dynamic_threshold_applied"]),
    }
    if match:
        enriched.update(match)
    else:
        enriched.update(
            {
                "watchlist_item": "unknown",
                "match_strength": "unknown",
                "trigger_matched": None,
                "context_only": None,
                "matched_conditions": [],
                "alert_when": [],
                "likely_benign_when": [],
                "routing_policy": None,
            }
        )
    return enriched


def _prob_band(prob: float) -> str:
    bands = [
        (0.04, "<0.04"),
        (0.08, "0.04-0.08"),
        (0.12, "0.08-0.12"),
        (0.20, "0.12-0.20"),
        (0.30, "0.20-0.30"),
        (0.95, "0.30-0.95"),
    ]
    for upper, label in bands:
        if prob < upper:
            return label
    return ">=0.95"


def _count(rows: list[dict], key: str) -> dict[str, int]:
    return dict(Counter(str(row.get(key)) for row in rows))


def _top(rows: list[dict], key: str, *, limit: int) -> dict[str, int]:
    counter = Counter(str(row.get(key)) for row in rows)
    return dict(counter.most_common(limit))


def _top_conditions(rows: list[dict], *, limit: int) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for row in rows:
        for condition in row.get("matched_conditions", []):
            counter[str(condition)] += 1
    return dict(counter.most_common(limit))


def _numeric_summary(rows: list[dict], key: str) -> dict[str, float]:
    values = sorted(float(row[key]) for row in rows if row.get(key) is not None)
    if not values:
        return {}
    return {
        "min": values[0],
        "p25": values[int((len(values) - 1) * 0.25)],
        "mean": mean(values),
        "p50": values[int((len(values) - 1) * 0.50)],
        "p75": values[int((len(values) - 1) * 0.75)],
        "max": values[-1],
    }


def _write_csv(path: Path, rows: list[dict]) -> None:
    fieldnames = [
        "flow_id",
        "day",
        "flow_family",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "route",
        "ml_prob",
        "ml_prob_band",
        "effective_review_threshold",
        "adjusted_by_watchlist",
        "dynamic_threshold_applied",
        "dynamic_threshold_reason",
        "watchlist_item",
        "match_strength",
        "trigger_matched",
        "context_only",
        "severity",
        "confidence",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fieldnames})


def _write_markdown(path: Path, summary: dict) -> None:
    lines = [
        "# Dynamic CVE FP Deep Dive",
        "",
        f"False positive alerts: {summary['false_positive_alert_count']}",
        "",
        "## Concentration",
        "",
        f"- By flow family: `{summary['by_flow_family']}`",
        f"- By watchlist item: `{summary['by_watchlist_item']}`",
        f"- By match strength: `{summary['by_match_strength']}`",
        f"- By route: `{summary['by_route']}`",
        f"- Dynamic threshold FP count: {summary['dynamic_threshold_false_positive_count']}",
        f"- Non-dynamic FP count: {summary['non_dynamic_false_positive_count']}",
        "",
        "## ML Probability",
        "",
        f"- Bands: `{summary['by_ml_prob_band']}`",
        f"- Summary: `{summary['ml_prob']}`",
        f"- Effective thresholds: `{summary['by_effective_review_threshold']}`",
        f"- Top matched conditions: `{summary['top_matched_conditions']}`",
        "",
        "## Network Shape",
        "",
        f"- Top source IPs: `{summary['top_src_ip']}`",
        f"- Top destination IPs: `{summary['top_dst_ip']}`",
        "",
        "## Root Cause",
        "",
        "The FP set is mostly normal workstation infrastructure traffic, not just",
        "actual DNS-tunnel-like traffic: 116 workstation DNS flows, 35 workstation NTP",
        "flows, and 2 workstation web browsing flows.",
        "",
        "The decisive bug is the interaction between broad source-scoped watchlist",
        "items and current detection-hint semantics. The watchlist item contains",
        "`target_assets` for broad workstation CIDRs and also includes a `src_ip",
        "in_cidr` detection hint over the same workstation CIDRs. The matcher does",
        "not require all detection hints to match as an AND group. It collects any",
        "matching hints, then derives the best match strength from the matched subset.",
        "As a result, a normal workstation flow can match the DNS-tunnel item through",
        "the source CIDR hint alone, even when `dst_port == 53`, UDP, external",
        "destination, or repeated-DNS behavior did not all match.",
        "",
        "Because that item carries `routing_policy.review_threshold: 0.04`, many",
        "benign workstation flows with ML probabilities around 0.05-0.10 are routed",
        "to Tier 1. Tier 1 then receives a Tier 2-curated DNS-tunnel context and often",
        "emits `alert`. This is not random LLM noise; it is a deterministic",
        "routing/context failure caused by broad source scope, OR-style hint matching,",
        "and the newly trusted `review_candidate` path.",
        "",
        "## Representative Samples",
        "",
    ]
    for sample in summary["samples"][:10]:
        lines.append(
            "- "
            f"{sample['flow_id']}: ml={sample['ml_prob']:.3f}, "
            f"threshold={sample['effective_review_threshold']}, "
            f"dst={sample['dst_ip']}:{sample['dst_port']}/{sample['protocol']}, "
            f"item={sample['watchlist_item']}, strength={sample['match_strength']}"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
