from __future__ import annotations

import asyncio
import json
import shutil
import sqlite3
from collections import Counter
from contextlib import closing
from datetime import date, datetime, time, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from soc.llm.provider import LLMProvider


RISK_LABELS = {
    "quiet": "Quiet",
    "needs_review": "Needs Review",
    "high_attention": "High Attention",
}

SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}

DAILY_SUMMARY_SYSTEM_PROMPT = """
You are the Tier 2 SOC analyst writing the operator daily summary.
Return strict JSON only with this shape:
{
  "easy_summary_ko": "Korean operator-facing paragraph",
  "first_checks_ko": ["Korean action item", "Korean action item"]
}

Rules:
- Write concise Korean for a SOC operator.
- Do not change or invent counts, IPs, ports, flow IDs, labels, or watchlist hit counts.
- Use only the provided aggregate data and highlighted flows.
- Keep first_checks_ko to 2-4 concrete checks.
- Do not include markdown fences.
""".strip()


def run_daily_summary(
    sqlite_path: str | Path,
    output_dir: str | Path,
    *,
    summary_date: date | str | None = None,
    timezone_name: str = "Asia/Seoul",
    max_alerts: int = 5,
    llm_provider: LLMProvider | None = None,
    llm_provider_name: str = "",
    llm_model: str = "",
    llm_max_tokens: int = 16384,
    llm_temperature: float = 0.3,
) -> dict[str, Any]:
    summary = build_daily_summary(
        sqlite_path,
        summary_date=summary_date,
        timezone_name=timezone_name,
        max_alerts=max_alerts,
    )
    if llm_provider is not None:
        summary = apply_llm_daily_summary(
            summary,
            llm_provider,
            provider_name=llm_provider_name,
            configured_model=llm_model,
            max_tokens=llm_max_tokens,
            temperature=llm_temperature,
        )
    write_daily_summary(summary, output_dir)
    return summary


def build_daily_summary(
    sqlite_path: str | Path,
    *,
    summary_date: date | str | None = None,
    timezone_name: str = "Asia/Seoul",
    max_alerts: int = 5,
) -> dict[str, Any]:
    local_tz = ZoneInfo(timezone_name)
    target_date = _coerce_date(summary_date, local_tz)
    day_start, day_end = _day_bounds(target_date, local_tz)
    rows = _load_daily_rows(sqlite_path, day_start, day_end)
    tier1_calls = _load_tier1_call_stats(sqlite_path, day_start, day_end)

    route_counts = Counter(_countable(row["route"]) for row in rows)
    verdict_counts = Counter(_countable(row["verdict"]) for row in rows)
    severity_counts = Counter(_countable(row["severity"]) for row in rows)
    fallback_counts = Counter(
        str(row["fallback_source"])
        for row in rows
        if row["fallback_source"]
    )
    watchlist_hits = sum(1 for row in rows if row["watchlist_matched"])
    dynamic_threshold_applied = sum(1 for row in rows if row["dynamic_threshold_applied"])
    top_alerts = _top_alerts(rows, local_tz, max_alerts)
    top_review_sources = _top_review_sources(rows)
    top_target_assets = _top_target_assets(rows)
    risk_level = _risk_level(verdict_counts, severity_counts, fallback_counts)

    summary: dict[str, Any] = {
        "date": target_date.isoformat(),
        "timezone": timezone_name,
        "window": {
            "start": day_start.isoformat(),
            "end": day_end.isoformat(),
        },
        "risk_level": risk_level,
        "risk_label": RISK_LABELS[risk_level],
        "flow_count": len(rows),
        "route_counts": dict(sorted(route_counts.items())),
        "verdict_counts": dict(sorted(verdict_counts.items())),
        "severity_counts": dict(sorted(severity_counts.items())),
        "watchlist_hit_count": watchlist_hits,
        "dynamic_threshold_applied_count": dynamic_threshold_applied,
        "fallback_counts": dict(sorted(fallback_counts.items())),
        "tier1_calls": tier1_calls,
        "top_alerts": top_alerts,
        "top_review_sources": top_review_sources,
        "top_target_assets": top_target_assets,
        "generation": {
            "mode": "deterministic_sqlite",
            "llm_called": False,
            "source": "sqlite_event_store",
        },
    }
    summary["easy_summary_ko"] = _easy_summary_ko(summary)
    summary["first_checks_ko"] = _first_checks_ko(summary)
    return summary


def write_daily_summary(summary: dict[str, Any], output_dir: str | Path) -> dict[str, Path]:
    base = Path(output_dir)
    base.mkdir(parents=True, exist_ok=True)
    stem = f"summary_{summary['date']}"
    json_path = base / f"{stem}.json"
    markdown_path = base / f"{stem}.md"

    json_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    markdown_path.write_text(render_daily_summary_markdown(summary), encoding="utf-8")
    shutil.copyfile(json_path, base / "latest.json")
    shutil.copyfile(markdown_path, base / "latest.md")
    return {
        "json": json_path,
        "markdown": markdown_path,
        "latest_json": base / "latest.json",
        "latest_markdown": base / "latest.md",
    }


def render_daily_summary_markdown(summary: dict[str, Any]) -> str:
    lines = [
        f"# Daily Easy Summary - {summary['date']}",
        "",
        f"- Timezone: `{summary['timezone']}`",
        f"- Risk level: **{summary['risk_label']}**",
        f"- Processed flows: {summary['flow_count']}",
        f"- Watchlist hits: {summary['watchlist_hit_count']}",
        "",
        "## Easy Summary",
        "",
        str(summary["easy_summary_ko"]),
        "",
        "## Daily Counts",
        "",
        f"- Routes: `{summary['route_counts']}`",
        f"- Verdicts: `{summary['verdict_counts']}`",
        f"- Severities: `{summary['severity_counts']}`",
        f"- Dynamic review thresholds applied: {summary['dynamic_threshold_applied_count']}",
        f"- Fallbacks: `{summary['fallback_counts']}`",
        _generation_markdown_line(summary),
        (
            "- Tier 1 calls: "
            f"{summary['tier1_calls']['total']} total, "
            f"{summary['tier1_calls']['failed']} failed/fallback"
        ),
        "",
        "## First Checks",
        "",
    ]
    for index, item in enumerate(summary["first_checks_ko"], start=1):
        lines.append(f"{index}. {item}")

    lines.extend(["", "## Important Alerts", ""])
    if summary["top_alerts"]:
        for item in summary["top_alerts"]:
            watchlist = item["watchlist_matched"] or "none"
            lines.append(
                "- "
                f"`{item['flow_id']}` at {item['time']} - "
                f"{item['src_ip']} -> {item['dst_ip']}:{item['dst_port']} "
                f"({item['route']}, prob={item['ml_prob']:.3f}, "
                f"{item['severity']}, watchlist={watchlist})"
            )
    else:
        lines.append("- No alert verdicts were stored for this day.")

    lines.extend(["", "## Review Hotspots", ""])
    if summary["top_review_sources"]:
        source_text = ", ".join(
            f"{item['src_ip']} ({item['count']})"
            for item in summary["top_review_sources"]
        )
        lines.append(f"- Review sources: {source_text}")
    else:
        lines.append("- Review sources: none")
    if summary["top_target_assets"]:
        target_text = ", ".join(
            f"{item['dst_ip']}:{item['dst_port']} ({item['count']})"
            for item in summary["top_target_assets"]
        )
        lines.append(f"- Target assets: {target_text}")
    else:
        lines.append("- Target assets: none")
    lines.append("")
    return "\n".join(lines)


def apply_llm_daily_summary(
    summary: dict[str, Any],
    provider: LLMProvider,
    *,
    provider_name: str,
    configured_model: str,
    max_tokens: int,
    temperature: float,
) -> dict[str, Any]:
    try:
        response = asyncio.run(
            provider.generate(
                DAILY_SUMMARY_SYSTEM_PROMPT,
                json.dumps(_llm_summary_payload(summary), ensure_ascii=False, indent=2),
                max_tokens=max_tokens,
                temperature=temperature,
                response_format="json",
            )
        )
        data = _parse_json_object(response.content)
        _merge_llm_summary(summary, data)
        summary["generation"] = {
            "mode": "tier2_llm",
            "llm_called": True,
            "fallback": False,
            "provider": provider_name,
            "configured_model": configured_model,
            "model": response.model_name,
            "tokens_used": response.tokens_used,
            "prompt_tokens": response.prompt_tokens,
            "completion_tokens": response.completion_tokens,
            "latency_ms": response.latency_ms,
        }
    except Exception as exc:
        summary["generation"] = {
            "mode": "tier2_llm_fallback",
            "llm_called": True,
            "fallback": True,
            "provider": provider_name,
            "configured_model": configured_model,
            "fallback_reason": f"{type(exc).__name__}: {exc}",
        }
    return summary


def _llm_summary_payload(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "date": summary.get("date"),
        "timezone": summary.get("timezone"),
        "risk_level": summary.get("risk_level"),
        "risk_label": summary.get("risk_label"),
        "flow_count": summary.get("flow_count"),
        "route_counts": summary.get("route_counts"),
        "verdict_counts": summary.get("verdict_counts"),
        "severity_counts": summary.get("severity_counts"),
        "watchlist_hit_count": summary.get("watchlist_hit_count"),
        "dynamic_threshold_applied_count": summary.get("dynamic_threshold_applied_count"),
        "fallback_counts": summary.get("fallback_counts"),
        "tier1_calls": summary.get("tier1_calls"),
        "top_alerts": summary.get("top_alerts"),
        "top_review_sources": summary.get("top_review_sources"),
        "top_target_assets": summary.get("top_target_assets"),
    }


def _parse_json_object(text: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = _parse_embedded_json_object(text)
    if not isinstance(data, dict):
        raise ValueError("LLM daily summary response must be a JSON object")
    return data


def _parse_embedded_json_object(text: str) -> dict[str, Any]:
    decoder = json.JSONDecoder()
    index = 0
    while index < len(text):
        start = text.find("{", index)
        if start == -1:
            break
        try:
            data, end = decoder.raw_decode(text[start:])
        except json.JSONDecodeError:
            index = start + 1
            continue
        if isinstance(data, dict):
            return data
        index = start + max(1, end)
    raise ValueError("LLM daily summary response did not contain a JSON object")


def _merge_llm_summary(summary: dict[str, Any], data: dict[str, Any]) -> None:
    easy_summary = str(data.get("easy_summary_ko") or "").strip()
    checks = [
        str(item).strip()
        for item in data.get("first_checks_ko", [])
        if str(item).strip()
    ] if isinstance(data.get("first_checks_ko"), list) else []
    if not easy_summary:
        raise ValueError("LLM daily summary omitted easy_summary_ko")
    if not checks:
        raise ValueError("LLM daily summary omitted first_checks_ko")
    summary["easy_summary_ko"] = easy_summary
    summary["first_checks_ko"] = checks[:4]


def _generation_markdown_line(summary: dict[str, Any]) -> str:
    generation = summary.get("generation") or {}
    mode = str(generation.get("mode") or "deterministic_sqlite")
    if mode == "tier2_llm":
        provider = generation.get("provider") or "tier2"
        model = generation.get("model") or generation.get("configured_model") or "-"
        return f"- Generation: Tier 2 LLM summary (`{provider}` / `{model}`)"
    if mode == "tier2_llm_fallback":
        reason = generation.get("fallback_reason") or "unknown"
        return f"- Generation: Tier 2 LLM attempted; deterministic fallback used ({reason})"
    return "- Generation: deterministic SQLite aggregation (no LLM call)"


def _load_daily_rows(
    sqlite_path: str | Path,
    day_start: datetime,
    day_end: datetime,
) -> list[sqlite3.Row]:
    path = Path(sqlite_path)
    if not path.exists():
        raise FileNotFoundError(f"SQLite event store does not exist: {path}")

    params = (
        _epoch_ms(day_start),
        _epoch_ms(day_end),
        day_start.astimezone(timezone.utc).isoformat(),
        day_end.astimezone(timezone.utc).isoformat(),
    )
    with closing(sqlite3.connect(path)) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(
            """
            SELECT
                f.flow_id,
                f.start_ms,
                f.created_at,
                f.src_ip,
                f.dst_ip,
                f.dst_port,
                r.route,
                r.ml_prob,
                r.dynamic_threshold_applied,
                v.verdict,
                v.severity,
                v.rationale_ko,
                v.recommended_action_ko,
                v.watchlist_matched,
                v.fallback_source
            FROM flows f
            LEFT JOIN route_decisions r ON r.flow_id = f.flow_id
            LEFT JOIN verdicts v ON v.flow_id = f.flow_id
            WHERE (
                f.start_ms IS NOT NULL
                AND f.start_ms >= ?
                AND f.start_ms < ?
            ) OR (
                f.start_ms IS NULL
                AND f.created_at >= ?
                AND f.created_at < ?
            )
            ORDER BY COALESCE(f.start_ms, 0), f.flow_id
            """,
            params,
        ).fetchall()


def _load_tier1_call_stats(
    sqlite_path: str | Path,
    day_start: datetime,
    day_end: datetime,
) -> dict[str, Any]:
    params = (
        _epoch_ms(day_start),
        _epoch_ms(day_end),
        day_start.astimezone(timezone.utc).isoformat(),
        day_end.astimezone(timezone.utc).isoformat(),
    )
    with closing(sqlite3.connect(sqlite_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT
                COUNT(t.id) AS total,
                SUM(CASE WHEN t.success = 0 THEN 1 ELSE 0 END) AS failed,
                AVG(t.latency_ms) AS avg_latency_ms,
                MAX(t.latency_ms) AS max_latency_ms,
                SUM(COALESCE(t.tokens_used, 0)) AS tokens_used
            FROM flows f
            JOIN tier1_calls t ON t.flow_id = f.flow_id
            WHERE (
                f.start_ms IS NOT NULL
                AND f.start_ms >= ?
                AND f.start_ms < ?
            ) OR (
                f.start_ms IS NULL
                AND f.created_at >= ?
                AND f.created_at < ?
            )
            """,
            params,
        ).fetchone()
    return {
        "total": int(row["total"] or 0),
        "failed": int(row["failed"] or 0),
        "avg_latency_ms": _optional_float(row["avg_latency_ms"]),
        "max_latency_ms": _optional_float(row["max_latency_ms"]),
        "tokens_used": int(row["tokens_used"] or 0),
    }


def _top_alerts(rows: list[sqlite3.Row], local_tz: ZoneInfo, limit: int) -> list[dict[str, Any]]:
    alerts = [row for row in rows if row["verdict"] == "alert"]
    alerts.sort(
        key=lambda row: (
            -SEVERITY_RANK.get(str(row["severity"]).lower(), 0),
            -float(row["ml_prob"] or 0.0),
            int(row["start_ms"] or 0),
            str(row["flow_id"]),
        )
    )
    return [
        {
            "flow_id": str(row["flow_id"]),
            "time": _row_time(row, local_tz),
            "src_ip": str(row["src_ip"]),
            "dst_ip": str(row["dst_ip"]),
            "dst_port": int(row["dst_port"] or 0),
            "route": _countable(row["route"]),
            "ml_prob": float(row["ml_prob"] or 0.0),
            "severity": _countable(row["severity"]),
            "watchlist_matched": str(row["watchlist_matched"]) if row["watchlist_matched"] else None,
            "rationale_ko": str(row["rationale_ko"] or ""),
            "recommended_action_ko": str(row["recommended_action_ko"] or ""),
        }
        for row in alerts[: max(0, limit)]
    ]


def _top_review_sources(rows: list[sqlite3.Row], limit: int = 5) -> list[dict[str, Any]]:
    counts = Counter(
        str(row["src_ip"])
        for row in rows
        if row["verdict"] in {"alert", "uncertain"} and row["src_ip"]
    )
    return [
        {"src_ip": src_ip, "count": count}
        for src_ip, count in counts.most_common(limit)
    ]


def _top_target_assets(rows: list[sqlite3.Row], limit: int = 5) -> list[dict[str, Any]]:
    counts = Counter(
        (str(row["dst_ip"]), int(row["dst_port"] or 0))
        for row in rows
        if row["verdict"] in {"alert", "uncertain"} and row["dst_ip"]
    )
    return [
        {"dst_ip": dst_ip, "dst_port": dst_port, "count": count}
        for (dst_ip, dst_port), count in counts.most_common(limit)
    ]


def _easy_summary_ko(summary: dict[str, Any]) -> str:
    route_counts = summary["route_counts"]
    verdict_counts = summary["verdict_counts"]
    alerts = int(verdict_counts.get("alert", 0))
    uncertain = int(verdict_counts.get("uncertain", 0))
    dismissed = int(route_counts.get("auto_dismiss", 0))
    reviewed = int(route_counts.get("tier1_llm", 0))
    auto_alerts = int(route_counts.get("auto_alert", 0))

    if summary["flow_count"] == 0:
        return (
            "이 날짜에는 저장된 realtime flow 결과가 없습니다. 입력 수집 상태와 "
            "Realtime Loop 실행 여부를 먼저 확인하세요."
        )

    opening = (
        f"오늘 Realtime Loop는 flow {summary['flow_count']}건을 처리했고, "
        f"ML이 {dismissed}건을 자동 기각했으며 {reviewed}건을 Tier 1 검토 경로로 보냈습니다."
    )
    alert_text = (
        f"최종 alert는 {alerts}건이고 ML 고위험 자동 경보 경로는 {auto_alerts}건이었습니다."
        if alerts
        else "최종 alert는 없었습니다."
    )
    review_text = (
        f"아직 해석이 필요한 uncertain 결과가 {uncertain}건 남아 있습니다."
        if uncertain
        else "uncertain 결과는 남지 않았습니다."
    )
    watchlist_text = (
        f"Tier 2 watchlist는 {summary['watchlist_hit_count']}건의 흐름에 맥락을 제공했습니다."
    )
    fallback_total = sum(int(value) for value in summary["fallback_counts"].values())
    fallback_text = (
        f" fallback 결과가 {fallback_total}건 있어 queue 정책과 provider 오류를 구분해 확인해야 합니다."
        if fallback_total
        else ""
    )
    return " ".join([opening, alert_text, review_text, watchlist_text]).strip() + fallback_text


def _first_checks_ko(summary: dict[str, Any]) -> list[str]:
    checks: list[str] = []
    if summary["top_alerts"]:
        first = summary["top_alerts"][0]
        checks.append(
            f"중요 alert `{first['flow_id']}`의 {first['src_ip']} -> "
            f"{first['dst_ip']}:{first['dst_port']} 흐름을 우선 확인하세요."
        )
    if summary["top_review_sources"]:
        source = summary["top_review_sources"][0]
        checks.append(
            f"alert 또는 uncertain 결과가 반복된 출발지 {source['src_ip']}의 "
            f"당일 흐름 {source['count']}건을 묶어서 검토하세요."
        )
    uncertain = int(summary["verdict_counts"].get("uncertain", 0))
    if uncertain:
        checks.append(f"uncertain 결과 {uncertain}건은 다음 근무 시작 전 수동 검토 대상으로 남기세요.")
    fallback_total = sum(int(value) for value in summary["fallback_counts"].values())
    if fallback_total:
        checks.append(
            f"fallback 결과 {fallback_total}건이 발생했으므로 Tier 1 queue와 provider 상태를 점검하세요."
        )
    if not checks:
        checks.append("중요 경보가 없으므로 최신 summary와 입력 source 상태만 확인하고 감시를 이어가세요.")
    return checks[:4]


def _risk_level(
    verdict_counts: Counter[str],
    severity_counts: Counter[str],
    fallback_counts: Counter[str],
) -> str:
    if verdict_counts.get("alert", 0) or severity_counts.get("critical", 0):
        return "high_attention"
    if verdict_counts.get("uncertain", 0) or sum(fallback_counts.values()):
        return "needs_review"
    return "quiet"


def _coerce_date(value: date | str | None, local_tz: ZoneInfo) -> date:
    if value is None:
        return datetime.now(local_tz).date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value))


def _day_bounds(target_date: date, local_tz: ZoneInfo) -> tuple[datetime, datetime]:
    day_start = datetime.combine(target_date, time.min, tzinfo=local_tz)
    day_end = datetime.combine(target_date.fromordinal(target_date.toordinal() + 1), time.min, tzinfo=local_tz)
    return day_start, day_end


def _epoch_ms(value: datetime) -> int:
    return int(value.timestamp() * 1000)


def _row_time(row: sqlite3.Row, local_tz: ZoneInfo) -> str:
    if row["start_ms"] is not None:
        return datetime.fromtimestamp(int(row["start_ms"]) / 1000, timezone.utc).astimezone(local_tz).isoformat()
    return str(row["created_at"] or "unknown")


def _countable(value: Any) -> str:
    if value in (None, ""):
        return "unknown"
    return str(value)


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    return float(value)
