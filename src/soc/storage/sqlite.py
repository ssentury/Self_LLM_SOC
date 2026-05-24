from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from soc.models import Flow, MLResult, RouteDecision, SourceActivitySummary, Verdict


class SQLiteEventStore:
    def __init__(self, sqlite_path: str | Path) -> None:
        self.sqlite_path = Path(sqlite_path)

    def initialize(self) -> None:
        if self.sqlite_path.parent:
            self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS flows (
                    flow_id TEXT PRIMARY KEY,
                    start_ms INTEGER,
                    end_ms INTEGER,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    raw_label TEXT,
                    raw_attack TEXT,
                    features_json TEXT,
                    created_at TEXT
                );

                CREATE TABLE IF NOT EXISTS ml_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id TEXT,
                    prob REAL,
                    category_hint TEXT,
                    category_confidence REAL,
                    shap_top5_json TEXT
                );

                CREATE TABLE IF NOT EXISTS route_decisions (
                    flow_id TEXT PRIMARY KEY,
                    route TEXT,
                    reason TEXT,
                    threshold_low REAL,
                    threshold_high REAL,
                    adjusted_by_watchlist INTEGER,
                    ml_prob REAL,
                    effective_review_threshold REAL,
                    dynamic_threshold_applied INTEGER,
                    dynamic_threshold_reason TEXT
                );

                CREATE TABLE IF NOT EXISTS verdicts (
                    flow_id TEXT PRIMARY KEY,
                    verdict TEXT,
                    severity TEXT,
                    rationale_ko TEXT,
                    recommended_action_ko TEXT,
                    watchlist_matched TEXT,
                    confidence REAL,
                    fallback_source TEXT,
                    fallback_reason TEXT
                );

                CREATE TABLE IF NOT EXISTS tier1_calls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id TEXT,
                    provider TEXT,
                    model_name TEXT,
                    latency_ms REAL,
                    tokens_used INTEGER,
                    prompt_tokens INTEGER,
                    completion_tokens INTEGER,
                    success INTEGER,
                    fallback_reason TEXT,
                    created_at TEXT
                );
                """
            )
            _ensure_column(conn, "tier1_calls", "prompt_tokens", "INTEGER")
            _ensure_column(conn, "tier1_calls", "completion_tokens", "INTEGER")
            _ensure_column(conn, "route_decisions", "effective_review_threshold", "REAL")
            _ensure_column(conn, "route_decisions", "dynamic_threshold_applied", "INTEGER")
            _ensure_column(conn, "route_decisions", "dynamic_threshold_reason", "TEXT")

    def save_flow(self, flow: Flow) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO flows (
                    flow_id, start_ms, end_ms, src_ip, dst_ip, src_port, dst_port,
                    protocol, raw_label, raw_attack, features_json, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    flow.flow_id,
                    flow.start_ms,
                    flow.end_ms,
                    flow.src_ip,
                    flow.dst_ip,
                    flow.src_port,
                    flow.dst_port,
                    flow.protocol,
                    flow.raw_label,
                    flow.raw_attack,
                    _json_dumps(flow.features),
                    _now_iso(),
                ),
            )

    def save_ml_result(self, flow_id: str, ml: MLResult) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM ml_results WHERE flow_id = ?", (flow_id,))
            conn.execute(
                """
                INSERT INTO ml_results (
                    flow_id, prob, category_hint, category_confidence, shap_top5_json
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    flow_id,
                    ml.prob,
                    ml.category_hint,
                    ml.category_confidence,
                    _json_dumps(ml.shap_top5),
                ),
            )

    def save_route_decision(self, flow_id: str, route: RouteDecision) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO route_decisions (
                    flow_id, route, reason, threshold_low, threshold_high,
                    adjusted_by_watchlist, ml_prob, effective_review_threshold,
                    dynamic_threshold_applied, dynamic_threshold_reason
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    flow_id,
                    route.route,
                    route.reason,
                    route.threshold_low,
                    route.threshold_high,
                    int(route.adjusted_by_watchlist),
                    route.ml_prob,
                    route.effective_review_threshold,
                    int(route.dynamic_threshold_applied),
                    route.dynamic_threshold_reason,
                ),
            )

    def save_verdict(self, flow_id: str, verdict: Verdict) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO verdicts (
                    flow_id, verdict, severity, rationale_ko, recommended_action_ko,
                    watchlist_matched, confidence, fallback_source, fallback_reason
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    flow_id,
                    verdict.verdict,
                    verdict.severity,
                    verdict.rationale_ko,
                    verdict.recommended_action_ko,
                    verdict.watchlist_matched,
                    verdict.confidence,
                    verdict.fallback_source,
                    verdict.fallback_reason,
                ),
            )

    def save_tier1_call(
        self,
        flow_id: str,
        provider: str,
        model_name: str | None = None,
        latency_ms: float | None = None,
        tokens_used: int | None = None,
        prompt_tokens: int | None = None,
        completion_tokens: int | None = None,
        success: bool = True,
        fallback_reason: str | None = None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO tier1_calls (
                    flow_id, provider, model_name, latency_ms, tokens_used,
                    prompt_tokens, completion_tokens, success, fallback_reason,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    flow_id,
                    provider,
                    model_name,
                    latency_ms,
                    tokens_used,
                    prompt_tokens,
                    completion_tokens,
                    int(success),
                    fallback_reason,
                    _now_iso(),
                ),
            )

    def summarize_source_activity(
        self,
        src_ip: str,
        before_time: int | None,
        window_minutes: int = 10,
        dst_ip: str | None = None,
        dst_port: int | None = None,
        protocol: str | None = None,
    ) -> SourceActivitySummary:
        params: list[Any] = [src_ip]
        clauses = ["f.src_ip = ?"]
        if before_time is not None:
            clauses.append("f.start_ms IS NOT NULL")
            clauses.append("f.start_ms < ?")
            params.append(before_time)
            clauses.append("f.start_ms >= ?")
            params.append(before_time - window_minutes * 60 * 1000)

        where_sql = " AND ".join(clauses)
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT f.dst_ip, f.dst_port, f.protocol, v.verdict, v.watchlist_matched
                FROM flows f
                LEFT JOIN verdicts v ON v.flow_id = f.flow_id
                WHERE {where_sql}
                ORDER BY COALESCE(f.start_ms, 0) DESC
                """,
                params,
            ).fetchall()

        dst_ips = {str(row["dst_ip"]) for row in rows if row["dst_ip"] is not None}
        port_counts: dict[int, int] = {}
        recent_verdicts: list[str] = []
        same_dst_count = 0
        same_dst_port_count = 0
        watchlist_hit_count = 0
        recent_alert_count = 0
        for row in rows:
            if row["dst_port"] is not None:
                port = int(row["dst_port"])
                port_counts[port] = port_counts.get(port, 0) + 1
            same_dst = dst_ip is not None and str(row["dst_ip"]) == str(dst_ip)
            if same_dst:
                same_dst_count += 1
                if (
                    dst_port is not None
                    and row["dst_port"] is not None
                    and int(row["dst_port"]) == int(dst_port)
                    and (protocol is None or str(row["protocol"]) == str(protocol))
                ):
                    same_dst_port_count += 1
            if row["verdict"] and len(recent_verdicts) < 5:
                verdict = str(row["verdict"])
                recent_verdicts.append(verdict)
                if verdict == "alert":
                    recent_alert_count += 1
            if row["watchlist_matched"]:
                watchlist_hit_count += 1

        top_dst_ports = [
            port for port, _ in sorted(port_counts.items(), key=lambda item: (-item[1], item[0]))[:5]
        ]
        return SourceActivitySummary(
            window_minutes=window_minutes,
            flow_count=len(rows),
            distinct_dst_count=len(dst_ips),
            top_dst_ports=top_dst_ports,
            recent_verdicts=recent_verdicts,
            same_src_same_dst_count=same_dst_count,
            same_src_same_dst_port_count=same_dst_port_count,
            watchlist_hit_count=watchlist_hit_count,
            recent_alert_count=recent_alert_count,
            summary_ko=(
                f"최근 {window_minutes}분 기준 DB에서 같은 출발지 flow "
                f"{len(rows)}건, 목적지 {len(dst_ips)}개를 확인했습니다."
            ),
        )

    def get_tier1_stats_snapshot(self, days: int = 7) -> dict[str, Any]:
        """Collects Tier 1 statistics for the Batch Loop."""
        import time
        from datetime import timedelta, timezone
        
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(days=days)
        start_iso = start_time.isoformat()

        stats: dict[str, Any] = {
            "period_days": days,
            "total_verdicts": 0,
            "verdict_distribution": {},
            "watchlist_matched_count": 0,
            "route_distribution": {},
            "fallback_count": 0,
            "high_critical_alerts": [],
        }

        with self._connect() as conn:
            # 1. Route counts
            route_rows = conn.execute(
                """
                SELECT r.route, COUNT(*) as cnt
                FROM route_decisions r
                JOIN flows f ON r.flow_id = f.flow_id
                WHERE f.created_at >= ?
                GROUP BY r.route
                """,
                (start_iso,)
            ).fetchall()
            for row in route_rows:
                stats["route_distribution"][str(row["route"])] = int(row["cnt"])

            # 2. Verdict stats
            verdict_rows = conn.execute(
                """
                SELECT v.verdict, v.watchlist_matched, v.fallback_source, v.severity, f.src_ip, f.dst_ip, f.dst_port
                FROM verdicts v
                JOIN flows f ON v.flow_id = f.flow_id
                WHERE f.created_at >= ?
                """,
                (start_iso,)
            ).fetchall()

            stats["total_verdicts"] = len(verdict_rows)
            for row in verdict_rows:
                v = str(row["verdict"]) if row["verdict"] else "unknown"
                stats["verdict_distribution"][v] = stats["verdict_distribution"].get(v, 0) + 1
                
                if row["watchlist_matched"]:
                    stats["watchlist_matched_count"] += 1
                
                if row["fallback_source"]:
                    stats["fallback_count"] += 1
                
                severity = str(row["severity"]).lower() if row["severity"] else ""
                if severity in ["high", "critical"] or v == "alert":
                    if len(stats["high_critical_alerts"]) < 50:  # Cap the summary list
                        stats["high_critical_alerts"].append({
                            "src_ip": row["src_ip"],
                            "dst_ip": row["dst_ip"],
                            "dst_port": row["dst_port"],
                            "verdict": v,
                            "severity": severity
                        })

        return stats

    def list_recent_flow_events(self, limit: int = 50) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    f.flow_id, f.start_ms, f.end_ms, f.src_ip, f.dst_ip,
                    f.src_port, f.dst_port, f.protocol, f.raw_label, f.raw_attack,
                    f.created_at,
                    m.prob, m.category_hint, m.category_confidence,
                    r.route, r.reason AS route_reason, r.adjusted_by_watchlist,
                    r.effective_review_threshold, r.dynamic_threshold_applied,
                    r.dynamic_threshold_reason,
                    v.verdict, v.severity, v.watchlist_matched,
                    v.fallback_source, v.fallback_reason
                FROM flows f
                LEFT JOIN ml_results m ON m.flow_id = f.flow_id
                LEFT JOIN route_decisions r ON r.flow_id = f.flow_id
                LEFT JOIN verdicts v ON v.flow_id = f.flow_id
                ORDER BY COALESCE(f.start_ms, 0) DESC, f.created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [_row_to_dict(row) for row in rows]

    def list_report_events(
        self,
        *,
        limit: int = 250,
        date: str | None = None,
        severity: str | None = None,
        verdict: str | None = None,
        asset: str | None = None,
        watchlist_hit: bool | None = None,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        clauses: list[str] = []
        params: list[Any] = []
        if severity:
            clauses.append("LOWER(v.severity) = LOWER(?)")
            params.append(severity)
        if verdict:
            clauses.append("LOWER(v.verdict) = LOWER(?)")
            params.append(verdict)
        if asset:
            clauses.append("(f.src_ip = ? OR f.dst_ip = ?)")
            params.extend([asset, asset])
        if watchlist_hit is True:
            clauses.append("v.watchlist_matched IS NOT NULL AND v.watchlist_matched != ''")
        elif watchlist_hit is False:
            clauses.append("(v.watchlist_matched IS NULL OR v.watchlist_matched = '')")

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT
                    f.flow_id, f.start_ms, f.end_ms, f.src_ip, f.dst_ip,
                    f.src_port, f.dst_port, f.protocol, f.raw_label, f.raw_attack,
                    f.created_at,
                    m.prob, m.category_hint, m.category_confidence,
                    r.route, r.reason AS route_reason, r.adjusted_by_watchlist,
                    r.effective_review_threshold, r.dynamic_threshold_applied,
                    r.dynamic_threshold_reason,
                    v.verdict, v.severity, v.watchlist_matched,
                    v.fallback_source, v.fallback_reason
                FROM flows f
                LEFT JOIN ml_results m ON m.flow_id = f.flow_id
                LEFT JOIN route_decisions r ON r.flow_id = f.flow_id
                LEFT JOIN verdicts v ON v.flow_id = f.flow_id
                {where_sql}
                ORDER BY COALESCE(f.start_ms, 0) DESC, f.created_at DESC
                LIMIT ?
                """,
                (*params, limit),
            ).fetchall()

        events = [_row_to_dict(row) for row in rows]
        if date:
            events = [event for event in events if _event_date(event) == date]
        return events

    def get_report_filter_options(self) -> dict[str, list[str]]:
        with self._connect() as conn:
            date_rows = conn.execute(
                """
                SELECT start_ms, created_at
                FROM flows
                ORDER BY COALESCE(start_ms, 0) DESC, created_at DESC
                LIMIT 1000
                """
            ).fetchall()
            severity_rows = conn.execute(
                """
                SELECT DISTINCT severity
                FROM verdicts
                WHERE severity IS NOT NULL AND severity != ''
                ORDER BY severity
                """
            ).fetchall()
            verdict_rows = conn.execute(
                """
                SELECT DISTINCT verdict
                FROM verdicts
                WHERE verdict IS NOT NULL AND verdict != ''
                ORDER BY verdict
                """
            ).fetchall()
            asset_rows = conn.execute(
                """
                SELECT src_ip AS asset FROM flows WHERE src_ip IS NOT NULL AND src_ip != ''
                UNION
                SELECT dst_ip AS asset FROM flows WHERE dst_ip IS NOT NULL AND dst_ip != ''
                ORDER BY asset
                LIMIT 250
                """
            ).fetchall()

        dates = sorted(
            {
                value
                for row in date_rows
                for value in [_date_from_row(row["start_ms"], row["created_at"])]
                if value
            },
            reverse=True,
        )
        return {
            "dates": dates,
            "severities": [str(row["severity"]) for row in severity_rows],
            "verdicts": [str(row["verdict"]) for row in verdict_rows],
            "assets": [str(row["asset"]) for row in asset_rows],
        }

    def get_flow_event_detail(self, flow_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    f.flow_id, f.start_ms, f.end_ms, f.src_ip, f.dst_ip,
                    f.src_port, f.dst_port, f.protocol, f.raw_label, f.raw_attack,
                    f.features_json, f.created_at,
                    m.prob, m.category_hint, m.category_confidence,
                    m.shap_top5_json,
                    r.route, r.reason AS route_reason, r.threshold_low,
                    r.threshold_high, r.adjusted_by_watchlist, r.ml_prob,
                    r.effective_review_threshold, r.dynamic_threshold_applied,
                    r.dynamic_threshold_reason,
                    v.verdict, v.severity, v.rationale_ko,
                    v.recommended_action_ko, v.watchlist_matched, v.confidence,
                    v.fallback_source, v.fallback_reason
                FROM flows f
                LEFT JOIN ml_results m ON m.flow_id = f.flow_id
                LEFT JOIN route_decisions r ON r.flow_id = f.flow_id
                LEFT JOIN verdicts v ON v.flow_id = f.flow_id
                WHERE f.flow_id = ?
                """,
                (flow_id,),
            ).fetchone()
            if row is None:
                return None
            tier1_calls = conn.execute(
                """
                SELECT provider, model_name, latency_ms, tokens_used,
                       prompt_tokens, completion_tokens, success,
                       fallback_reason, created_at
                FROM tier1_calls
                WHERE flow_id = ?
                ORDER BY created_at DESC
                """,
                (flow_id,),
            ).fetchall()

        detail = _row_to_dict(row)
        detail["features"] = _json_loads(detail.pop("features_json", None), {})
        detail["shap_top5"] = _json_loads(detail.pop("shap_top5_json", None), [])
        detail["tier1_calls"] = [_row_to_dict(call) for call in tier1_calls]
        return detail

    def get_runtime_status(self) -> dict[str, Any]:
        with self._connect() as conn:
            tables = {
                table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in (
                    "flows",
                    "ml_results",
                    "route_decisions",
                    "verdicts",
                    "tier1_calls",
                )
            }
            route_rows = conn.execute(
                "SELECT route, COUNT(*) AS count FROM route_decisions GROUP BY route"
            ).fetchall()
            verdict_rows = conn.execute(
                "SELECT verdict, COUNT(*) AS count FROM verdicts GROUP BY verdict"
            ).fetchall()
            fallback_rows = conn.execute(
                """
                SELECT fallback_source, COUNT(*) AS count
                FROM verdicts
                WHERE fallback_source IS NOT NULL
                GROUP BY fallback_source
                """
            ).fetchall()
        return {
            "sqlite_path": str(self.sqlite_path),
            "tables": tables,
            "routes": {str(row["route"]): int(row["count"]) for row in route_rows},
            "verdicts": {str(row["verdict"]): int(row["count"]) for row in verdict_rows},
            "fallbacks": {
                str(row["fallback_source"]): int(row["count"]) for row in fallback_rows
            },
        }

    def clear_all_events(self) -> dict[str, int]:
        """Delete all rows from every event table. Returns deleted row counts."""
        tables = ("tier1_calls", "verdicts", "route_decisions", "ml_results", "flows")
        deleted: dict[str, int] = {}
        with self._connect() as conn:
            for table in tables:
                count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                conn.execute(f"DELETE FROM {table}")
                deleted[table] = int(count)
        return deleted

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.sqlite_path)
        conn.row_factory = sqlite3.Row
        return conn


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _json_loads(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(str(value))
    except json.JSONDecodeError:
        return default


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    for key in ("adjusted_by_watchlist", "dynamic_threshold_applied", "success"):
        if key in data and data[key] is not None:
            data[key] = bool(data[key])

    if data.get("verdict") is None:
        if data.get("route") == "tier1_llm":
            data["processing_state"] = "tier1_processing"
            data["verdict"] = "processing"
            data["severity"] = "pending"
        elif data.get("route"):
            data["processing_state"] = "route_processing"
        else:
            data["processing_state"] = "ingested"
    else:
        data["processing_state"] = "complete"

    return data


def _event_date(event: dict[str, Any]) -> str | None:
    return _date_from_row(event.get("start_ms"), event.get("created_at"))


def _date_from_row(start_ms: Any, created_at: Any) -> str | None:
    if start_ms is not None:
        try:
            return datetime.fromtimestamp(int(start_ms) / 1000, timezone.utc).date().isoformat()
        except (TypeError, ValueError, OSError):
            pass
    if created_at:
        try:
            return datetime.fromisoformat(str(created_at)).date().isoformat()
        except ValueError:
            return str(created_at)[:10] or None
    return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_column(
    conn: sqlite3.Connection,
    table: str,
    column: str,
    column_type: str,
) -> None:
    columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")
