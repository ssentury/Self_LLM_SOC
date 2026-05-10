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
                    ml_prob REAL
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
                    adjusted_by_watchlist, ml_prob
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    flow_id,
                    route.route,
                    route.reason,
                    route.threshold_low,
                    route.threshold_high,
                    int(route.adjusted_by_watchlist),
                    route.ml_prob,
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

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.sqlite_path)
        conn.row_factory = sqlite3.Row
        return conn


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


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
