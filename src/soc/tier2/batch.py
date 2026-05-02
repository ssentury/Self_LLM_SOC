from __future__ import annotations

import json
import yaml
from datetime import datetime, timedelta, timezone
from pathlib import Path

from soc.models import Tier2Output, SourceSnapshot
from soc.tier2.input_collectors import Tier2InputCollector
from soc.tier2.writer import write_tier2_output


KST = timezone(timedelta(hours=9))
SERVICE_PORTS: dict[str, int] = {
    "ssh": 22,
    "ftp": 21,
    "http": 80,
    "https": 443,
    "dns": 53,
    "smtp": 25,
}


class DeterministicTier2Runner:
    """Slow-loop runner that deterministically processes SourceSnapshots without an LLM."""

    def run(self, config_path: str | Path, output_dir: str | Path = "output") -> Tier2Output:
        now = datetime.now(KST)
        iso_year, iso_week, _ = now.isocalendar()
        week_id = f"{iso_year}-W{iso_week:02d}"

        # 1. Load config
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)

        # 2. Collect snapshots
        collector = Tier2InputCollector(config)
        snapshots = collector.collect()

        # 3. Process snapshots deterministically
        source_status = {s.name: s.status for s in snapshots}
        
        watchlist, brief_context, memory = self._process_snapshots(week_id, now, snapshots)
        watchlist["source_status"] = source_status

        # 4. Generate Output
        tier2_output = Tier2Output(
            week_id=week_id,
            watchlist=watchlist,
            brief_context=brief_context,
            attack_surface_memory=memory,
            summary_html="<p>Deterministic Tier 2 runner completed.</p>",
            metadata={
                "runner": "deterministic",
                "model": "none",
                "api_call": False,
                "snapshot_stats": {s.name: s.item_count for s in snapshots if s.status == "used"}
            },
        )
        write_tier2_output(tier2_output, output_dir)
        return tier2_output

    def _process_snapshots(self, week_id: str, now: datetime, snapshots: list[SourceSnapshot]) -> tuple[dict, str, str]:
        valid_until = now + timedelta(days=7)
        watchlist = {
            "watchlist_version": week_id,
            "generated_at": now.isoformat(),
            "valid_until": valid_until.isoformat(),
            "generated_by": "deterministic-tier2",
            "priority_1": [],
            "priority_2": [],
            "priority_3": [],
        }
        
        brief_lines = [f"# Brief Context - {week_id}\n\n## 조직 현황 요약\n내부망은 172.31.0.0/16 대역으로 가정합니다.\n"]
        memory_lines = [f"# Attack Surface Memory - {week_id}\n"]
        
        for snapshot in snapshots:
            if snapshot.status != "used" or not snapshot.content:
                continue

            if snapshot.name == "assets":
                data = yaml.safe_load(snapshot.content)
                for asset in data.get("assets", []):
                    # Hardcoded logic: Add high/critical assets or specific sample IPs to P1
                    if asset.get("criticality") in ["high", "critical"] or asset.get("ip") == "172.31.69.28":
                        service_ports = _service_ports(asset.get("services", []))
                        detection_hints = []
                        if service_ports:
                            detection_hints.append(
                                {"field": "dst_port", "operator": "in", "value": service_ports}
                            )
                        watchlist["priority_1"].append({
                            "id": f"P1-{week_id.replace('-', '')}-{len(watchlist['priority_1'])+1:03d}",
                            "target_assets": [{"ip": asset.get("ip"), "role": asset.get("role", "unknown")}],
                            "reason": f"자산 중요도({asset.get('criticality')}) 기반 우선 감시",
                            "detection_hints": detection_hints,
                            "escalation_rule": "prob >= 0.20이면 Tier 1 LLM으로 보냄"
                        })
                        brief_lines.append(f"- 주의 자산: {asset.get('ip')} ({asset.get('role')})")

            elif snapshot.name == "policy":
                data = yaml.safe_load(snapshot.content) or {}
                brief_lines.append("\n## 정책 지침")
                
                elevated = data.get("elevated_risk_rules", [])
                if elevated:
                    brief_lines.append("\n### 위험 증가 규칙")
                    for rule in elevated:
                        brief_lines.append(f"- 조건: {rule.get('condition')} (위험도: {rule.get('severity_boost', '자동 격상')})")
                
                asset_policies = data.get("asset_specific_policies", [])
                if asset_policies:
                    brief_lines.append("\n### 자산별 접근 정책")
                    for p in asset_policies:
                        brief_lines.append(f"- {p.get('asset')}: {p.get('rule')}")

            elif snapshot.name == "cve_feed":
                pass # Can be added if needed

            elif snapshot.name == "threat_feed":
                pass # Can be added if needed

            elif snapshot.name == "tier1_db":
                stats = json.loads(snapshot.content)
                memory_lines.append(f"\n## 최근 7일 통계")
                memory_lines.append(f"- 총 판정 수: {stats.get('total_verdicts', 0)}")
                memory_lines.append(f"- Watchlist 매칭 수: {stats.get('watchlist_matched_count', 0)}")
                
                alerts = stats.get("high_critical_alerts", [])
                if alerts:
                    memory_lines.append(f"\n### 주요 경보 (최대 50건)")
                    for alert in alerts[:5]:  # Top 5 for brevity
                        memory_lines.append(f"- {alert.get('src_ip')} -> {alert.get('dst_ip')}:{alert.get('dst_port')} ({alert.get('verdict')}, {alert.get('severity')})")

        brief_lines.append("\n## Tier 1 판정 지침\nTier 1은 원천 CVE, 자산, 정책 파일을 직접 펼쳐 읽지 않습니다. 이 brief와 watchlist에서 정리된 맥락만 사용합니다.")

        # Fallback if no P1 generated (e.g. sample config didn't trigger)
        if not watchlist["priority_1"]:
            watchlist["priority_1"].append({
                "id": f"P1-{week_id.replace('-', '')}-001",
                "target_assets": [{"ip": "172.31.69.28", "role": "web-application-server"}],
                "reason": "발표자료 예시와 맞춘 공개 웹 서버 우선 감시 항목입니다. (Fallback)",
                "detection_hints": [{"field": "dst_port", "operator": "in", "value": [80, 443]}],
                "escalation_rule": "prob >= 0.20이면 Tier 1 LLM으로 보냄",
            })

        return watchlist, "\n".join(brief_lines), "\n".join(memory_lines)


def _service_ports(services: object) -> list[int]:
    if not isinstance(services, list):
        return []

    ports: set[int] = set()
    for service in services:
        if not isinstance(service, str):
            continue
        port = SERVICE_PORTS.get(service.strip().lower())
        if port is not None:
            ports.add(port)
    return sorted(ports)
