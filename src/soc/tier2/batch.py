from __future__ import annotations

import asyncio
import json
import yaml
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from soc.llm.provider import GeminiProvider, LLMProvider, OllamaProvider
from soc.models import Tier2Output, SourceSnapshot
from soc.tier2.input_collectors import Tier2InputCollector
from soc.tier2.parser import ParsedTier2Artifacts, parse_tier2_response
from soc.tier2.prompt_builder import build_tier2_system_prompt, build_tier2_user_prompt
from soc.tier2.watchlist_quality import enhance_watchlist_quality
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


def run_tier2_from_config(
    config_path: str | Path,
    output_dir: str | Path = "output",
    overrides: dict[str, Any] | None = None,
) -> Tier2Output:
    config = _load_config(config_path)
    if overrides:
        _apply_tier2_overrides(config, overrides)

    provider = str(config.get("tier2", {}).get("provider", "deterministic"))
    if provider in {"deterministic", "fake"}:
        return DeterministicTier2Runner().run_config(config, output_dir)
    if provider == "ollama":
        return OllamaTier2Runner().run_config(config, output_dir)
    if provider == "gemini":
        return GeminiTier2Runner().run_config(config, output_dir)
    raise ValueError("tier2.provider must be one of: deterministic, fake, ollama, gemini")


class DeterministicTier2Runner:
    """Batch-loop runner that deterministically processes SourceSnapshots without an LLM."""

    def run(self, config_path: str | Path, output_dir: str | Path = "output") -> Tier2Output:
        return self.run_config(_load_config(config_path), output_dir)

    def run_config(self, config: dict[str, Any], output_dir: str | Path = "output") -> Tier2Output:
        now = datetime.now(KST)
        cycle_id = _cycle_id(now)

        collector = Tier2InputCollector(config)
        snapshots = collector.collect()
        source_status = {s.name: s.status for s in snapshots}
        
        watchlist, brief_context, memory = self._process_snapshots(cycle_id, now, snapshots)
        watchlist["source_status"] = source_status

        tier2_output = Tier2Output(
            cycle_id=cycle_id,
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

    def _process_snapshots(self, cycle_id: str, now: datetime, snapshots: list[SourceSnapshot]) -> tuple[dict, str, str]:
        valid_until = now + timedelta(days=7)
        watchlist = {
            "watchlist_version": cycle_id,
            "generated_at": now.isoformat(),
            "valid_until": valid_until.isoformat(),
            "generated_by": "deterministic-tier2",
            "priority_1": [],
            "priority_2": [],
            "priority_3": [],
        }
        
        brief_lines = [f"# Brief Context - {cycle_id}\n\n## 조직 현황 요약\n내부망은 172.31.0.0/16 대역으로 가정합니다.\n"]
        memory_lines = [f"# Attack Surface Memory - {cycle_id}\n"]
        
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
                            "id": f"P1-{cycle_id.replace('-', '')}-{len(watchlist['priority_1'])+1:03d}",
                            "target_assets": [{"ip": asset.get("ip"), "role": asset.get("role", "unknown")}],
                            "reason": f"자산 중요도({asset.get('criticality')}) 기반 우선 감시",
                            "detection_hints": detection_hints,
                            "alert_when": [
                                "Access comes from an unauthorized or unusual source.",
                                "The same source shows repeated attempts, failures, or scanning behavior.",
                                "The flow uses an unexpected service, port, or protocol for this asset.",
                            ],
                            "likely_benign_when": [
                                "Traffic comes from an approved business, monitoring, or maintenance source.",
                                "The flow uses an expected service port with no repeated or high-volume anomaly.",
                                "Recent source activity is low and has no failed or suspicious follow-up attempts.",
                            ],
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
                "id": f"P1-{cycle_id.replace('-', '')}-001",
                "target_assets": [{"ip": "172.31.69.28", "role": "web-application-server"}],
                "reason": "발표자료 예시와 맞춘 공개 웹 서버 우선 감시 항목입니다. (Fallback)",
                "detection_hints": [{"field": "dst_port", "operator": "in", "value": [80, 443]}],
                "alert_when": [
                    "External or unauthorized source repeatedly attempts access.",
                    "The source uses exploit-like behavior, unusual ports, or suspicious follow-up activity.",
                ],
                "likely_benign_when": [
                    "Single normal HTTP/HTTPS connection from an expected user or service.",
                    "No repeated attempts, failures, high-volume transfer, or suspicious source history.",
                ],
                "escalation_rule": "prob >= 0.20이면 Tier 1 LLM으로 보냄",
            })

        return enhance_watchlist_quality(watchlist, snapshots=snapshots), "\n".join(brief_lines), "\n".join(memory_lines)


class LLMTier2Runner:
    """Batch-loop runner that asks an LLM to create Tier 2 artifacts."""

    def __init__(self, provider: LLMProvider, runner_name: str = "llm") -> None:
        self.provider = provider
        self.runner_name = runner_name

    def run(self, config_path: str | Path, output_dir: str | Path = "output") -> Tier2Output:
        return self.run_config(_load_config(config_path), output_dir)

    def run_config(self, config: dict[str, Any], output_dir: str | Path = "output") -> Tier2Output:
        return asyncio.run(self._run_config_async(config, output_dir))

    async def _run_config_async(
        self,
        config: dict[str, Any],
        output_dir: str | Path,
    ) -> Tier2Output:
        now = datetime.now(KST)
        cycle_id = _cycle_id(now)
        tier2_config = config.get("tier2", {})

        collector = Tier2InputCollector(config)
        snapshots = collector.collect()
        source_status = {snapshot.name: snapshot.status for snapshot in snapshots}

        try:
            response = await self.provider.generate(
                system_prompt=build_tier2_system_prompt(),
                user_prompt=build_tier2_user_prompt(
                    cycle_id=cycle_id,
                    snapshots=snapshots,
                    attack_surface_memory_max_chars=int(
                        tier2_config.get("attack_surface_memory_max_chars", 3000)
                    ),
                ),
                max_tokens=int(tier2_config.get("max_tokens", 8192)),
                temperature=float(tier2_config.get("temperature", 0.2)),
                response_format=str(tier2_config.get("response_format", "text")),
            )
        except Exception as exc:
            output = _deterministic_fallback_output(
                cycle_id,
                now,
                snapshots,
                source_status,
                {
                    "runner": self.runner_name,
                    "api_call": True,
                    "fallback_reason": f"provider_error: {exc}",
                },
            )
            write_tier2_output(output, output_dir)
            return output

        parsed = parse_tier2_response(
            response.content,
            cycle_id=cycle_id,
            now=now,
            source_status=source_status,
            generated_by=response.model_name,
            snapshots=snapshots,
        )
        if parsed.parse_error:
            _write_failed_response(output_dir, cycle_id, response.content)
            output = _deterministic_fallback_output(
                cycle_id,
                now,
                snapshots,
                source_status,
                {
                    "runner": self.runner_name,
                    "api_call": True,
                    "model": response.model_name,
                    "latency_ms": response.latency_ms,
                    "tokens_used": response.tokens_used,
                    "prompt_tokens": response.prompt_tokens,
                    "completion_tokens": response.completion_tokens,
                    "fallback_reason": f"parse_error: {parsed.parse_error}",
                },
            )
            write_tier2_output(output, output_dir)
            return output

        output = _output_from_parsed_artifacts(
            cycle_id=cycle_id,
            parsed=parsed,
            metadata={
                "runner": self.runner_name,
                "model": response.model_name,
                "api_call": True,
                "latency_ms": response.latency_ms,
                "tokens_used": response.tokens_used,
                "prompt_tokens": response.prompt_tokens,
                "completion_tokens": response.completion_tokens,
                "snapshot_stats": {
                    snapshot.name: snapshot.item_count
                    for snapshot in snapshots
                    if snapshot.status == "used"
                },
            },
        )
        write_tier2_output(output, output_dir)
        return output


class OllamaTier2Runner(LLMTier2Runner):
    def __init__(self, config: dict[str, Any] | None = None) -> None:
        tier2_config = (config or {}).get("tier2", {})
        super().__init__(
            OllamaProvider(
                model=str(tier2_config.get("model", "gemma4:26b")),
                base_url=str(tier2_config.get("ollama_url", "http://localhost:11434")),
                timeout_seconds=float(tier2_config.get("timeout_seconds", 600.0)),
            ),
            runner_name="ollama",
        )

    def run_config(self, config: dict[str, Any], output_dir: str | Path = "output") -> Tier2Output:
        tier2_config = config.get("tier2", {})
        self.provider = OllamaProvider(
            model=str(tier2_config.get("model", "gemma4:26b")),
            base_url=str(tier2_config.get("ollama_url", "http://localhost:11434")),
            timeout_seconds=float(tier2_config.get("timeout_seconds", 600.0)),
        )
        return super().run_config(config, output_dir)


class GeminiTier2Runner(LLMTier2Runner):
    def __init__(self, config: dict[str, Any] | None = None) -> None:
        tier2_config = (config or {}).get("tier2", {})
        super().__init__(
            GeminiProvider(
                model=str(tier2_config.get("model", "gemini-3.5-flash")),
                api_key_env=str(
                    tier2_config.get(
                        "gemini_api_key_env",
                        "26_AISecApp_Project_GEMINI_API_KEY",
                    )
                ),
                base_url=str(
                    tier2_config.get(
                        "gemini_api_base_url",
                        "https://generativelanguage.googleapis.com/v1beta",
                    )
                ),
                timeout_seconds=float(tier2_config.get("timeout_seconds", 600.0)),
            ),
            runner_name="gemini",
        )

    def run_config(self, config: dict[str, Any], output_dir: str | Path = "output") -> Tier2Output:
        tier2_config = config.get("tier2", {})
        self.provider = GeminiProvider(
            model=str(tier2_config.get("model", "gemini-3.5-flash")),
            api_key_env=str(
                tier2_config.get("gemini_api_key_env", "26_AISecApp_Project_GEMINI_API_KEY")
            ),
            base_url=str(
                tier2_config.get(
                    "gemini_api_base_url",
                    "https://generativelanguage.googleapis.com/v1beta",
                )
            ),
            timeout_seconds=float(tier2_config.get("timeout_seconds", 600.0)),
        )
        return super().run_config(config, output_dir)


def _output_from_parsed_artifacts(
    *,
    cycle_id: str,
    parsed: ParsedTier2Artifacts,
    metadata: dict[str, Any],
) -> Tier2Output:
    return Tier2Output(
        cycle_id=cycle_id,
        watchlist=parsed.watchlist,
        brief_context=parsed.brief_context,
        attack_surface_memory=parsed.attack_surface_memory,
        summary_html="<p>LLM Tier 2 runner completed.</p>",
        metadata=metadata,
    )


def _deterministic_fallback_output(
    cycle_id: str,
    now: datetime,
    snapshots: list[SourceSnapshot],
    source_status: dict[str, str],
    metadata: dict[str, Any],
) -> Tier2Output:
    runner = DeterministicTier2Runner()
    watchlist, brief_context, memory = runner._process_snapshots(cycle_id, now, snapshots)
    watchlist["source_status"] = source_status
    fallback_metadata = {
        "model": "deterministic-fallback",
        "fallback": True,
        "snapshot_stats": {
            snapshot.name: snapshot.item_count for snapshot in snapshots if snapshot.status == "used"
        },
    }
    fallback_metadata.update(metadata)
    return Tier2Output(
        cycle_id=cycle_id,
        watchlist=watchlist,
        brief_context=brief_context,
        attack_surface_memory=memory,
        summary_html="<p>Tier 2 fallback runner completed.</p>",
        metadata=fallback_metadata,
    )


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


def _load_config(config_path: str | Path) -> dict[str, Any]:
    with Path(config_path).open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"settings file must contain a mapping: {config_path}")
    return data


def _apply_tier2_overrides(config: dict[str, Any], overrides: dict[str, Any]) -> None:
    tier2_config = config.setdefault("tier2", {})
    if not isinstance(tier2_config, dict):
        raise ValueError("tier2 settings must be a mapping")
    for key, value in overrides.items():
        if value is not None:
            tier2_config[key] = value


def _write_failed_response(output_dir: str | Path, cycle_id: str, content: str) -> None:
    base = Path(output_dir)
    base.mkdir(parents=True, exist_ok=True)
    (base / f"tier2_failed_{cycle_id}.txt").write_text(content, encoding="utf-8")


def _cycle_id(now: datetime) -> str:
    return now.strftime("%Y%m%dT%H%M%S%z")
