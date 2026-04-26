from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from soc.models import Tier2Output
from soc.tier2.input_collectors import collect_source_status
from soc.tier2.writer import write_tier2_output


KST = timezone(timedelta(hours=9))


class FakeTier2Runner:
    """Slow-loop scaffold that produces presentation-aligned files without an API call."""

    def run(self, config_path: str | Path, output_dir: str | Path = "output") -> Tier2Output:
        now = datetime.now(KST)
        iso_year, iso_week, _ = now.isocalendar()
        week_id = f"{iso_year}-W{iso_week:02d}"
        source_status = collect_source_status(Path(config_path).parent)
        tier2_output = Tier2Output(
            week_id=week_id,
            watchlist=_sample_watchlist(week_id, now, source_status),
            brief_context=_sample_brief_context(week_id),
            attack_surface_memory=_sample_memory(week_id),
            summary_html="<p>Fake Tier 2 scaffold run completed.</p>",
            metadata={"runner": "fake", "model": "none", "api_call": False},
        )
        write_tier2_output(tier2_output, output_dir)
        return tier2_output


def _sample_watchlist(week_id: str, now: datetime, source_status: dict[str, str]) -> dict:
    valid_until = now + timedelta(days=7)
    return {
        "watchlist_version": week_id,
        "generated_at": now.isoformat(),
        "valid_until": valid_until.isoformat(),
        "generated_by": "fake-tier2",
        "source_status": source_status,
        "priority_1": [
            {
                "id": f"P1-{week_id.replace('-', '')}-001",
                "target_assets": [
                    {"ip": "172.31.69.28", "role": "web-application-server"},
                ],
                "reason": "발표자료 예시와 맞춘 공개 웹 서버 우선 감시 항목입니다.",
                "detection_hints": [
                    {"field": "dst_port", "operator": "in", "value": [80, 443]},
                ],
                "escalation_rule": "prob >= 0.20이면 Tier 1 LLM으로 보냄",
            }
        ],
        "priority_2": [],
        "priority_3": [],
    }


def _sample_brief_context(week_id: str) -> str:
    return f"""# Brief Context - {week_id}

## 조직 현황 요약

내부망은 172.31.0.0/16 대역으로 가정합니다. 172.31.69.28은 공개 웹 애플리케이션 서버이며 이번 주 우선 감시 대상입니다.

## 이번 주 주의 자산

- 172.31.69.28: HTTP/HTTPS 공개 웹 서버입니다. 외부 출발지에서 80/443 포트로 들어오는 flow는 Tier 1 검토 우선순위를 높입니다.
- 172.31.69.25: SSH/FTP/HTTP를 제공하는 다용도 서버입니다.

## Tier 1 판정 지침

Tier 1은 원천 CVE, 자산, 정책 파일을 직접 펼쳐 읽지 않습니다. 이 brief와 watchlist에서 정리된 맥락만 사용합니다.
"""


def _sample_memory(week_id: str) -> str:
    return f"""# Attack Surface Memory - {week_id}

- 공개 웹 서버 172.31.69.28은 발표자료의 예시 자산이며, Slow Loop가 장기 맥락을 기록하는 위치를 검증하기 위해 사용합니다.
- 이후 실제 Tier 2 LLM이 연결되면 이전 watchlist hit/miss와 Tier 1 판정 통계를 여기에 누적합니다.
"""
