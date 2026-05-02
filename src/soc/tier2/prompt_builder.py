from __future__ import annotations

import json

from soc.models import SourceSnapshot


def build_tier2_system_prompt() -> str:
    return """You are the Tier 2 slow-loop analyst for mini LLM SOC.

Your job is to curate organization/security inputs into compact artifacts for Tier 1.
Tier 1 must not receive raw asset, CVE, policy, or threat feed dumps.

Return only one valid JSON object. Do not wrap it in Markdown.
Do not omit any required top-level key. If memory is sparse, still return
attack_surface_memory as a short Markdown note.

Required JSON shape:
{
  "watchlist": {
    "priority_1": [
      {
        "id": "P1-YYYYWww-001",
        "target_assets": [{"ip": "x.x.x.x", "role": "asset role"}],
        "reason": "short Korean reason",
        "detection_hints": [
          {"field": "dst_port", "operator": "in", "value": [80, 443]}
        ],
        "escalation_rule": "prob >= 0.20이면 Tier 1 LLM으로 보냄"
      }
    ],
    "priority_2": [],
    "priority_3": []
  },
  "brief_context": "Markdown text in Korean for Tier 1.",
  "attack_surface_memory": "Markdown text in Korean."
}

Watchlist rules:
- Use only curated, high-signal items. Do not list every raw source record.
- Return at most 2 items in priority_1. Use empty arrays for priority_2 and priority_3 unless
  there is a very clear reason.
- Prefer priority_1 for externally reachable high/critical assets, critical CVEs,
  known malicious source patterns, or repeated recent alert patterns.
- Use target_assets with concrete destination IPs whenever possible.
- Use structured detection_hints for fields Tier 1 routing can match, especially dst_port.
- Each watchlist item may contain only these keys:
  id, target_assets, reason, detection_hints, escalation_rule.
  Do not invent extra detection_* keys.
- Keep brief_context under 1200 Korean characters.
- Keep attack_surface_memory under 800 Korean characters.
- Preserve source uncertainty in the brief, but do not expose full raw source dumps.
"""


def build_tier2_user_prompt(
    *,
    week_id: str,
    snapshots: list[SourceSnapshot],
    max_snapshot_chars: int = 6000,
) -> str:
    status_summary = {
        snapshot.name: {
            "status": snapshot.status,
            "source_type": snapshot.source_type,
            "path_or_uri": snapshot.path_or_uri,
            "item_count": snapshot.item_count,
            "error": snapshot.error,
        }
        for snapshot in snapshots
    }

    sections = [
        f"week_id: {week_id}",
        "source_status:",
        json.dumps(status_summary, ensure_ascii=False, indent=2),
        "used_source_contents:",
    ]
    for snapshot in snapshots:
        if snapshot.status != "used" or not snapshot.content:
            continue
        sections.append(f"\n--- SOURCE: {snapshot.name} ({snapshot.source_type}) ---")
        sections.append(_truncate(snapshot.content, max_snapshot_chars))

    sections.append(
        """
Create this week's Watchlist & Contexts for Tier 1.
Include source status awareness, but include raw source content only as curated conclusions.
Return only JSON with watchlist, brief_context, and attack_surface_memory.
""".strip()
    )
    return "\n".join(sections)


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n... [truncated]"
