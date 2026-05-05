from __future__ import annotations

import json
from pathlib import Path

from soc.models import SourceSnapshot


def build_tier2_system_prompt(prompt_path: str | Path | None = None) -> str:
    path = Path(prompt_path) if prompt_path is not None else _default_system_prompt_path()
    return path.read_text(encoding="utf-8").strip()


def build_tier2_user_prompt(
    *,
    cycle_id: str,
    snapshots: list[SourceSnapshot],
    max_snapshot_chars: int = 6000,
    brief_context_max_chars: int = 1200,
    attack_surface_memory_max_chars: int = 3000,
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
        f"cycle_id: {cycle_id}",
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
        f"""
Create the current Tier 2 batch artifacts.
First derive attack_surface_memory, then derive watchlist and brief_context from
the current source inputs plus that newly derived memory.
Include source status awareness, but include raw source content only as curated conclusions.
Keep brief_context under {brief_context_max_chars} Korean characters.
Keep attack_surface_memory under {attack_surface_memory_max_chars} Korean characters.
Return only JSON with watchlist, brief_context, and attack_surface_memory.
""".strip()
    )
    return "\n".join(sections)


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n... [truncated]"


def _default_system_prompt_path() -> Path:
    return Path(__file__).resolve().parents[3] / "prompts" / "tier2_system.md"
