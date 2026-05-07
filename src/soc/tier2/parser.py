from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import re
from typing import Any

import yaml

from soc.context.watchlist import lint_watchlist


@dataclass(frozen=True)
class ParsedTier2Artifacts:
    watchlist: dict[str, Any]
    brief_context: str
    attack_surface_memory: str
    parse_error: str | None = None


def parse_tier2_response(
    content: str,
    *,
    cycle_id: str,
    now: datetime,
    source_status: dict[str, str],
    generated_by: str,
) -> ParsedTier2Artifacts:
    try:
        data = _load_response_object(content)
    except Exception as exc:
        return ParsedTier2Artifacts(
            watchlist=normalize_watchlist(
                {},
                cycle_id=cycle_id,
                now=now,
                source_status=source_status,
                generated_by=generated_by,
            ),
            brief_context=_fallback_brief(cycle_id),
            attack_surface_memory=_fallback_memory(cycle_id, f"Tier 2 output parse failed: {exc}"),
            parse_error=str(exc),
        )

    watchlist = normalize_watchlist(
        data.get("watchlist") if isinstance(data, dict) else {},
        cycle_id=cycle_id,
        now=now,
        source_status=source_status,
        generated_by=generated_by,
    )
    brief_context = _text_field(data, "brief_context", "brief_context_md", "brief")
    attack_surface_memory = _text_field(
        data,
        "attack_surface_memory",
        "attack_surface_memory_md",
        "attack_surface_memory_context",
        "memory_context",
        "memory_md",
        "memory",
    )
    if not brief_context:
        brief_context = _fallback_brief(cycle_id)
    if not attack_surface_memory:
        attack_surface_memory = _fallback_memory(cycle_id, "Tier 2 did not return memory text.")

    return ParsedTier2Artifacts(
        watchlist=watchlist,
        brief_context=brief_context,
        attack_surface_memory=attack_surface_memory,
    )


def normalize_watchlist(
    raw: Any,
    *,
    cycle_id: str,
    now: datetime,
    source_status: dict[str, str],
    generated_by: str,
) -> dict[str, Any]:
    valid_until = now + timedelta(days=7)
    raw_dict = raw if isinstance(raw, dict) else {}
    normalized: dict[str, Any] = {
        "watchlist_version": str(raw_dict.get("watchlist_version") or cycle_id),
        "generated_at": str(raw_dict.get("generated_at") or now.isoformat()),
        "valid_until": str(raw_dict.get("valid_until") or valid_until.isoformat()),
        "generated_by": str(raw_dict.get("generated_by") or generated_by),
        "source_status": dict(source_status),
        "priority_1": [],
        "priority_2": [],
        "priority_3": [],
    }

    for priority in ("priority_1", "priority_2", "priority_3"):
        items = raw_dict.get(priority, [])
        if not isinstance(items, list):
            items = []
        normalized_items: list[dict[str, Any]] = []
        for index, candidate in enumerate(items):
            item = _normalize_watchlist_item(priority, candidate, index, cycle_id)
            if item is not None:
                normalized_items.append(item)
        normalized[priority] = normalized_items

    return lint_watchlist(normalized)


def _normalize_watchlist_item(
    priority: str,
    raw: Any,
    index: int,
    cycle_id: str,
) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None

    target_assets = _normalize_target_assets(raw.get("target_assets"))
    if not target_assets:
        return None

    priority_label = {"priority_1": "P1", "priority_2": "P2", "priority_3": "P3"}[priority]
    item_id = str(raw.get("id") or f"{priority_label}-{cycle_id.replace('-', '')}-{index + 1:03d}")
    reason = str(raw.get("reason") or "Tier 2 curated watchlist item.")
    return {
        "id": item_id,
        "target_assets": target_assets,
        "reason": reason,
        "detection_hints": _normalize_detection_hints(raw.get("detection_hints")),
        "alert_when": _normalize_text_list(raw.get("alert_when")),
        "likely_benign_when": _normalize_text_list(raw.get("likely_benign_when")),
        "escalation_rule": str(
            raw.get("escalation_rule") or "prob >= 0.20이면 Tier 1 LLM으로 보냄"
        ),
    }


def _normalize_target_assets(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    assets: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        ip = item.get("ip")
        if not ip:
            continue
        asset: dict[str, Any] = {"ip": str(ip)}
        if item.get("role"):
            asset["role"] = str(item["role"])
        assets.append(asset)
    return assets


def _normalize_detection_hints(raw: Any) -> list[Any]:
    if not isinstance(raw, list):
        return []
    hints: list[Any] = []
    for hint in raw:
        normalized = _normalize_detection_hint(hint)
        if normalized is not None:
            hints.append(normalized)
    return hints


def _normalize_detection_hint(raw: Any) -> Any | None:
    if isinstance(raw, str):
        return raw
    if not isinstance(raw, dict):
        return None

    field = str(raw.get("field") or "").strip()
    operator = str(raw.get("operator") or "").strip()
    if not field or not operator:
        return None

    if operator == "in":
        value = raw.get("value")
        if not isinstance(value, list):
            return None
        return {"field": field, "operator": operator, "value": value}

    if operator in {"eq", "gte", "lte", "gt", "lt"} and "value" in raw:
        return {"field": field, "operator": operator, "value": raw.get("value")}

    return None


def _normalize_text_list(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    return [text for item in raw if (text := str(item).strip())]


def _load_response_object(content: str) -> dict[str, Any]:
    text = content.strip()
    if not text:
        raise ValueError("empty Tier 2 response")

    candidates = [text]
    fenced = re.findall(r"```(?:json|yaml|yml)?\s*(.*?)```", text, flags=re.DOTALL | re.IGNORECASE)
    candidates.extend(candidate.strip() for candidate in fenced if candidate.strip())
    if "{" in text and "}" in text:
        candidates.append(text[text.find("{") : text.rfind("}") + 1])

    last_error: Exception | None = None
    for candidate in candidates:
        try:
            data = json.loads(candidate)
            if isinstance(data, dict):
                return data
        except Exception as exc:
            last_error = exc
        try:
            data = yaml.safe_load(candidate)
            if isinstance(data, dict):
                return data
        except Exception as exc:
            last_error = exc

    raise ValueError(f"Tier 2 response did not contain a JSON/YAML object: {last_error}")


def _text_field(data: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str):
            return value.strip()
    return ""


def _fallback_brief(cycle_id: str) -> str:
    return (
        f"# Brief Context - {cycle_id}\n\n"
        "Tier 2 LLM output was unavailable or incomplete. Tier 1 should rely on "
        "the validated watchlist and realtime ML/activity evidence only."
    )


def _fallback_memory(cycle_id: str, reason: str) -> str:
    return f"# Attack Surface Memory - {cycle_id}\n\n- {reason}"
