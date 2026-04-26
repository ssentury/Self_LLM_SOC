from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from soc.models import Flow, WatchlistMatch


EMPTY_WATCHLIST: dict[str, Any] = {
    "watchlist_version": "empty",
    "priority_1": [],
    "priority_2": [],
    "priority_3": [],
}


def load_watchlist(path: str | Path) -> dict[str, Any]:
    watchlist_path = Path(path)
    if not watchlist_path.exists():
        return dict(EMPTY_WATCHLIST)

    text = watchlist_path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore

            data = yaml.safe_load(text)
        except Exception:
            return dict(EMPTY_WATCHLIST)

    if not isinstance(data, dict):
        return dict(EMPTY_WATCHLIST)
    for priority in ("priority_1", "priority_2", "priority_3"):
        if not isinstance(data.get(priority), list):
            data[priority] = []
    return data


def match_watchlist(flow: Flow, watchlist: dict[str, Any]) -> WatchlistMatch:
    for priority in ("priority_1", "priority_2", "priority_3"):
        for item in watchlist.get(priority, []):
            if not isinstance(item, dict):
                continue
            if not _target_asset_matches(flow, item):
                continue
            hint_matches = _match_detection_hints(flow, item.get("detection_hints", []))
            if hint_matches is None:
                continue
            return WatchlistMatch(
                matched=True,
                priority=priority,
                item_id=item.get("id"),
                reason=item.get("reason"),
                matched_conditions=hint_matches,
                escalation_hint=item.get("escalation_rule"),
            )
    return WatchlistMatch(matched=False)


def _target_asset_matches(flow: Flow, item: dict[str, Any]) -> bool:
    assets = item.get("target_assets", [])
    if not isinstance(assets, list):
        return False
    return any(isinstance(asset, dict) and asset.get("ip") == flow.dst_ip for asset in assets)


def _match_detection_hints(flow: Flow, hints: Any) -> list[str] | None:
    if not isinstance(hints, list) or not hints:
        return ["target_assets.ip == flow.dst_ip"]

    matched: list[str] = ["target_assets.ip == flow.dst_ip"]
    recognized = 0
    for hint in hints:
        result = _match_hint(flow, hint)
        if result == "unrecognized":
            continue
        recognized += 1
        if result is None:
            return None
        matched.append(result)
    return matched if recognized else matched


def _match_hint(flow: Flow, hint: Any) -> str | None:
    if isinstance(hint, dict):
        field = str(hint.get("field", "")).strip()
        operator = str(hint.get("operator", "")).strip()
        value = hint.get("value")
        if field in {"dst_port", "L4_DST_PORT"} and operator == "in" and isinstance(value, list):
            values = {int(v) for v in value}
            return f"{field} in {sorted(values)}" if flow.dst_port in values else None
        if field in {"dst_port", "L4_DST_PORT"} and operator == "eq":
            return f"{field} == {value}" if flow.dst_port == int(value) else None
        return "unrecognized"

    if isinstance(hint, str):
        dst_port_match = re.search(r"(?:dst_port|L4_DST_PORT)\s+in\s+\[([^\]]+)\]", hint)
        if dst_port_match:
            values = {int(part.strip()) for part in dst_port_match.group(1).split(",")}
            return hint if flow.dst_port in values else None
        return "unrecognized"

    return "unrecognized"
