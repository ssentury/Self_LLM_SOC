from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

import yaml

from soc.models import SourceSnapshot


def enhance_watchlist_quality(
    watchlist: dict[str, Any],
    *,
    snapshots: list[SourceSnapshot] | None = None,
) -> dict[str, Any]:
    """Stabilize Tier 2 watchlist artifacts before they are written for Tier 1."""

    enhanced = deepcopy(watchlist)
    context = _SourceContext.from_snapshots(snapshots or [])
    for priority in ("priority_1", "priority_2", "priority_3"):
        for item in enhanced.get(priority, []):
            if not isinstance(item, dict):
                continue
            _ensure_text_guidance(item)
            if priority == "priority_1":
                _enhance_priority_1_item(item, context)
    return enhanced


class _SourceContext:
    def __init__(self) -> None:
        self.assets_by_ip: dict[str, dict[str, Any]] = {}
        self.asset_policies: dict[str, str] = {}
        self.suspicious_patterns: list[dict[str, Any]] = []
        self.known_bad_ips: list[dict[str, Any]] = []

    @classmethod
    def from_snapshots(cls, snapshots: list[SourceSnapshot]) -> "_SourceContext":
        context = cls()
        for snapshot in snapshots:
            if snapshot.status != "used" or not snapshot.content:
                continue
            data = _load_snapshot(snapshot.content)
            if not isinstance(data, dict):
                continue
            if snapshot.name == "assets":
                for asset in data.get("assets", []):
                    if isinstance(asset, dict) and asset.get("ip"):
                        context.assets_by_ip[str(asset["ip"])] = asset
            elif snapshot.name == "policy":
                for policy in data.get("asset_specific_policies", []):
                    if isinstance(policy, dict) and policy.get("asset"):
                        context.asset_policies[str(policy["asset"])] = str(policy.get("rule") or "")
            elif snapshot.name == "threat_feed":
                context.suspicious_patterns.extend(
                    pattern for pattern in data.get("suspicious_patterns", []) if isinstance(pattern, dict)
                )
                context.known_bad_ips.extend(
                    item for item in data.get("known_malicious_ips", []) if isinstance(item, dict)
                )
        return context


def _load_snapshot(content: str) -> Any:
    try:
        return yaml.safe_load(content)
    except Exception:
        try:
            return json.loads(content)
        except Exception:
            return None


def _ensure_text_guidance(item: dict[str, Any]) -> None:
    if not _text_list(item.get("alert_when")):
        item["alert_when"] = [
            "Alert when the scoped asset match is paired with an observable threat, policy, or repeated behavior trigger."
        ]
    if not _text_list(item.get("likely_benign_when")):
        item["likely_benign_when"] = [
            "Likely benign when the source, service, timing, and recent activity match normal approved business use."
        ]


def _enhance_priority_1_item(item: dict[str, Any], context: _SourceContext) -> None:
    target_ips = _target_ips(item)
    text = _item_text(item)
    for target_ip in target_ips:
        _add_pattern_hints(item, target_ip, text, context)
        _add_policy_hints(item, target_ip, text, context)


def _add_pattern_hints(
    item: dict[str, Any],
    target_ip: str,
    text: str,
    context: _SourceContext,
) -> None:
    for pattern in context.suspicious_patterns:
        fields = pattern.get("expected_flow_fields")
        if not isinstance(fields, dict) or str(fields.get("dst_ip")) != target_ip:
            continue
        if "dst_port" in fields:
            _add_hint(item, "dst_port", "in" if isinstance(fields["dst_port"], list) else "eq", fields["dst_port"])
        if "protocol" in fields:
            _add_hint(item, "protocol", "eq", fields["protocol"])

        pattern_text = " ".join(str(pattern.get(key) or "") for key in ("name", "condition")).lower()
        if "repeated" in pattern_text or "spray" in pattern_text:
            _add_hint(item, "recent_source_same_dst_port_count", "gte", 2)
        if any(token in pattern_text for token in ("known", "scanner", "prober", "bruteforce")):
            bad_ips = _known_bad_ips_for_pattern(context.known_bad_ips, pattern_text)
            if bad_ips:
                _add_hint(item, "src_ip", "in", bad_ips)


def _add_policy_hints(
    item: dict[str, Any],
    target_ip: str,
    text: str,
    context: _SourceContext,
) -> None:
    asset = context.assets_by_ip.get(target_ip, {})
    role = str(asset.get("role") or "")
    policy = context.asset_policies.get(target_ip, "")
    combined = " ".join([text, role, policy]).lower()

    if any(token in combined for token in ("postgres", "database", "db", "billing")):
        _add_hint(item, "dst_port", "eq", 5432)
        _add_hint(item, "src_ip", "not_in_cidr", ["10.42.20.0/24", "10.42.50.0/24"])
    if any(token in combined for token in ("backup", "nas", "smb", "ransomware")):
        _add_hint(item, "dst_port", "eq", 445)
        _add_hint(item, "src_ip", "in_cidr", ["10.42.100.0/24"])
    if "jumpbox" in combined or "rdp" in combined or (
        "ssh" in combined and any(token in combined for token in ("admin", "workstation", "direct access"))
    ):
        _add_hint(item, "dst_port", "in", [22, 3389])
        _add_hint(item, "src_ip", "in_cidr", ["10.42.100.0/24"])
    if "metadata" in combined or "169.254.169.254" in combined:
        _add_hint(item, "dst_ip", "eq", "169.254.169.254")
        _add_hint(item, "dst_port", "eq", 80)


def _known_bad_ips_for_pattern(known_bad_ips: list[dict[str, Any]], pattern_text: str) -> list[str]:
    result: list[str] = []
    for item in known_bad_ips:
        ip = item.get("ip")
        tags = " ".join(str(tag).lower() for tag in item.get("tags", []))
        if not ip:
            continue
        if "vpn" in pattern_text and "vpn" in tags:
            result.append(str(ip))
        elif any(token in pattern_text for token in ("web", "portal", "scanner", "prober")) and any(
            token in tags for token in ("web", "scanner", "prober", "rce")
        ):
            result.append(str(ip))
        elif "database" in pattern_text and ("database" in tags or "postgres" in tags):
            result.append(str(ip))
    return sorted(set(result))


def _add_hint(item: dict[str, Any], field: str, operator: str, value: Any) -> None:
    hints = item.setdefault("detection_hints", [])
    if not isinstance(hints, list):
        hints = []
        item["detection_hints"] = hints
    candidate = {"field": field, "operator": operator, "value": value}
    if candidate not in hints:
        hints.append(candidate)


def _target_ips(item: dict[str, Any]) -> list[str]:
    assets = item.get("target_assets", [])
    if not isinstance(assets, list):
        return []
    return [str(asset["ip"]) for asset in assets if isinstance(asset, dict) and asset.get("ip")]


def _item_text(item: dict[str, Any]) -> str:
    parts = [str(item.get("reason") or ""), str(item.get("escalation_rule") or "")]
    parts.extend(_text_list(item.get("alert_when")))
    parts.extend(_text_list(item.get("likely_benign_when")))
    return " ".join(parts).lower()


def _text_list(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    return [str(item) for item in raw if item is not None]
