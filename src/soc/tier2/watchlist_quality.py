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
    _add_source_wide_pattern_items(enhanced, context)
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
        self.trust_zones: list[dict[str, Any]] = []
        self.cve_advisories: list[dict[str, Any]] = []
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
                context.trust_zones.extend(
                    zone for zone in data.get("trust_zones", []) if isinstance(zone, dict)
                )
            elif snapshot.name == "policy":
                for policy in data.get("asset_specific_policies", []):
                    if isinstance(policy, dict) and policy.get("asset"):
                        context.asset_policies[str(policy["asset"])] = str(policy.get("rule") or "")
            elif snapshot.name == "cve_feed":
                context.cve_advisories.extend(
                    advisory for advisory in data.get("advisories", []) if isinstance(advisory, dict)
                )
                context.cve_advisories.extend(
                    advisory for advisory in data.get("cves", []) if isinstance(advisory, dict)
                )
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
        _add_cve_hints(item, target_ip, text, context)
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
        if str(fields.get("dst_ip")) == "169.254.169.254":
            internal_cidrs = _cidrs_by_zone_tokens(context, include=("internal", "workstation", "admin"))
            if internal_cidrs:
                _add_hint(item, "src_ip", "in_cidr", internal_cidrs)

        pattern_text = " ".join(str(pattern.get(key) or "") for key in ("name", "condition")).lower()
        if "repeated" in pattern_text or "spray" in pattern_text:
            _add_hint(item, "recent_source_same_dst_port_count", "gte", 2)
        if any(token in pattern_text for token in ("known", "scanner", "prober", "bruteforce")):
            bad_ips = _known_bad_ips_for_pattern(context.known_bad_ips, pattern_text)
            if bad_ips:
                _add_hint(item, "src_ip", "in", bad_ips)
        _ensure_routing_policy(
            item,
            "Tier 2 source pattern says matching low-score flows still need Tier 1 review.",
        )


def _add_cve_hints(
    item: dict[str, Any],
    target_ip: str,
    text: str,
    context: _SourceContext,
) -> None:
    for advisory in context.cve_advisories:
        affected_assets = {str(asset) for asset in _list_value(advisory.get("affects_assets"))}
        if target_ip not in affected_assets:
            continue

        affected_ports = _list_value(advisory.get("affected_ports"))
        if affected_ports:
            _add_hint(
                item,
                "dst_port",
                "in" if len(affected_ports) > 1 else "eq",
                affected_ports if len(affected_ports) > 1 else affected_ports[0],
            )

        advisory_text = " ".join(
            [
                text,
                str(advisory.get("title") or ""),
                str(advisory.get("content") or ""),
                " ".join(str(value) for value in _list_value(advisory.get("netflow_observables"))),
            ]
        ).lower()
        if any(token in advisory_text for token in ("repeated", "probing", "spray", "scanner")):
            _add_hint(item, "recent_source_same_dst_port_count", "gte", 2)
        if any(token in advisory_text for token in ("unapproved", "management-plane", "management plane")):
            admin_cidrs = _cidrs_by_zone_tokens(context, include=("admin",))
            if admin_cidrs:
                _add_hint(item, "src_ip", "not_in_cidr", admin_cidrs)
        if "outbound" in advisory_text or "egress" in advisory_text:
            _add_hint(item, "dst_port", "eq", 443)
            _add_external_destination_hint(item, context)
            _ensure_routing_policy(
                item,
                "Tier 2 CVE source marks post-exposure egress as review-worthy.",
                review_threshold=0.12,
            )

        benign_notes = [
            str(value)
            for value in _list_value(advisory.get("netflow_observables"))
            if "benign" in str(value).lower()
        ]
        if benign_notes:
            _append_unique_text(item, "likely_benign_when", benign_notes)
        _ensure_routing_policy(
            item,
            "Tier 2 CVE source says matching low-score flows still need Tier 1 review.",
        )


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
        approved_cidrs = _cidrs_by_zone_tokens(context, include=("app", "admin"))
        if approved_cidrs:
            _add_hint(item, "src_ip", "not_in_cidr", approved_cidrs)
        _ensure_routing_policy(item, "Tier 2 policy marks unusual database access for Tier 1 review.")
    if any(token in combined for token in ("backup", "nas", "smb", "ransomware")):
        _add_hint(item, "dst_port", "eq", 445)
        workstation_cidrs = _cidrs_by_zone_tokens(context, include=("workstation",))
        if workstation_cidrs:
            _add_hint(item, "src_ip", "in_cidr", workstation_cidrs)
        _ensure_routing_policy(item, "Tier 2 policy marks unusual backup access for Tier 1 review.")
        if _has_dst_port_hint(item, 443) or any(
            token in combined for token in ("egress", "outbound", "exfil", "external")
        ):
            _add_hint(item, "dst_port", "eq", 443)
            _add_external_destination_hint(item, context)
            _ensure_routing_policy(
                item,
                "Tier 2 policy marks sensitive backup egress for Tier 1 review.",
                review_threshold=0.12,
            )
    if "jumpbox" in combined or "rdp" in combined or (
        "ssh" in combined and any(token in combined for token in ("admin", "workstation", "direct access"))
    ):
        _add_hint(item, "dst_port", "in", [22, 3389])
        admin_cidrs = _cidrs_by_zone_tokens(context, include=("admin",))
        if admin_cidrs:
            _add_hint(item, "src_ip", "not_in_cidr", admin_cidrs)
        _ensure_routing_policy(item, "Tier 2 policy marks unapproved admin access for Tier 1 review.")
    if "metadata" in combined or "169.254.169.254" in combined:
        _add_hint(item, "dst_ip", "eq", "169.254.169.254")
        _add_hint(item, "dst_port", "eq", 80)
        internal_cidrs = _cidrs_by_zone_tokens(context, include=("internal", "workstation", "admin"))
        if internal_cidrs:
            _add_hint(item, "src_ip", "in_cidr", internal_cidrs)
        _ensure_routing_policy(item, "Tier 2 policy marks metadata access for Tier 1 review.")
    if any(token in combined for token in ("firewall-manager", "fortimanager", "management-plane", "tcp/541")):
        _add_hint(item, "dst_port", "eq", 541)
        admin_cidrs = _cidrs_by_zone_tokens(context, include=("admin",))
        if admin_cidrs:
            _add_hint(item, "src_ip", "not_in_cidr", admin_cidrs)
        _ensure_routing_policy(item, "Tier 2 policy marks unapproved management-plane access for Tier 1 review.")
        if _has_dst_port_hint(item, 443) or any(token in combined for token in ("egress", "outbound", "external")):
            _add_hint(item, "dst_port", "eq", 443)
            _add_external_destination_hint(item, context)
            _ensure_routing_policy(
                item,
                "Tier 2 policy marks management-plane follow-up egress for Tier 1 review.",
                review_threshold=0.12,
            )


def _add_source_wide_pattern_items(watchlist: dict[str, Any], context: _SourceContext) -> None:
    priority_1 = watchlist.setdefault("priority_1", [])
    if not isinstance(priority_1, list):
        watchlist["priority_1"] = []
        priority_1 = watchlist["priority_1"]
    existing_ids = {str(item.get("id")) for item in priority_1 if isinstance(item, dict)}
    for pattern in context.suspicious_patterns:
        fields = pattern.get("expected_flow_fields")
        if not isinstance(fields, dict):
            continue
        pattern_text = " ".join(str(pattern.get(key) or "") for key in ("name", "condition")).lower()
        if not _should_create_source_wide_pattern(pattern_text):
            continue
        item_id = f"P1-SOURCE-PATTERN-{_safe_id(str(pattern.get('name') or 'pattern'))}"
        if item_id in existing_ids:
            continue
        target_assets = _source_wide_pattern_targets(pattern_text, fields, context)
        if not target_assets:
            continue
        item: dict[str, Any] = {
            "id": item_id,
            "target_assets": target_assets,
            "reason": str(pattern.get("condition") or pattern.get("name") or "source-backed suspicious pattern"),
            "detection_hints": [],
            "alert_when": [
                "Route to Tier 1 when the source-scoped pattern also matches the observable service and direction hints."
            ],
            "likely_benign_when": [
                "Likely benign when the destination is an approved internal service and recent source activity is low."
            ],
        }
        _add_expected_flow_hints(item, fields)
        if "dns" in pattern_text:
            _add_source_cidr_hint(item, context, include=("workstation",))
            _add_external_destination_hint(item, context)
            _add_hint(item, "recent_source_same_dst_port_count", "gte", 2)
            _ensure_routing_policy(
                item,
                "Tier 2 threat pattern marks repeated external DNS as critical review traffic.",
                review_threshold=0.04,
            )
        elif "169.254.169.254" in pattern_text or "metadata" in pattern_text:
            _add_source_cidr_hint(item, context, include=("internal", "workstation", "app", "admin"))
            _ensure_routing_policy(
                item,
                "Tier 2 threat pattern marks metadata-service access as critical review traffic.",
                review_threshold=0.04,
            )
        priority_1.append(item)
        existing_ids.add(item_id)


def _should_create_source_wide_pattern(pattern_text: str) -> bool:
    return (
        "dns" in pattern_text
        or "169.254.169.254" in pattern_text
        or "metadata" in pattern_text
    )


def _source_wide_pattern_targets(
    pattern_text: str,
    fields: dict[str, Any],
    context: _SourceContext,
) -> list[dict[str, Any]]:
    if fields.get("dst_ip"):
        return [{"ip": str(fields["dst_ip"]), "role": pattern_text[:40] or "source-backed pattern", "match": "dst"}]
    include = ("workstation",) if "workstation" in pattern_text else ("internal", "workstation")
    return [
        {"cidr": cidr, "role": "source-scope", "match": "src"}
        for cidr in _cidrs_by_zone_tokens(context, include=include)
    ]


def _add_expected_flow_hints(item: dict[str, Any], fields: dict[str, Any]) -> None:
    for field in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol"):
        if field not in fields:
            continue
        value = fields[field]
        _add_hint(item, field, "in" if isinstance(value, list) else "eq", value)


def _add_source_cidr_hint(
    item: dict[str, Any],
    context: _SourceContext,
    *,
    include: tuple[str, ...],
) -> None:
    cidrs = _cidrs_by_zone_tokens(context, include=include)
    if cidrs:
        _add_hint(item, "src_ip", "in_cidr", cidrs)


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


def _ensure_routing_policy(item: dict[str, Any], reason: str, *, review_threshold: float = 0.10) -> None:
    item.setdefault(
        "routing_policy",
        {
            "review_threshold": review_threshold,
            "max_threshold_drop": 0.20,
            "action": "tier1_llm",
            "reason": reason,
        },
    )


def _cidrs_by_zone_tokens(context: _SourceContext, *, include: tuple[str, ...]) -> list[str]:
    cidrs: list[str] = []
    for zone in context.trust_zones:
        zone_name = str(zone.get("zone") or "").lower()
        cidr = zone.get("cidr")
        if not cidr:
            continue
        if "external" in zone_name or "dmz" in zone_name or "public" in zone_name:
            continue
        if any(token in zone_name for token in include):
            cidrs.append(str(cidr))
    return sorted(set(cidrs))


def _non_external_cidrs(context: _SourceContext) -> list[str]:
    cidrs: list[str] = []
    for zone in context.trust_zones:
        zone_name = str(zone.get("zone") or "").lower()
        cidr = zone.get("cidr")
        if not cidr:
            continue
        if "external" in zone_name or "unknown" in zone_name:
            continue
        cidrs.append(str(cidr))
    return sorted(set(cidrs))


def _add_external_destination_hint(item: dict[str, Any], context: _SourceContext) -> None:
    cidrs = _non_external_cidrs(context)
    if cidrs:
        _add_hint(item, "dst_ip", "not_in_cidr", cidrs)


def _has_dst_port_hint(item: dict[str, Any], port: int) -> bool:
    for hint in item.get("detection_hints", []):
        if not isinstance(hint, dict) or str(hint.get("field")) != "dst_port":
            continue
        value = hint.get("value")
        values = value if isinstance(value, list) else [value]
        if any(_same_scalar(candidate, port) for candidate in values):
            return True
    return False


def _same_scalar(left: Any, right: Any) -> bool:
    try:
        return float(left) == float(right)
    except (TypeError, ValueError):
        return str(left) == str(right)


def _safe_id(value: str) -> str:
    safe = "".join(char.upper() if char.isalnum() else "-" for char in value)
    return "-".join(part for part in safe.split("-") if part)[:48] or "PATTERN"


def _list_value(raw: Any) -> list[Any]:
    if isinstance(raw, list):
        return raw
    return []


def _append_unique_text(item: dict[str, Any], key: str, values: list[str]) -> None:
    current = item.setdefault(key, [])
    if not isinstance(current, list):
        current = []
        item[key] = current
    for value in values:
        if value and value not in current:
            current.append(value)


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
