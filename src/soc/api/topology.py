from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Any

import yaml

from soc.models import SourceSnapshot


GROUP_ORDER = {
    "external": 0,
    "dmz": 1,
    "internal-app": 2,
    "database": 3,
    "clinical": 4,
    "backup": 5,
    "admin": 6,
    "infrastructure": 7,
    "workstation": 8,
    "other": 9,
}

GROUP_LABELS = {
    "external": "External / Public",
    "dmz": "DMZ / Public Services",
    "internal-app": "Internal Apps",
    "database": "Databases",
    "clinical": "Clinical Systems",
    "backup": "Backup",
    "admin": "Admin",
    "infrastructure": "Infrastructure",
    "workstation": "Workstations",
    "other": "Other Assets",
}


@dataclass(frozen=True)
class TrustZone:
    cidr: str
    zone: str
    network: ipaddress._BaseNetwork


def build_topology_payload(
    snapshots: list[SourceSnapshot],
    recent_events: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build an operator-facing asset relationship view from assets and recent flows."""
    asset_snapshot = next((item for item in snapshots if item.name == "assets"), None)
    assets_data = _load_assets_yaml(asset_snapshot)
    trust_zones = _trust_zones(assets_data)

    nodes: dict[str, dict[str, Any]] = {}
    asset_ip_to_node: dict[str, str] = {}
    for asset in _asset_items(assets_data):
        ip = str(asset.get("ip") or "").strip()
        if not ip:
            continue
        group = _group_for_asset(asset, trust_zones)
        node_id = f"asset:{ip}"
        node = {
            "id": node_id,
            "ip": ip,
            "label": str(asset.get("role") or asset.get("id") or ip),
            "role": str(asset.get("role") or "-"),
            "zone": str(asset.get("zone") or _zone_for_ip(ip, trust_zones) or "-"),
            "group": group,
            "services": _as_string_list(asset.get("services")),
            "criticality": str(asset.get("criticality") or "unknown"),
            "source": "asset_input",
        }
        nodes[node_id] = node
        asset_ip_to_node[ip] = node_id

    edges: dict[tuple[str, str], dict[str, Any]] = {}
    for event in recent_events:
        src_ip = str(event.get("src_ip") or "").strip()
        dst_ip = str(event.get("dst_ip") or "").strip()
        if not src_ip or not dst_ip:
            continue
        src_id = _ensure_node(nodes, asset_ip_to_node, trust_zones, src_ip)
        dst_id = _ensure_node(nodes, asset_ip_to_node, trust_zones, dst_ip)
        key = (src_id, dst_id)
        edge = edges.setdefault(
            key,
            {
                "id": f"{src_id}->{dst_id}",
                "src": src_id,
                "dst": dst_id,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "count": 0,
                "flow_ids": [],
                "latest_flow_id": None,
                "latest_route": None,
                "latest_verdict": None,
                "latest_severity": None,
                "alert_count": 0,
                "watchlist_hit_count": 0,
            },
        )
        edge["count"] += 1
        flow_id = str(event.get("flow_id") or "")
        if flow_id:
            edge["flow_ids"].append(flow_id)
            if edge["latest_flow_id"] is None:
                edge["latest_flow_id"] = flow_id
        if edge["latest_route"] is None:
            edge["latest_route"] = event.get("route")
        if edge["latest_verdict"] is None:
            edge["latest_verdict"] = event.get("verdict")
        if edge["latest_severity"] is None:
            edge["latest_severity"] = event.get("severity")
        if _is_alert_event(event):
            edge["alert_count"] += 1
        if event.get("watchlist_matched"):
            edge["watchlist_hit_count"] += 1

    groups = _groups_from_nodes(nodes)
    return {
        "status": _topology_status(asset_snapshot, nodes),
        "source": {
            "status": asset_snapshot.status if asset_snapshot else "missing",
            "source_type": asset_snapshot.source_type if asset_snapshot else "yaml",
            "path_or_uri": asset_snapshot.path_or_uri if asset_snapshot else None,
            "item_count": asset_snapshot.item_count if asset_snapshot else 0,
            "error": asset_snapshot.error if asset_snapshot else "assets source is not configured",
        },
        "groups": groups,
        "nodes": sorted(
            nodes.values(),
            key=lambda node: (GROUP_ORDER.get(str(node["group"]), 99), str(node["label"]), str(node["ip"])),
        ),
        "edges": sorted(
            edges.values(),
            key=lambda edge: (-int(edge["alert_count"]), -int(edge["watchlist_hit_count"]), -int(edge["count"]), str(edge["id"])),
        ),
        "note": "Operator-facing asset relationship view from configured assets/zones and recent stored flows; not a discovered network map.",
    }


def _load_assets_yaml(snapshot: SourceSnapshot | None) -> dict[str, Any]:
    if snapshot is None or snapshot.status != "used" or not snapshot.content.strip():
        return {}
    try:
        data = yaml.safe_load(snapshot.content)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _asset_items(data: dict[str, Any]) -> list[dict[str, Any]]:
    assets = data.get("assets")
    return [item for item in assets if isinstance(item, dict)] if isinstance(assets, list) else []


def _trust_zones(data: dict[str, Any]) -> list[TrustZone]:
    zones = data.get("trust_zones")
    if not isinstance(zones, list):
        return []
    result: list[TrustZone] = []
    for item in zones:
        if not isinstance(item, dict):
            continue
        cidr = str(item.get("cidr") or "")
        zone = str(item.get("zone") or "")
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        result.append(TrustZone(cidr=cidr, zone=zone, network=network))
    return sorted(result, key=lambda zone: zone.network.prefixlen, reverse=True)


def _group_for_asset(asset: dict[str, Any], trust_zones: list[TrustZone]) -> str:
    zone = str(asset.get("zone") or _zone_for_ip(str(asset.get("ip") or ""), trust_zones) or "")
    role = str(asset.get("role") or "")
    services = " ".join(_as_string_list(asset.get("services")))
    return _classify_group(" ".join([zone, role, services]))


def _classify_group(text: str) -> str:
    value = text.lower()
    if "external" in value or "internet" in value:
        return "external"
    if "dmz" in value or "public" in value:
        return "dmz"
    if "workstation" in value or "laptop" in value or "pc" in value or "client" in value:
        return "workstation"
    if "db" in value or "database" in value or "postgres" in value or "mysql" in value or "mssql" in value:
        return "database"
    if "backup" in value or "storage" in value or "nas" in value:
        return "backup"
    if "admin" in value or "management" in value or "jumpbox" in value:
        return "admin"
    if "clinical" in value or "pacs" in value or "dicom" in value:
        return "clinical"
    if "infra" in value or "dns" in value or "domain" in value or "ntp" in value or "siem" in value:
        return "infrastructure"
    if "app" in value or "api" in value or "web" in value or "service" in value:
        return "internal-app"
    return "other"


def _zone_for_ip(ip: str, trust_zones: list[TrustZone]) -> str | None:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for zone in trust_zones:
        if address in zone.network:
            return zone.zone
    return None


def _ensure_node(
    nodes: dict[str, dict[str, Any]],
    asset_ip_to_node: dict[str, str],
    trust_zones: list[TrustZone],
    ip: str,
) -> str:
    existing = asset_ip_to_node.get(ip)
    if existing:
        return existing
    zone = _zone_for_ip(ip, trust_zones)
    group = _classify_group(zone or _fallback_zone_for_ip(ip))
    node_id = f"endpoint:{ip}"
    nodes.setdefault(
        node_id,
        {
            "id": node_id,
            "ip": ip,
            "label": ip,
            "role": "recent endpoint",
            "zone": zone or _fallback_zone_for_ip(ip),
            "group": group,
            "services": [],
            "criticality": "unknown",
            "source": "recent_flow",
        },
    )
    return node_id


def _fallback_zone_for_ip(ip: str) -> str:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if _is_rfc1918_or_local(address):
        return "internal-unknown"
    return "external-unknown"


def _is_rfc1918_or_local(address: ipaddress._BaseAddress) -> bool:
    private_networks = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10"),
    )
    return any(address in network for network in private_networks)


def _groups_from_nodes(nodes: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for node in nodes.values():
        group_id = str(node["group"])
        group = grouped.setdefault(
            group_id,
            {
                "id": group_id,
                "label": GROUP_LABELS.get(group_id, group_id.replace("-", " ").title()),
                "asset_count": 0,
                "recent_endpoint_count": 0,
                "zones": set(),
            },
        )
        if node.get("source") == "asset_input":
            group["asset_count"] += 1
        else:
            group["recent_endpoint_count"] += 1
        zone = str(node.get("zone") or "")
        if zone and zone != "-":
            group["zones"].add(zone)

    result = []
    for group in grouped.values():
        zones = sorted(group.pop("zones"))
        group["zones"] = zones
        group["total_count"] = int(group["asset_count"]) + int(group["recent_endpoint_count"])
        result.append(group)
    return sorted(result, key=lambda group: GROUP_ORDER.get(str(group["id"]), 99))


def _topology_status(
    asset_snapshot: SourceSnapshot | None,
    nodes: dict[str, dict[str, Any]],
) -> str:
    if asset_snapshot is None:
        return "missing_assets"
    if asset_snapshot.status != "used":
        return asset_snapshot.status
    if not any(node.get("source") == "asset_input" for node in nodes.values()):
        return "no_assets"
    return "ready"


def _is_alert_event(event: dict[str, Any]) -> bool:
    severity = str(event.get("severity") or "").lower()
    return (
        str(event.get("verdict") or "").lower() == "alert"
        or str(event.get("route") or "").lower() == "auto_alert"
        or severity in {"high", "critical"}
    )


def _as_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    if value in (None, ""):
        return []
    return [str(value)]
