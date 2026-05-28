from __future__ import annotations

import html
import ipaddress
import json
import re
import shutil
from pathlib import Path
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


GROUP_EDGE_POLICY = (
    ("external", "dmz"),
    ("dmz", "internal-app"),
    ("workstation", "internal-app"),
    ("admin", "internal-app"),
    ("admin", "infrastructure"),
    ("admin", "backup"),
    ("infrastructure", "internal-app"),
    ("internal-app", "database"),
    ("internal-app", "clinical"),
    ("internal-app", "backup"),
    ("clinical", "internal-app"),
)


def write_topology_artifact(
    *,
    snapshots: list[SourceSnapshot],
    watchlist: dict[str, Any],
    output_dir: str | Path,
    cycle_id: str,
) -> None:
    artifact = build_mermaid_topology_artifact(
        snapshots=snapshots,
        watchlist=watchlist,
        cycle_id=cycle_id,
    )
    topology_dir = Path(output_dir) / "topology"
    topology_dir.mkdir(parents=True, exist_ok=True)

    mermaid_path = topology_dir / f"topology_{cycle_id}.mmd"
    map_path = topology_dir / f"topology_{cycle_id}.json"
    mermaid_path.write_text(artifact["mermaid"], encoding="utf-8")
    map_path.write_text(
        json.dumps(artifact["runtime_map"], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    shutil.copyfile(mermaid_path, topology_dir / "latest.mmd")
    shutil.copyfile(map_path, topology_dir / "latest.json")


def build_mermaid_topology_artifact(
    *,
    snapshots: list[SourceSnapshot],
    watchlist: dict[str, Any],
    cycle_id: str,
) -> dict[str, Any]:
    asset_snapshot = next((item for item in snapshots if item.name == "assets"), None)
    assets_data = _load_assets_yaml(asset_snapshot)
    trust_zones = _trust_zones(assets_data)
    focus_by_ip = _watchlist_focus_by_ip(watchlist)

    groups: dict[str, list[dict[str, Any]]] = {}
    subnets_by_group: dict[str, list[dict[str, Any]]] = {}
    runtime_nodes: list[dict[str, Any]] = []
    nodes_by_ip: dict[str, str] = {}

    for trust_zone in trust_zones:
        group = _classify_group(str(trust_zone.get("zone") or ""))
        subnets_by_group.setdefault(group, []).append(
            {
                "id": _mermaid_id(f"subnet_{trust_zone.get('cidr')}_{trust_zone.get('zone')}"),
                "cidr": str(trust_zone.get("cidr") or ""),
                "zone": str(trust_zone.get("zone") or ""),
            }
        )

    for asset in _asset_items(assets_data):
        ip = str(asset.get("ip") or "").strip()
        if not ip:
            continue
        role = str(asset.get("role") or asset.get("id") or ip)
        services = _as_string_list(asset.get("services"))
        zone = str(asset.get("zone") or _zone_for_ip(ip, trust_zones) or "")
        group = _classify_group(" ".join([zone, role, " ".join(services)]))
        node_id = _asset_node_id(asset, ip)
        focus = focus_by_ip.get(ip, {})
        node = {
            "id": node_id,
            "ip": ip,
            "label": role,
            "group": group,
            "zone": zone or "-",
            "services": services,
            "criticality": str(asset.get("criticality") or "unknown"),
            "status": str(asset.get("status") or "active"),
            "priority": focus.get("priority"),
            "watchlist_item_id": focus.get("item_id"),
            "base_class": _base_node_class(asset, focus),
        }
        groups.setdefault(group, []).append(node)
        runtime_nodes.append(node)
        nodes_by_ip[ip] = node_id

    for group in subnets_by_group:
        groups.setdefault(group, [])

    if groups and "external" not in groups:
        groups["external"] = []

    for nodes in groups.values():
        nodes.sort(key=_node_sort_key)
    ordered_groups = sorted(groups.items(), key=lambda item: GROUP_ORDER.get(item[0], 99))

    mermaid = _render_mermaid(cycle_id, ordered_groups, subnets_by_group)
    return {
        "mermaid": mermaid,
        "runtime_map": {
            "cycle_id": cycle_id,
            "layout_policy": "stable-zone-mermaid-v1",
            "nodes_by_ip": nodes_by_ip,
            "nodes": sorted(runtime_nodes, key=lambda node: (GROUP_ORDER.get(node["group"], 99), node["label"], node["ip"])),
        },
    }


def _render_mermaid(
    cycle_id: str,
    ordered_groups: list[tuple[str, list[dict[str, Any]]]],
    subnets_by_group: dict[str, list[dict[str, Any]]],
) -> str:
    lines = [
        f"%% Tier 2 topology artifact: {cycle_id}",
        "flowchart LR",
    ]
    class_members: dict[str, list[str]] = {
        "zoneHub": [],
        "normal": [],
        "critical": [],
        "retired": [],
        "watchP1": [],
        "watchP2": [],
        "watchP3": [],
        "subnet": [],
    }
    group_ids = {group_id for group_id, _ in ordered_groups}

    for group_id, nodes in ordered_groups:
        group_node = _group_node_id(group_id)
        class_members["zoneHub"].append(group_node)
        label = GROUP_LABELS.get(group_id, group_id.replace("-", " ").title())
        lines.append(f"  subgraph {_mermaid_id('zone_' + group_id)}[\"{_label(label)}\"]")
        lines.append("    direction TB")
        lines.append(f"    {group_node}((\"{len(nodes)}\"))")
        for subnet in sorted(subnets_by_group.get(group_id, []), key=lambda item: (item["zone"], item["cidr"])):
            lines.append(f"    {subnet['id']}[\"{_label(subnet['cidr'])}<br/>{_label(subnet['zone'])}\"]")
            lines.append(f"    {group_node} --- {subnet['id']}")
            class_members["subnet"].append(str(subnet["id"]))
        for node in nodes:
            service_label = ", ".join(node["services"][:2]) or node["zone"]
            lines.append(
                f"    {node['id']}[\"{_label(_short_node_label(node['label']))}<br/>{_label(node['ip'])}<br/>{_label(service_label)}\"]"
            )
            lines.append(f"    {group_node} --- {node['id']}")
            class_members.setdefault(str(node["base_class"]), []).append(str(node["id"]))
        lines.append("  end")

    for src, dst in GROUP_EDGE_POLICY:
        if src in group_ids and dst in group_ids:
            lines.append(f"  {_group_node_id(src)} --> {_group_node_id(dst)}")

    lines.extend(
        [
            "  classDef zoneHub fill:#121820,stroke:#6b7280,color:#edf2f7,stroke-width:1.4px,font-size:12px;",
            "  classDef normal fill:#1f2630,stroke:#4b5565,color:#edf2f7,font-size:12px;",
            "  classDef critical fill:#222a38,stroke:#6c8ff0,color:#edf2f7,stroke-width:1.6px,font-size:12px;",
            "  classDef subnet fill:#151b23,stroke:#384657,color:#c7d0dc,stroke-width:1px,font-size:10px;",
            "  classDef retired fill:#1b1f25,stroke:#596273,color:#8f9aaa,stroke-dasharray: 4 3,font-size:12px;",
            "  classDef watchP1 fill:#421820,stroke:#f35d6a,color:#ffe1e4,stroke-width:2.4px,font-size:12px;",
            "  classDef watchP2 fill:#3a2d12,stroke:#f1b84b,color:#fff3ce,stroke-width:2px,font-size:12px;",
            "  classDef watchP3 fill:#163226,stroke:#45c486,color:#ddffec,stroke-width:1.8px,font-size:12px;",
            "  classDef liveFlow fill:#123447,stroke:#4bb6d8,color:#edf2f7,stroke-width:2.4px,font-size:12px;",
            "  classDef selected fill:#102f44,stroke:#4bb6d8,color:#edf2f7,stroke-width:3px,font-size:12px;",
            "  classDef alertHit fill:#4b1720,stroke:#f35d6a,color:#ffe1e4,stroke-width:3px,font-size:12px;",
            "  classDef watchHit fill:#42300f,stroke:#f1b84b,color:#fff3ce,stroke-width:2.6px,font-size:12px;",
        ]
    )
    for class_name, members in class_members.items():
        if members:
            lines.append(f"  class {','.join(members)} {class_name};")
    return "\n".join(lines) + "\n"


def _watchlist_focus_by_ip(watchlist: dict[str, Any]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    ranks = {"priority_1": 1, "priority_2": 2, "priority_3": 3}
    for priority in ("priority_1", "priority_2", "priority_3"):
        items = watchlist.get(priority)
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            item_id = str(item.get("id") or "")
            targets = item.get("target_assets")
            if not isinstance(targets, list):
                continue
            for target in targets:
                if not isinstance(target, dict):
                    continue
                ip = str(target.get("ip") or "").strip()
                if not ip:
                    continue
                current = result.get(ip)
                if current and ranks.get(str(current.get("priority")), 99) <= ranks[priority]:
                    continue
                result[ip] = {"priority": priority, "item_id": item_id}
    return result


def _base_node_class(asset: dict[str, Any], focus: dict[str, str]) -> str:
    priority = focus.get("priority")
    if priority == "priority_1":
        return "watchP1"
    if priority == "priority_2":
        return "watchP2"
    if priority == "priority_3":
        return "watchP3"
    if str(asset.get("status") or "").lower() == "retired":
        return "retired"
    if str(asset.get("criticality") or "").lower() in {"critical", "high"}:
        return "critical"
    return "normal"


def _node_sort_key(node: dict[str, Any]) -> tuple[int, str, str]:
    criticality_rank = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
    }.get(str(node.get("criticality") or "").lower(), 4)
    return (criticality_rank, str(node.get("label") or ""), str(node.get("ip") or ""))


def _asset_node_id(asset: dict[str, Any], ip: str) -> str:
    stable = str(asset.get("id") or asset.get("role") or ip)
    return _mermaid_id(f"asset_{stable}_{ip}")


def _group_node_id(group_id: str) -> str:
    return _mermaid_id(f"group_{group_id}")


def _mermaid_id(value: str) -> str:
    cleaned = re.sub(r"[^0-9A-Za-z_]+", "_", value.strip()).strip("_").lower()
    if not cleaned:
        return "node"
    if cleaned[0].isdigit():
        cleaned = f"n_{cleaned}"
    return cleaned


def _label(value: str) -> str:
    return html.escape(str(value), quote=True)


def _short_group_label(label: str) -> str:
    return label.split("/")[0].strip()


def _short_node_label(label: str) -> str:
    text = str(label)
    return text if len(text) <= 22 else f"{text[:19]}..."


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


def _trust_zones(data: dict[str, Any]) -> list[dict[str, Any]]:
    zones = data.get("trust_zones")
    if not isinstance(zones, list):
        return []
    result: list[dict[str, Any]] = []
    for item in zones:
        if not isinstance(item, dict):
            continue
        cidr = str(item.get("cidr") or "")
        zone = str(item.get("zone") or "")
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        result.append({"cidr": cidr, "zone": zone, "network": network})
    return sorted(result, key=lambda zone: zone["network"].prefixlen, reverse=True)


def _zone_for_ip(ip: str, trust_zones: list[dict[str, Any]]) -> str | None:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for zone in trust_zones:
        if address in zone["network"]:
            return str(zone["zone"])
    return None


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


def _as_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    if value in (None, ""):
        return []
    return [str(value)]
