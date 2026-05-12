from __future__ import annotations

import argparse
import csv
import json
import math
import shutil
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc.ml.features import binary_feature_contract


KST = timezone(timedelta(hours=9))
BASE_DATES = [datetime(2026, 5, day, tzinfo=KST) for day in range(2, 7)]
FLOW_INTERVAL = timedelta(minutes=7, seconds=12)
SCENARIO_DIR = ROOT / "config" / "scenarios" / "regional_care_dynamic_cve"

BENIGN_PORT_ROTATION = {
    "patient-portal-web": ["443", "80"],
    "appointment-api": ["443", "8443"],
    "employee-vpn": ["443"],
    "staff-saas-cloud": ["443"],
    "workstation-dns": ["53"],
    "workstation-ntp": ["123"],
    "ehr-api-access": ["443", "8443"],
    "lab-results-api-access": ["8443", "8080"],
    "app-to-db-query": ["5432", "1433", "3306"],
    "backup-window-smb": ["445"],
    "monitoring-scrape": ["443", "9100"],
    "admin-management": ["22", "3389", "443"],
    "pacs-dicom-access": ["443", "104"],
    "partner-sftp": ["22"],
    "edr-patch-update": ["443"],
    "workstation-web-browsing": ["443", "80"],
    "internal-file-share": ["445"],
}

ATTACK_SOURCE_PORT_FALLBACKS = {
    "Brute_Force_-Web": ["80", "443", "8080", "445"],
    "SQL_Injection": ["80"],
    "SSH-Bruteforce": ["22"],
    "DDOS_attack-HOIC": ["80"],
    "Infilteration": ["443", "80", "53", "541", "3306", "445", "22"],
}


@dataclass(frozen=True)
class SourceCandidate:
    row: dict[str, str]
    source_index: int
    source_stage: str


@dataclass(frozen=True)
class PlannedFlow:
    day_index: int
    slot: int
    kind: str
    scenario: str
    source_label: str
    source_attack: str
    source_port: str
    output_port: str
    src_ip: str
    dst_ip: str
    cve_id: str | None = None


def main() -> int:
    args = _parse_args()
    contract = binary_feature_contract()
    flow_plan = _load_yaml(args.flow_plan)
    output_columns, source_columns = _load_columns(args.source)

    planned_flows = _build_planned_flows(flow_plan)
    _validate_plan(planned_flows)
    source_needs = _source_needs(planned_flows)

    print("collecting source candidates from NF-CICIDS2018-v3...")
    candidates, scanned_rows = _collect_candidates(
        source_path=args.source,
        source_needs=source_needs,
        feature_order=contract.feature_order,
    )

    rows, trace = _materialize_rows(
        planned_flows=planned_flows,
        candidates=candidates,
        source_columns=source_columns,
        feature_order=contract.feature_order,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=output_columns)
        writer.writeheader()
        writer.writerows(rows)

    manifest_path = args.manifest or args.output.with_name(
        f"{args.output.stem}_manifest.json"
    )
    _write_manifest(
        manifest_path=manifest_path,
        rows=rows,
        trace=trace,
        scanned_rows=scanned_rows,
        source_path=args.source,
        output_path=args.output,
        flow_plan_path=args.flow_plan,
        feature_order=contract.feature_order,
    )
    if args.materialize_sources:
        _materialize_source_snapshots(args.generated_sources)

    print(f"wrote={len(rows)} output={args.output}")
    print(f"manifest={manifest_path}")
    if args.materialize_sources:
        print(f"generated_sources={args.generated_sources}")
    return 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate the regional-care dynamic CVE XGBoost flow CSV and "
            "day-specific source snapshots."
        )
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=ROOT / "Dataset" / "NF-CICIDS2018-v3.csv",
    )
    parser.add_argument(
        "--flow-plan",
        type=Path,
        default=SCENARIO_DIR / "flow_plan.yaml",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "data" / "sample" / "regional_care_dynamic_cve_flows_xgb.csv",
    )
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument(
        "--generated-sources",
        type=Path,
        default=SCENARIO_DIR / "generated",
    )
    parser.add_argument(
        "--no-materialize-sources",
        dest="materialize_sources",
        action="store_false",
    )
    parser.set_defaults(materialize_sources=True)
    return parser.parse_args()


def _load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML root must be a mapping: {path}")
    return data


def _load_columns(source_path: Path) -> tuple[list[str], list[str]]:
    with source_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        source_columns = list(reader.fieldnames or [])
    if "flow_id" in source_columns:
        raise ValueError("source dataset unexpectedly already has flow_id")
    if "mock_prob" in source_columns:
        raise ValueError("source dataset unexpectedly has mock_prob")
    return ["flow_id", *source_columns], source_columns


def _build_planned_flows(flow_plan: dict[str, Any]) -> list[PlannedFlow]:
    attack_slots_by_day = flow_plan["attack_slots_by_day"]
    attack_profiles = flow_plan["attack_daily_profiles"]
    benign_profiles = {
        item["key"]: int(item["daily_count"])
        for item in flow_plan["benign_daily_profiles"]
    }
    planned: list[PlannedFlow] = []
    for day_index, day_start in enumerate(BASE_DATES):
        day_key = f"day{day_index + 1:02d}"
        attack_slots = list(attack_slots_by_day[day_key])
        attack_queue = _expand_attack_profiles(day_index, attack_profiles[day_key])
        benign_queue = _build_benign_queue(
            day_index=day_index,
            attack_slots=set(attack_slots),
            benign_profiles=benign_profiles,
        )
        for slot in range(200):
            if slot in attack_slots:
                attack = attack_queue.pop(0)
                planned.append(_planned_attack(day_index, slot, attack))
            else:
                profile = benign_queue.pop(0)
                planned.append(_planned_benign(day_index, slot, profile))
        if attack_queue:
            raise RuntimeError(f"{day_key} attack queue was not fully consumed")
        if benign_queue:
            raise RuntimeError(f"{day_key} benign queue was not fully consumed")
    return planned


def _expand_attack_profiles(
    day_index: int, profiles: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    expanded: list[dict[str, Any]] = []
    for profile in profiles:
        for _ in range(int(profile["count"])):
            expanded.append(dict(profile))
    rotation = day_index % len(expanded)
    return expanded[rotation:] + expanded[:rotation]


def _build_benign_queue(
    *,
    day_index: int,
    attack_slots: set[int],
    benign_profiles: dict[str, int],
) -> list[str]:
    remaining = Counter(benign_profiles)
    queue: list[str] = []
    for slot in range(200):
        if slot in attack_slots:
            continue
        hour = _slot_start(day_index, slot).hour
        candidates = [key for key in _benign_preferences(hour, day_index) if remaining[key] > 0]
        if not candidates:
            candidates = [key for key, count in remaining.items() if count > 0]
        chosen = _choose_profile(candidates, remaining, slot + day_index)
        queue.append(chosen)
        remaining[chosen] -= 1
    if any(remaining.values()):
        raise RuntimeError(f"benign profile counts were not consumed: {remaining}")
    return queue


def _benign_preferences(hour: int, day_index: int) -> list[str]:
    kiosk_first = ["workstation-dns", "workstation-web-browsing", "lab-results-api-access"]
    if day_index >= 3:
        kiosk_first = ["workstation-dns", "lab-results-api-access", "workstation-web-browsing"]
    if 2 <= hour < 4:
        return [
            "backup-window-smb",
            "workstation-dns",
            "workstation-ntp",
            "edr-patch-update",
            "monitoring-scrape",
        ]
    if 6 <= hour < 8:
        return ["partner-sftp", "workstation-dns", "employee-vpn", "edr-patch-update"]
    if 8 <= hour < 12:
        return [
            "patient-portal-web",
            "appointment-api",
            "ehr-api-access",
            "lab-results-api-access",
            "pacs-dicom-access",
            "app-to-db-query",
            "workstation-dns",
            "employee-vpn",
        ]
    if 12 <= hour < 17:
        return [
            "patient-portal-web",
            "ehr-api-access",
            "staff-saas-cloud",
            "lab-results-api-access",
            "pacs-dicom-access",
            "workstation-web-browsing",
            "internal-file-share",
            "workstation-dns",
        ]
    if 17 <= hour < 20:
        return [
            "employee-vpn",
            "staff-saas-cloud",
            "admin-management",
            "monitoring-scrape",
            "patient-portal-web",
            "appointment-api",
            "workstation-dns",
        ]
    if 20 <= hour or hour < 2:
        return [
            "admin-management",
            "monitoring-scrape",
            "workstation-ntp",
            "edr-patch-update",
            "patient-portal-web",
            "employee-vpn",
            "workstation-dns",
        ]
    return kiosk_first


def _choose_profile(candidates: list[str], remaining: Counter[str], rotation: int) -> str:
    best = max(remaining[key] for key in candidates)
    top = [key for key in candidates if remaining[key] == best]
    return top[rotation % len(top)]


def _planned_benign(day_index: int, slot: int, profile: str) -> PlannedFlow:
    output_port = _benign_output_port(profile, day_index, slot)
    src_ip, dst_ip = _benign_endpoints(profile, day_index, slot, output_port)
    return PlannedFlow(
        day_index=day_index,
        slot=slot,
        kind="benign",
        scenario=profile,
        source_label="Benign",
        source_attack="Benign",
        source_port=output_port,
        output_port=output_port,
        src_ip=src_ip,
        dst_ip=dst_ip,
    )


def _planned_attack(day_index: int, slot: int, profile: dict[str, Any]) -> PlannedFlow:
    output_port = _select_output_port([str(port) for port in profile["dst_ports"]], day_index, slot)
    source_attack = str(profile["source_attack"])
    source_port = _attack_source_port(source_attack, output_port)
    src_ip = str(profile.get("src_ip") or _attack_source_ip(str(profile["key"]), day_index, slot))
    return PlannedFlow(
        day_index=day_index,
        slot=slot,
        kind="attack",
        scenario=str(profile["key"]),
        source_label="Malicious",
        source_attack=source_attack,
        source_port=source_port,
        output_port=output_port,
        src_ip=src_ip,
        dst_ip=str(profile["dst_ip"]),
        cve_id=profile.get("cve_id"),
    )


def _select_output_port(ports: list[str], day_index: int, slot: int) -> str:
    return ports[(day_index + slot) % len(ports)]


def _benign_output_port(profile: str, day_index: int, slot: int) -> str:
    if profile == "admin-management" and day_index == 4 and slot % 5 == 0:
        return "541"
    return _select_output_port(BENIGN_PORT_ROTATION[profile], day_index, slot)


def _attack_source_port(source_attack: str, output_port: str) -> str:
    fallbacks = ATTACK_SOURCE_PORT_FALLBACKS[source_attack]
    if output_port in fallbacks:
        return output_port
    if source_attack == "Brute_Force_-Web" and output_port == "8443":
        return "8080"
    return fallbacks[0]


def _validate_plan(planned_flows: list[PlannedFlow]) -> None:
    if len(planned_flows) != 1000:
        raise RuntimeError(f"expected 1000 planned flows, got {len(planned_flows)}")
    for day_index in range(5):
        day = [flow for flow in planned_flows if flow.day_index == day_index]
        benign_count = sum(1 for flow in day if flow.kind == "benign")
        attack_count = sum(1 for flow in day if flow.kind == "attack")
        if len(day) != 200 or benign_count != 180 or attack_count != 20:
            raise RuntimeError(
                f"bad day {day_index + 1}: total={len(day)} benign={benign_count} attack={attack_count}"
            )


def _source_needs(planned_flows: list[PlannedFlow]) -> Counter[tuple[str, str, str]]:
    needs: Counter[tuple[str, str, str]] = Counter()
    for flow in planned_flows:
        needs[(flow.source_label, flow.source_attack, flow.source_port)] += 1
    return needs


def _collect_candidates(
    *,
    source_path: Path,
    source_needs: Counter[tuple[str, str, str]],
    feature_order: list[str],
) -> tuple[dict[tuple[str, str, str], list[SourceCandidate]], int]:
    pools: dict[tuple[str, str, str], list[SourceCandidate]] = defaultdict(list)
    initial_benign_run = True
    scanned_rows = 0
    with source_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for source_index, row in enumerate(reader):
            scanned_rows = source_index + 1
            attack = str(row.get("Attack") or "")
            label = "Benign" if attack == "Benign" else "Malicious"
            port = str(row.get("L4_DST_PORT") or "")
            key = (label, attack, port)
            if key in source_needs and len(pools[key]) < source_needs[key]:
                if _row_has_ml_features(row, feature_order):
                    stage = (
                        "initial_benign_run"
                        if label == "Benign" and initial_benign_run
                        else "source_label_port_match"
                    )
                    pools[key].append(SourceCandidate(dict(row), source_index, stage))
            if label != "Benign":
                initial_benign_run = False
            if all(len(pools[key]) >= count for key, count in source_needs.items()):
                break
    missing = {
        "|".join(key): count - len(pools[key])
        for key, count in source_needs.items()
        if len(pools[key]) < count
    }
    if missing:
        raise RuntimeError(f"source dataset did not satisfy candidate needs: {missing}")
    return dict(pools), scanned_rows


def _row_has_ml_features(row: dict[str, str], feature_order: list[str]) -> bool:
    for feature in feature_order:
        value = row.get(feature)
        if value in (None, ""):
            return False
        try:
            numeric = float(value)
        except ValueError:
            return False
        if not math.isfinite(numeric):
            return False
    return True


def _materialize_rows(
    *,
    planned_flows: list[PlannedFlow],
    candidates: dict[tuple[str, str, str], list[SourceCandidate]],
    source_columns: list[str],
    feature_order: list[str],
) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    rows: list[dict[str, str]] = []
    trace: list[dict[str, Any]] = []
    for planned in planned_flows:
        key = (planned.source_label, planned.source_attack, planned.source_port)
        candidate = candidates[key].pop(0)
        flow_id = (
            f"xgb-d{planned.day_index + 1:02d}-{planned.kind}-"
            f"{planned.scenario}-{planned.slot + 1:03d}"
        )
        row = _materialize_row(
            flow_id=flow_id,
            planned=planned,
            candidate=candidate,
            source_columns=source_columns,
            feature_order=feature_order,
        )
        rows.append(row)
        trace.append(_trace_row(flow_id, planned, candidate, row))
    rows.sort(key=lambda row: int(row["FLOW_START_MILLISECONDS"]))
    return rows, trace


def _materialize_row(
    *,
    flow_id: str,
    planned: PlannedFlow,
    candidate: SourceCandidate,
    source_columns: list[str],
    feature_order: list[str],
) -> dict[str, str]:
    output = {"flow_id": flow_id}
    output.update({column: candidate.row.get(column, "") for column in source_columns})
    start = _slot_start(planned.day_index, planned.slot)
    start_ms = _epoch_ms(start)
    output["FLOW_START_MILLISECONDS"] = str(start_ms)
    output["FLOW_END_MILLISECONDS"] = str(start_ms + _source_duration_ms(candidate.row))
    output["IPV4_SRC_ADDR"] = planned.src_ip
    output["L4_SRC_PORT"] = str(_src_port(planned.day_index, planned.slot, planned.output_port))
    output["IPV4_DST_ADDR"] = planned.dst_ip
    output["L4_DST_PORT"] = planned.output_port
    output["Label"] = "Benign" if planned.kind == "benign" else "Malicious"
    output["Attack"] = "Benign" if planned.kind == "benign" else planned.source_attack
    if "mock_prob" in output:
        raise ValueError("generated XGBoost scenario must not include mock_prob")
    if not _row_has_ml_features(output, feature_order):
        raise ValueError(f"generated row has invalid ML features: {flow_id}")
    return {key: str(value) for key, value in output.items()}


def _trace_row(
    flow_id: str,
    planned: PlannedFlow,
    candidate: SourceCandidate,
    row: dict[str, str],
) -> dict[str, Any]:
    projection_reasons: list[str] = []
    if candidate.row.get("L4_DST_PORT") != row.get("L4_DST_PORT"):
        projection_reasons.append("service port projected to regional-care topology")
    if candidate.row.get("PROTOCOL") != row.get("PROTOCOL"):
        projection_reasons.append("protocol projected to regional-care topology")
    return {
        "flow_id": flow_id,
        "day": planned.day_index + 1,
        "scenario": planned.scenario,
        "cve_id": planned.cve_id,
        "label": row["Label"],
        "attack": row["Attack"],
        "source_index": candidate.source_index,
        "source_stage": candidate.source_stage,
        "source_attack": candidate.row.get("Attack"),
        "source_dst_port": candidate.row.get("L4_DST_PORT"),
        "output_dst_port": row.get("L4_DST_PORT"),
        "source_protocol": candidate.row.get("PROTOCOL"),
        "output_protocol": row.get("PROTOCOL"),
        "projection_reason": "; ".join(projection_reasons) if projection_reasons else "",
    }


def _slot_start(day_index: int, slot: int) -> datetime:
    return BASE_DATES[day_index] + timedelta(minutes=5) + slot * FLOW_INTERVAL


def _src_port(day_index: int, slot: int, dst_port: str) -> int:
    if dst_port == "53":
        return 53000 + day_index * 400 + slot
    if dst_port == "123":
        return 12300 + day_index * 400 + slot
    return 49152 + day_index * 2400 + slot * 7


def _benign_endpoints(profile: str, day_index: int, slot: int, port: str) -> tuple[str, str]:
    if profile == "patient-portal-web":
        return _external_patient_ip(day_index, slot), "203.0.113.10"
    if profile == "appointment-api":
        return _external_patient_ip(day_index, slot + 11), "203.0.113.30"
    if profile == "employee-vpn":
        return _staff_remote_ip(day_index, slot), "203.0.113.20"
    if profile == "staff-saas-cloud":
        return _workstation_ip(day_index, slot), "198.51.100.150"
    if profile == "workstation-dns":
        return _workstation_ip(day_index, slot), "10.60.60.5"
    if profile == "workstation-ntp":
        return _workstation_ip(day_index, slot), "10.60.60.15"
    if profile == "ehr-api-access":
        return _workstation_ip(day_index, slot), "10.60.20.15"
    if profile == "lab-results-api-access":
        return _workstation_ip(day_index, slot + 3), "10.60.20.30"
    if profile == "app-to-db-query":
        src = "10.60.20.30" if port == "3306" else "10.60.20.15"
        dst = {"5432": "10.60.30.20", "1433": "10.60.30.25", "3306": "10.60.30.30"}[port]
        return src, dst
    if profile == "backup-window-smb":
        return "10.60.40.10" if slot % 2 else "10.60.50.8", "10.60.40.12"
    if profile == "monitoring-scrape":
        return "10.60.60.20", "10.60.50.30" if port == "9100" else "10.60.20.15"
    if profile == "admin-management":
        if day_index == 4 and slot % 5 == 0:
            return "10.60.50.8", "10.60.50.30"
        if port == "3389":
            return "10.60.50.8", "10.60.50.8"
        return "10.60.50.8", "10.60.50.20" if port == "443" else "10.60.50.8"
    if profile == "pacs-dicom-access":
        return _doctor_laptop_ip(day_index, slot), "10.60.35.10"
    if profile == "partner-sftp":
        return "198.51.100.180", "203.0.113.40"
    if profile == "edr-patch-update":
        return _workstation_ip(day_index, slot), "10.60.50.15" if slot % 2 else "10.60.50.20"
    if profile == "workstation-web-browsing":
        return _workstation_ip(day_index, slot), "198.51.100.151" if port == "443" else "198.51.100.152"
    if profile == "internal-file-share":
        return _workstation_ip(day_index, slot), "10.60.60.10"
    raise ValueError(f"unknown benign profile: {profile}")


def _attack_source_ip(scenario: str, day_index: int, slot: int) -> str:
    if scenario in {"portal-web-probe", "public-web-probe", "public-web-noise"}:
        return "198.51.100.88"
    if scenario in {"tomcat-lab-api-probe", "tomcat-appointment-api-probe", "tomcat-repeat-probe", "tomcat-residual-probe"}:
        return "198.51.100.91" if day_index >= 3 else "192.0.2.210"
    if scenario == "vpn-password-spray":
        return "198.51.100.77"
    if scenario in {"direct-db-probe", "retired-reporting-db-scan", "appointment-api-sql"}:
        return "198.51.100.90"
    if scenario in {"admin-ssh-bruteforce", "admin-jumpbox-bruteforce", "partner-sftp-bruteforce"}:
        return f"192.0.2.{70 + day_index + slot % 9}"
    if scenario in {"backup-smb-tamper", "workstation-domain-smb"}:
        return _workstation_ip(day_index, slot)
    if scenario in {"dns-tunnel-burst", "metadata-service-access", "kiosk-to-lab-anomaly"}:
        return _workstation_ip(day_index, slot + 5)
    if scenario in {"backup-exfil-https"}:
        return "10.60.40.12"
    if scenario in {"portal-ddos-burst"}:
        return f"198.51.100.{180 + day_index}"
    if scenario == "fortimanager-541-probe":
        return "10.60.100.96" if slot % 2 else "192.0.2.88"
    if scenario in {"firewall-manager-egress"}:
        return "10.60.50.30"
    if scenario in {"app-host-followup-egress", "app-to-db-unusual", "tomcat-followup-lateral"}:
        return "10.60.20.30"
    return f"192.0.2.{100 + ((day_index + slot) % 80)}"


def _external_patient_ip(day_index: int, slot: int) -> str:
    return f"198.51.100.{20 + ((slot + day_index * 7) % 45)}"


def _staff_remote_ip(day_index: int, slot: int) -> str:
    return f"192.0.2.{20 + ((slot + day_index * 11) % 60)}"


def _workstation_ip(day_index: int, slot: int) -> str:
    if day_index >= 3 and slot % 11 == 0:
        return f"10.60.100.{96 + (slot % 3)}"
    pools = [
        range(21, 40),
        range(41, 60),
        range(61, 80),
        range(81, 95),
    ]
    pool = pools[(slot + day_index) % len(pools)]
    values = list(pool)
    return f"10.60.100.{values[(slot + day_index * 13) % len(values)]}"


def _doctor_laptop_ip(day_index: int, slot: int) -> str:
    return f"10.60.100.{61 + ((slot + day_index) % 3)}"


def _source_duration_ms(row: dict[str, str]) -> int:
    try:
        duration = int(float(row.get("FLOW_DURATION_MILLISECONDS", "0")))
    except ValueError:
        duration = 0
    return min(max(duration, 1), 420000)


def _epoch_ms(value: datetime) -> int:
    return int(value.timestamp() * 1000)


def _write_manifest(
    *,
    manifest_path: Path,
    rows: list[dict[str, str]],
    trace: list[dict[str, Any]],
    scanned_rows: int,
    source_path: Path,
    output_path: Path,
    flow_plan_path: Path,
    feature_order: list[str],
) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    label_counts = Counter(row["Label"] for row in rows)
    attack_counts = Counter(row["Attack"] for row in rows)
    day_counts = Counter(item["day"] for item in trace)
    scenario_counts = Counter(item["scenario"] for item in trace)
    cve_counts = Counter(item["cve_id"] for item in trace if item.get("cve_id"))
    projection_overrides = [
        item
        for item in trace
        if item["source_dst_port"] != item["output_dst_port"]
        or item["source_protocol"] != item["output_protocol"]
    ]
    manifest = {
        "dataset": str(output_path.as_posix()),
        "source_dataset": str(source_path.as_posix()),
        "flow_plan": str(flow_plan_path.as_posix()),
        "generator": "scripts/generate_regional_care_dynamic_cve_xgb_flows.py",
        "row_count": len(rows),
        "scanned_source_rows": scanned_rows,
        "date_range_kst": [BASE_DATES[0].date().isoformat(), BASE_DATES[-1].date().isoformat()],
        "schema": {
            "mock_prob_present": False,
            "ml_feature_count": len(feature_order),
            "ml_feature_order": feature_order,
            "output_column_count": len(rows[0]) if rows else 0,
        },
        "generation_policy": {
            "ml_feature_preservation": "Rows preserve source NF-CICIDS2018-v3 model feature vectors except audited topology projections.",
            "benign": "Benign rows are source-order candidates selected by service port to preserve normal feature/label relationships.",
            "attacks": "Attack rows keep real attack-label feature vectors, then project IP, time, source port, and selected service ports into the regional-care topology.",
            "projection_overrides": "Every changed destination port or protocol is listed in projection_overrides.",
        },
        "label_counts": dict(label_counts),
        "attack_counts": dict(attack_counts),
        "day_counts": {str(day): count for day, count in sorted(day_counts.items())},
        "scenario_counts": dict(scenario_counts),
        "cve_counts": dict(cve_counts),
        "projection_override_count": len(projection_overrides),
        "projection_overrides": projection_overrides,
        "source_trace": trace,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _materialize_source_snapshots(output_dir: Path) -> None:
    base_dir = SCENARIO_DIR / "base"
    overlay_dir = SCENARIO_DIR / "overlays"
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    base_sources = {
        name: _load_yaml(base_dir / f"{name}.yaml")
        for name in ("organization", "assets", "policy", "cve_feed", "threat_feed")
    }
    day03 = _load_yaml(overlay_dir / "day03_cve_tomcat.yaml")
    day04 = _load_yaml(overlay_dir / "day04_inventory_and_ioc.yaml")
    day05 = _load_yaml(overlay_dir / "day05_cve_fortimanager.yaml")

    for day_index in range(1, 6):
        day_sources = _deepcopy_jsonable(base_sources)
        if day_index >= 3:
            _append_list(
                day_sources["cve_feed"],
                "advisories",
                day03["cve_feed_additions"]["advisories"],
            )
        if day_index >= 4:
            _append_list(day_sources["assets"], "assets", day04["asset_additions"]["assets"])
            _apply_asset_updates(day_sources["assets"], day04["asset_updates"])
            _append_list(
                day_sources["policy"],
                "asset_specific_policies",
                day04["policy_additions"]["asset_specific_policies"],
            )
            _append_list(
                day_sources["threat_feed"],
                "known_malicious_ips",
                day04["threat_feed_additions"]["known_malicious_ips"],
            )
            _append_list(
                day_sources["threat_feed"],
                "suspicious_patterns",
                day04["threat_feed_additions"]["suspicious_patterns"],
            )
        if day_index >= 5:
            _append_list(
                day_sources["cve_feed"],
                "advisories",
                day05["cve_feed_additions"]["advisories"],
            )
            _append_list(
                day_sources["threat_feed"],
                "suspicious_patterns",
                day05["threat_feed_additions"]["suspicious_patterns"],
            )
        day_dir = output_dir / f"day{day_index:02d}"
        day_dir.mkdir(parents=True, exist_ok=True)
        for name, data in day_sources.items():
            (day_dir / f"{name}.yaml").write_text(
                yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
                encoding="utf-8",
            )


def _deepcopy_jsonable(data: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(data))


def _append_list(target: dict[str, Any], key: str, additions: list[dict[str, Any]]) -> None:
    target.setdefault(key, [])
    target[key].extend(_deepcopy_jsonable({"items": additions})["items"])


def _apply_asset_updates(assets_doc: dict[str, Any], updates: list[dict[str, Any]]) -> None:
    by_ip = {asset.get("ip"): asset for asset in assets_doc.get("assets", []) if isinstance(asset, dict)}
    for update in updates:
        asset = by_ip.get(update["ip"])
        if asset is not None:
            asset.update({key: value for key, value in update.items() if key != "ip"})


if __name__ == "__main__":
    raise SystemExit(main())
