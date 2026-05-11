from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from soc.ml.features import binary_feature_contract


KST = timezone(timedelta(hours=9))
BASE_DATES = [
    datetime(2026, 5, 2, tzinfo=KST),
    datetime(2026, 5, 3, tzinfo=KST),
    datetime(2026, 5, 4, tzinfo=KST),
]
ATTACK_SLOTS = [9, 18, 27, 36, 45, 54, 63, 72, 81, 90]

BENIGN_DAILY_QUOTAS = {
    "patient-portal-https": 9,
    "patient-portal-http": 12,
    "employee-vpn": 5,
    "ehr-https": 4,
    "staff-saas": 4,
    "cloud-update": 2,
    "internal-dns": 18,
    "backup-smb": 6,
    "nightly-backup": 3,
    "admin-rdp": 6,
    "admin-ssh": 6,
    "time-sync": 6,
    "ehr-api-8443": 3,
    "app-db-mysql": 3,
    "app-db-mssql": 3,
}

BENIGN_PROFILE_PORTS = {
    "patient-portal-https": "443",
    "patient-portal-http": "80",
    "employee-vpn": "443",
    "ehr-https": "443",
    "staff-saas": "443",
    "cloud-update": "443",
    "internal-dns": "53",
    "backup-smb": "445",
    "nightly-backup": "445",
    "admin-rdp": "3389",
    "admin-ssh": "22",
    "time-sync": "123",
    "ehr-api-8443": "8443",
    "app-db-mysql": "3306",
    "app-db-mssql": "1433",
}

ATTACK_PLAN = [
    {
        "key": "vpn-web-probe",
        "source_key": "web_bruteforce_443",
        "dst_ip": "203.0.113.20",
        "dst_port": "443",
        "protocol": "6",
    },
    {
        "key": "portal-sql-injection",
        "source_key": "sql_injection_80",
        "dst_ip": "203.0.113.10",
        "dst_port": "80",
        "protocol": "6",
    },
    {
        "key": "admin-ssh-bruteforce",
        "source_key": "ssh_bruteforce_22",
        "dst_ip": "10.42.50.8",
        "dst_port": "22",
        "protocol": "6",
    },
    {
        "key": "backup-smb-tamper",
        "source_key": "web_bruteforce_445",
        "dst_ip": "10.42.40.12",
        "dst_port": "445",
        "protocol": "6",
    },
    {
        "key": "dns-tunnel-burst",
        "source_key": "infiltration_53",
        "dst_ip": "8.8.8.8",
        "dst_port": "53",
        "protocol": "17",
    },
    {
        "key": "metadata-service-access",
        "source_key": "infiltration_80",
        "dst_ip": "169.254.169.254",
        "dst_port": "80",
        "protocol": "6",
    },
    {
        "key": "portal-ddos-burst",
        "source_key": "ddos_hoic_80",
        "dst_ip": "203.0.113.10",
        "dst_port": "80",
        "protocol": "6",
    },
    {
        "key": "backup-exfil-https",
        "source_key": "infiltration_443",
        "dst_ip": "198.51.100.123",
        "dst_port": "443",
        "protocol": "6",
    },
    {
        "key": "external-postgres-probe",
        "source_key": "sql_injection_80",
        "dst_ip": "10.42.30.25",
        "dst_port": "5432",
        "protocol": "6",
    },
    {
        "key": "vpn-followup-infiltration",
        "source_key": "infiltration_443",
        "dst_ip": "203.0.113.20",
        "dst_port": "443",
        "protocol": "6",
    },
]

ATTACK_SOURCE_SPECS = {
    "web_bruteforce_443": ("Brute_Force_-Web", "443"),
    "sql_injection_80": ("SQL_Injection", "80"),
    "ssh_bruteforce_22": ("SSH-Bruteforce", "22"),
    "web_bruteforce_445": ("Brute_Force_-Web", "445"),
    "infiltration_53": ("Infilteration", "53"),
    "infiltration_80": ("Infilteration", "80"),
    "ddos_hoic_80": ("DDOS_attack-HOIC", "80"),
    "infiltration_443": ("Infilteration", "443"),
}


@dataclass(frozen=True)
class SourceCandidate:
    row: dict[str, str]
    source_index: int
    source_stage: str


def main() -> int:
    args = _parse_args()
    contract = binary_feature_contract()
    output_columns, source_columns = _load_columns(args.source)
    benign_needs = _benign_port_needs()
    attack_needs = _attack_source_needs()

    print("collecting source candidates from NF-CICIDS2018-v3...")
    candidates, scanned_rows = _collect_candidates(
        source_path=args.source,
        benign_needs=benign_needs,
        attack_needs=attack_needs,
        feature_order=contract.feature_order,
    )

    rows, trace = _build_rows(
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
        feature_order=contract.feature_order,
    )
    print(f"wrote={len(rows)} output={args.output}")
    print(f"manifest={manifest_path}")
    return 0


def _parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description=(
            "Generate a clinic telehealth flow set with NF-CICIDS2018-v3 "
            "features for XGBoost/SHAP evaluation."
        )
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=repo_root / "Dataset" / "NF-CICIDS2018-v3.csv",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=repo_root / "data" / "sample" / "clinic_telehealth_flows_xgb.csv",
    )
    parser.add_argument("--manifest", type=Path, default=None)
    return parser.parse_args()


def _load_columns(source_path: Path) -> tuple[list[str], list[str]]:
    with source_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        source_columns = list(reader.fieldnames or [])
    if "flow_id" in source_columns:
        raise ValueError("source dataset unexpectedly already has flow_id")
    if "mock_prob" in source_columns:
        raise ValueError("source dataset unexpectedly has mock_prob")
    return ["flow_id", *source_columns], source_columns


def _benign_port_needs() -> Counter[str]:
    if sum(BENIGN_DAILY_QUOTAS.values()) != 90:
        raise ValueError("BENIGN_DAILY_QUOTAS must sum to 90")
    needs: Counter[str] = Counter()
    for key, count in BENIGN_DAILY_QUOTAS.items():
        needs[BENIGN_PROFILE_PORTS[key]] += count * len(BASE_DATES)
    return needs


def _attack_source_needs() -> Counter[str]:
    if len(ATTACK_PLAN) != len(ATTACK_SLOTS):
        raise ValueError("ATTACK_PLAN must match ATTACK_SLOTS")
    needs: Counter[str] = Counter()
    for scenario in ATTACK_PLAN:
        needs[str(scenario["source_key"])] += len(BASE_DATES)
    return needs


def _collect_candidates(
    *,
    source_path: Path,
    benign_needs: Counter[str],
    attack_needs: Counter[str],
    feature_order: list[str],
) -> tuple[dict[str, dict[str, list[SourceCandidate]]], int]:
    benign_primary: dict[str, list[SourceCandidate]] = defaultdict(list)
    benign_fallback: dict[str, list[SourceCandidate]] = defaultdict(list)
    attack_pools: dict[str, list[SourceCandidate]] = defaultdict(list)
    initial_benign_run = True
    scanned_rows = 0

    with source_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for source_index, row in enumerate(reader):
            scanned_rows = source_index + 1
            attack = row.get("Attack", "")
            dst_port = row.get("L4_DST_PORT", "")

            if attack == "Benign":
                _collect_benign_candidate(
                    row=row,
                    source_index=source_index,
                    dst_port=dst_port,
                    initial_benign_run=initial_benign_run,
                    benign_needs=benign_needs,
                    benign_primary=benign_primary,
                    benign_fallback=benign_fallback,
                    feature_order=feature_order,
                )
            else:
                initial_benign_run = False
                _collect_attack_candidate(
                    row=row,
                    source_index=source_index,
                    attack=attack,
                    dst_port=dst_port,
                    attack_needs=attack_needs,
                    attack_pools=attack_pools,
                    feature_order=feature_order,
                )

            if _candidate_requirements_met(
                benign_needs=benign_needs,
                attack_needs=attack_needs,
                benign_primary=benign_primary,
                benign_fallback=benign_fallback,
                attack_pools=attack_pools,
            ):
                break

    if not _candidate_requirements_met(
        benign_needs=benign_needs,
        attack_needs=attack_needs,
        benign_primary=benign_primary,
        benign_fallback=benign_fallback,
        attack_pools=attack_pools,
    ):
        missing = _missing_requirements(
            benign_needs,
            attack_needs,
            benign_primary,
            benign_fallback,
            attack_pools,
        )
        raise RuntimeError(f"source dataset did not satisfy candidate needs: {missing}")

    benign_pools = {
        port: [*benign_primary[port], *benign_fallback[port]]
        for port in benign_needs
    }
    return {
        "benign": benign_pools,
        "attacks": dict(attack_pools),
    }, scanned_rows


def _collect_benign_candidate(
    *,
    row: dict[str, str],
    source_index: int,
    dst_port: str,
    initial_benign_run: bool,
    benign_needs: Counter[str],
    benign_primary: dict[str, list[SourceCandidate]],
    benign_fallback: dict[str, list[SourceCandidate]],
    feature_order: list[str],
) -> None:
    if dst_port not in benign_needs:
        return
    target = benign_primary if initial_benign_run else benign_fallback
    total = len(benign_primary[dst_port]) + len(benign_fallback[dst_port])
    if total >= benign_needs[dst_port]:
        return
    if not _row_has_ml_features(row, feature_order):
        return
    stage = "initial_benign_run" if initial_benign_run else "benign_fallback"
    target[dst_port].append(SourceCandidate(dict(row), source_index, stage))


def _collect_attack_candidate(
    *,
    row: dict[str, str],
    source_index: int,
    attack: str,
    dst_port: str,
    attack_needs: Counter[str],
    attack_pools: dict[str, list[SourceCandidate]],
    feature_order: list[str],
) -> None:
    for source_key, (needed_attack, needed_port) in ATTACK_SOURCE_SPECS.items():
        if source_key not in attack_needs:
            continue
        if len(attack_pools[source_key]) >= attack_needs[source_key]:
            continue
        if attack != needed_attack or dst_port != needed_port:
            continue
        if not _row_has_ml_features(row, feature_order):
            continue
        attack_pools[source_key].append(
            SourceCandidate(dict(row), source_index, "attack_label_port_match")
        )


def _candidate_requirements_met(
    *,
    benign_needs: Counter[str],
    attack_needs: Counter[str],
    benign_primary: dict[str, list[SourceCandidate]],
    benign_fallback: dict[str, list[SourceCandidate]],
    attack_pools: dict[str, list[SourceCandidate]],
) -> bool:
    benign_ok = all(
        len(benign_primary[port]) + len(benign_fallback[port]) >= count
        for port, count in benign_needs.items()
    )
    attacks_ok = all(
        len(attack_pools[source_key]) >= count
        for source_key, count in attack_needs.items()
    )
    return benign_ok and attacks_ok


def _missing_requirements(
    benign_needs: Counter[str],
    attack_needs: Counter[str],
    benign_primary: dict[str, list[SourceCandidate]],
    benign_fallback: dict[str, list[SourceCandidate]],
    attack_pools: dict[str, list[SourceCandidate]],
) -> dict[str, dict[str, int]]:
    return {
        "benign": {
            port: count - len(benign_primary[port]) - len(benign_fallback[port])
            for port, count in benign_needs.items()
            if len(benign_primary[port]) + len(benign_fallback[port]) < count
        },
        "attacks": {
            source_key: count - len(attack_pools[source_key])
            for source_key, count in attack_needs.items()
            if len(attack_pools[source_key]) < count
        },
    }


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


def _build_rows(
    *,
    candidates: dict[str, dict[str, list[SourceCandidate]]],
    source_columns: list[str],
    feature_order: list[str],
) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    rows: list[dict[str, str]] = []
    trace: list[dict[str, Any]] = []
    benign_plans = [_build_benign_plan(day_index) for day_index in range(len(BASE_DATES))]

    for day_index, day_start in enumerate(BASE_DATES):
        attack_index = 0
        for slot in range(100):
            start = day_start + timedelta(minutes=10 + slot * 14)
            if slot in ATTACK_SLOTS:
                scenario = ATTACK_PLAN[attack_index]
                row, row_trace = _build_attack_row(
                    scenario=scenario,
                    candidate=_pop_candidate(
                        candidates["attacks"], str(scenario["source_key"])
                    ),
                    source_columns=source_columns,
                    feature_order=feature_order,
                    day_index=day_index,
                    slot=slot,
                    start=start,
                )
                attack_index += 1
            else:
                profile_key = benign_plans[day_index][slot]
                port = BENIGN_PROFILE_PORTS[profile_key]
                row, row_trace = _build_benign_row(
                    profile_key=profile_key,
                    candidate=_pop_candidate(candidates["benign"], port),
                    source_columns=source_columns,
                    feature_order=feature_order,
                    day_index=day_index,
                    slot=slot,
                    start=start,
                )
            rows.append(row)
            trace.append(row_trace)

        if attack_index != len(ATTACK_PLAN):
            raise RuntimeError(f"day {day_index + 1} generated {attack_index} attacks")

    rows.sort(key=lambda row: int(row["FLOW_START_MILLISECONDS"]))
    return rows, trace


def _build_benign_plan(day_index: int) -> dict[int, str]:
    remaining = Counter(BENIGN_DAILY_QUOTAS)
    plan: dict[int, str] = {}
    for slot in range(100):
        if slot in ATTACK_SLOTS:
            continue
        start = BASE_DATES[day_index] + timedelta(minutes=10 + slot * 14)
        chosen = _choose_profile_for_hour(start.hour, slot, remaining)
        plan[slot] = chosen
        remaining[chosen] -= 1
    if any(remaining.values()):
        raise RuntimeError(f"benign daily plan did not consume all quotas: {remaining}")
    return plan


def _choose_profile_for_hour(
    hour: int, slot: int, remaining: Counter[str]
) -> str:
    preferred = [key for key in _preferred_profiles(hour) if remaining[key] > 0]
    if preferred:
        return _choose_highest_remaining_ratio(preferred, slot + hour, remaining)
    fallback = [key for key, count in remaining.items() if count > 0]
    return _choose_highest_remaining_ratio(fallback, slot + hour, remaining)


def _choose_highest_remaining_ratio(
    keys: list[str], rotation: int, remaining: Counter[str]
) -> str:
    best_ratio = max(remaining[key] / BENIGN_DAILY_QUOTAS[key] for key in keys)
    top = [
        key
        for key in keys
        if abs((remaining[key] / BENIGN_DAILY_QUOTAS[key]) - best_ratio) < 1e-12
    ]
    return top[rotation % len(top)]


def _preferred_profiles(hour: int) -> list[str]:
    if 2 <= hour < 4:
        return [
            "nightly-backup",
            "backup-smb",
            "internal-dns",
            "time-sync",
            "cloud-update",
        ]
    if 8 <= hour < 12:
        return [
            "patient-portal-https",
            "patient-portal-http",
            "ehr-https",
            "ehr-api-8443",
            "app-db-mysql",
            "app-db-mssql",
            "internal-dns",
            "employee-vpn",
        ]
    if 12 <= hour < 17:
        return [
            "patient-portal-https",
            "staff-saas",
            "ehr-https",
            "patient-portal-http",
            "internal-dns",
            "app-db-mysql",
            "app-db-mssql",
        ]
    if 17 <= hour < 20:
        return [
            "employee-vpn",
            "staff-saas",
            "admin-rdp",
            "admin-ssh",
            "patient-portal-https",
            "internal-dns",
        ]
    if 20 <= hour or hour < 2:
        return [
            "admin-ssh",
            "admin-rdp",
            "internal-dns",
            "time-sync",
            "patient-portal-https",
            "cloud-update",
            "employee-vpn",
        ]
    return [
        "cloud-update",
        "internal-dns",
        "time-sync",
        "patient-portal-https",
        "staff-saas",
    ]


def _build_benign_row(
    *,
    profile_key: str,
    candidate: SourceCandidate,
    source_columns: list[str],
    feature_order: list[str],
    day_index: int,
    slot: int,
    start: datetime,
) -> tuple[dict[str, str], dict[str, Any]]:
    dst_port = str(candidate.row["L4_DST_PORT"])
    src_ip, dst_ip = _benign_endpoints(profile_key, day_index, slot, dst_port)
    flow_id = f"xgb-d{day_index + 1:02d}-benign-{profile_key}-{slot + 1:03d}"
    row = _materialize_row(
        flow_id=flow_id,
        candidate=candidate,
        source_columns=source_columns,
        feature_order=feature_order,
        start=start,
        src_ip=src_ip,
        src_port=_src_port(day_index, slot, dst_port),
        dst_ip=dst_ip,
        dst_port=None,
        protocol=None,
        label="Benign",
        attack="Benign",
    )
    return row, _trace_row(flow_id, profile_key, "Benign", candidate, row)


def _build_attack_row(
    *,
    scenario: dict[str, str],
    candidate: SourceCandidate,
    source_columns: list[str],
    feature_order: list[str],
    day_index: int,
    slot: int,
    start: datetime,
) -> tuple[dict[str, str], dict[str, Any]]:
    key = str(scenario["key"])
    flow_id = f"xgb-d{day_index + 1:02d}-attack-{key}-{slot + 1:03d}"
    row = _materialize_row(
        flow_id=flow_id,
        candidate=candidate,
        source_columns=source_columns,
        feature_order=feature_order,
        start=start,
        src_ip=_attack_source_ip(key, day_index),
        src_port=_src_port(day_index, slot, str(scenario["dst_port"])),
        dst_ip=str(scenario["dst_ip"]),
        dst_port=str(scenario["dst_port"]),
        protocol=str(scenario["protocol"]),
        label="Malicious",
        attack=str(candidate.row["Attack"]),
    )
    return row, _trace_row(flow_id, key, "Malicious", candidate, row)


def _materialize_row(
    *,
    flow_id: str,
    candidate: SourceCandidate,
    source_columns: list[str],
    feature_order: list[str],
    start: datetime,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: str | None,
    protocol: str | None,
    label: str,
    attack: str,
) -> dict[str, str]:
    output = {"flow_id": flow_id}
    output.update({column: candidate.row.get(column, "") for column in source_columns})

    start_ms = _epoch_ms(start)
    duration_ms = _source_duration_ms(candidate.row)
    output["FLOW_START_MILLISECONDS"] = str(start_ms)
    output["FLOW_END_MILLISECONDS"] = str(start_ms + duration_ms)
    output["IPV4_SRC_ADDR"] = src_ip
    output["L4_SRC_PORT"] = str(src_port)
    output["IPV4_DST_ADDR"] = dst_ip
    if dst_port is not None:
        output["L4_DST_PORT"] = dst_port
    if protocol is not None:
        output["PROTOCOL"] = protocol
    output["Label"] = label
    output["Attack"] = attack

    if "mock_prob" in output:
        raise ValueError("generated XGBoost scenario must not include mock_prob")
    if not _row_has_ml_features(output, feature_order):
        raise ValueError(f"generated row has invalid ML features: {flow_id}")
    return {key: str(value) for key, value in output.items()}


def _trace_row(
    flow_id: str,
    scenario: str,
    label: str,
    candidate: SourceCandidate,
    row: dict[str, str],
) -> dict[str, Any]:
    return {
        "flow_id": flow_id,
        "scenario": scenario,
        "label": label,
        "attack": row["Attack"],
        "source_index": candidate.source_index,
        "source_stage": candidate.source_stage,
        "source_attack": candidate.row.get("Attack"),
        "source_dst_port": candidate.row.get("L4_DST_PORT"),
        "output_dst_port": row.get("L4_DST_PORT"),
        "source_protocol": candidate.row.get("PROTOCOL"),
        "output_protocol": row.get("PROTOCOL"),
    }


def _pop_candidate(
    pools: dict[str, list[SourceCandidate]], key: str
) -> SourceCandidate:
    if not pools.get(key):
        raise RuntimeError(f"candidate pool exhausted: {key}")
    return pools[key].pop(0)


def _benign_endpoints(
    profile_key: str, day_index: int, slot: int, dst_port: str
) -> tuple[str, str]:
    if profile_key in {"patient-portal-https", "patient-portal-http"}:
        return _external_patient_ip(day_index, slot), "203.0.113.10"
    if profile_key == "employee-vpn":
        return _staff_remote_ip(day_index, slot), "203.0.113.20"
    if profile_key in {"ehr-https", "ehr-api-8443"}:
        return _workstation_ip(day_index, slot), "10.42.20.15"
    if profile_key in {"app-db-mysql", "app-db-mssql"}:
        return "10.42.20.15", "10.42.30.25"
    if profile_key == "staff-saas":
        return _workstation_ip(day_index, slot + 5), "198.51.100.150"
    if profile_key == "cloud-update":
        return "10.42.20.15", "52.95.110.5"
    if profile_key == "internal-dns":
        return _workstation_ip(day_index, slot), "10.42.60.5"
    if profile_key == "backup-smb":
        return "10.42.20.15", "10.42.40.12"
    if profile_key == "nightly-backup":
        return "10.42.40.10", "10.42.40.12"
    if profile_key == "admin-rdp":
        return "10.42.50.9", "10.42.50.8"
    if profile_key == "admin-ssh":
        return "10.42.50.9", "10.42.50.8" if dst_port == "22" else "10.42.40.12"
    if profile_key == "time-sync":
        return _workstation_ip(day_index, slot + 9), "129.6.15.28"
    raise ValueError(f"unknown benign profile: {profile_key}")


def _attack_source_ip(scenario_key: str, day_index: int) -> str:
    if scenario_key == "vpn-web-probe":
        return "198.51.100.77"
    if scenario_key == "portal-sql-injection":
        return "198.51.100.88"
    if scenario_key == "admin-ssh-bruteforce":
        return f"192.0.2.{70 + day_index}"
    if scenario_key == "backup-smb-tamper":
        return "10.42.100.45"
    if scenario_key == "dns-tunnel-burst":
        return "10.42.100.46"
    if scenario_key == "metadata-service-access":
        return "10.42.20.15"
    if scenario_key == "portal-ddos-burst":
        return f"198.51.100.{180 + day_index}"
    if scenario_key == "backup-exfil-https":
        return "10.42.40.12"
    if scenario_key == "external-postgres-probe":
        return "198.51.100.90"
    if scenario_key == "vpn-followup-infiltration":
        return "198.51.100.77"
    raise ValueError(f"unknown attack scenario: {scenario_key}")


def _src_port(day_index: int, slot: int, dst_port: str) -> int:
    if dst_port == "53":
        return 53000 + day_index * 300 + slot
    if dst_port == "123":
        return 12300 + day_index * 300 + slot
    return 49152 + day_index * 1200 + slot * 11


def _external_patient_ip(day_index: int, slot: int) -> str:
    return f"198.51.100.{20 + ((slot + day_index * 7) % 45)}"


def _staff_remote_ip(day_index: int, slot: int) -> str:
    return f"192.0.2.{20 + ((slot + day_index * 11) % 60)}"


def _workstation_ip(day_index: int, slot: int) -> str:
    return f"10.42.100.{20 + ((slot + day_index * 13) % 50)}"


def _source_duration_ms(row: dict[str, str]) -> int:
    try:
        return max(0, int(float(row.get("FLOW_DURATION_MILLISECONDS", "0"))))
    except ValueError:
        return 0


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
    feature_order: list[str],
) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    label_counts = Counter(row["Label"] for row in rows)
    attack_counts = Counter(row["Attack"] for row in rows)
    scenario_counts = Counter(item["scenario"] for item in trace)
    projection_overrides = [
        item
        for item in trace
        if item["source_dst_port"] != item["output_dst_port"]
        or item["source_protocol"] != item["output_protocol"]
    ]
    manifest = {
        "dataset": str(output_path.as_posix()),
        "source_dataset": str(source_path.as_posix()),
        "generator": "scripts/generate_clinic_telehealth_xgb_flows.py",
        "row_count": len(rows),
        "scanned_source_rows": scanned_rows,
        "date_range_kst": [
            BASE_DATES[0].date().isoformat(),
            BASE_DATES[-1].date().isoformat(),
        ],
        "schema": {
            "mock_prob_present": False,
            "ml_feature_count": len(feature_order),
            "ml_feature_order": feature_order,
            "output_column_count": len(rows[0]) if rows else 0,
        },
        "sampling_policy": {
            "benign": (
                "Benign rows are sampled from source-order NF-CICIDS2018-v3 "
                "traffic, preferring the initial contiguous benign run and "
                "matching the destination service port used in the clinic flow."
            ),
            "attacks": (
                "Attack rows keep real NF-CICIDS2018-v3 attack feature vectors "
                "selected by Attack label and destination port, then project IP, "
                "time, and source-port fields into the clinic scenario."
            ),
            "port_projection_exceptions": (
                "Only organization-specific attack simulations that require a "
                "clinic service absent from the source attack port distribution "
                "override L4_DST_PORT; every override is listed below."
            ),
        },
        "label_counts": dict(label_counts),
        "attack_counts": dict(attack_counts),
        "scenario_counts": dict(scenario_counts),
        "projection_overrides": projection_overrides,
        "source_trace": trace,
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    raise SystemExit(main())
