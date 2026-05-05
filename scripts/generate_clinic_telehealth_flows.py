from __future__ import annotations

import argparse
import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path


COLUMNS = [
    "flow_id",
    "FLOW_START_MILLISECONDS",
    "FLOW_END_MILLISECONDS",
    "IPV4_SRC_ADDR",
    "L4_SRC_PORT",
    "IPV4_DST_ADDR",
    "L4_DST_PORT",
    "PROTOCOL",
    "mock_prob",
    "Label",
    "Attack",
]

KST = timezone(timedelta(hours=9))
BASE_DATES = [
    datetime(2026, 5, 2, tzinfo=KST),
    datetime(2026, 5, 3, tzinfo=KST),
    datetime(2026, 5, 4, tzinfo=KST),
]
ATTACK_SLOTS = {9, 18, 27, 36, 45, 54, 63, 72, 81, 90}


def main() -> int:
    args = _parse_args()
    rows = build_rows()
    output = args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote={len(rows)} output={output}")
    return 0


def _parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Generate the clinic telehealth prompt-evaluation flow sample."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=repo_root / "data" / "sample" / "clinic_telehealth_flows.csv",
    )
    return parser.parse_args()


def build_rows() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for day_index, day_start in enumerate(BASE_DATES):
        attack_index = 0
        for slot in range(100):
            start = day_start + timedelta(minutes=10 + slot * 14)
            if slot in ATTACK_SLOTS:
                rows.append(_attack_row(day_index, slot, attack_index, start))
                attack_index += 1
            else:
                rows.append(_benign_row(day_index, slot, start))
        if attack_index != 10:
            raise RuntimeError(f"day {day_index + 1} generated {attack_index} attacks")
    return rows


def _benign_row(day_index: int, slot: int, start: datetime) -> dict[str, str]:
    local_hour = start.astimezone(KST).hour
    variant = (slot + day_index * 3) % 11
    prob = 0.04 + (((slot + day_index) % 8) * 0.025)
    src_port = _src_port(day_index, slot)

    if 2 <= local_hour < 4 and slot % 4 == 0:
        return _row(
            day_index,
            slot,
            "benign-nightly-backup",
            start,
            duration_ms=4800,
            src_ip="10.42.40.10",
            src_port=src_port,
            dst_ip="10.42.40.12",
            dst_port=445,
            protocol=6,
            mock_prob=0.180,
            label="Benign",
            attack="",
        )

    if variant == 0:
        return _row(
            day_index,
            slot,
            "benign-patient-portal-https",
            start,
            duration_ms=700,
            src_ip=_external_patient_ip(day_index, slot),
            src_port=src_port,
            dst_ip="203.0.113.10",
            dst_port=443,
            protocol=6,
            mock_prob=prob,
            label="Benign",
            attack="",
        )
    if variant == 1:
        return _row(
            day_index,
            slot,
            "benign-patient-portal-http",
            start,
            duration_ms=520,
            src_ip=_external_patient_ip(day_index, slot + 17),
            src_port=src_port,
            dst_ip="203.0.113.10",
            dst_port=80,
            protocol=6,
            mock_prob=prob + 0.015,
            label="Benign",
            attack="",
        )
    if variant == 2:
        return _row(
            day_index,
            slot,
            "benign-office-ehr-api",
            start,
            duration_ms=650,
            src_ip=_workstation_ip(day_index, slot),
            src_port=src_port,
            dst_ip="10.42.20.15",
            dst_port=8443,
            protocol=6,
            mock_prob=prob + 0.040,
            label="Benign",
            attack="",
        )
    if variant == 3:
        return _row(
            day_index,
            slot,
            "benign-app-db-query",
            start,
            duration_ms=760,
            src_ip="10.42.20.15",
            src_port=src_port,
            dst_ip="10.42.30.25",
            dst_port=5432,
            protocol=6,
            mock_prob=prob + 0.060,
            label="Benign",
            attack="",
        )
    if variant == 4:
        return _row(
            day_index,
            slot,
            "benign-admin-jumpbox-ssh",
            start,
            duration_ms=900,
            src_ip="10.42.50.9",
            src_port=src_port,
            dst_ip="10.42.50.8",
            dst_port=22,
            protocol=6,
            mock_prob=prob + 0.050,
            label="Benign",
            attack="",
        )
    if variant == 5:
        return _row(
            day_index,
            slot,
            "benign-employee-vpn",
            start,
            duration_ms=820,
            src_ip=_staff_remote_ip(day_index, slot),
            src_port=src_port,
            dst_ip="203.0.113.20",
            dst_port=443,
            protocol=6,
            mock_prob=min(prob + 0.080, 0.285),
            label="Benign",
            attack="",
        )
    if variant == 6:
        return _row(
            day_index,
            slot,
            "benign-internal-dns",
            start,
            duration_ms=90,
            src_ip=_workstation_ip(day_index, slot),
            src_port=53000 + slot,
            dst_ip="10.42.60.5",
            dst_port=53,
            protocol=17,
            mock_prob=0.035 + ((slot % 3) * 0.015),
            label="Benign",
            attack="",
        )
    if variant == 7:
        return _row(
            day_index,
            slot,
            "benign-cloud-update",
            start,
            duration_ms=1300,
            src_ip="10.42.20.15",
            src_port=src_port,
            dst_ip="52.95.110.5",
            dst_port=443,
            protocol=6,
            mock_prob=prob + 0.030,
            label="Benign",
            attack="",
        )
    if variant == 8:
        return _row(
            day_index,
            slot,
            "benign-staff-saas",
            start,
            duration_ms=1500,
            src_ip=_workstation_ip(day_index, slot + 5),
            src_port=src_port,
            dst_ip="198.51.100.150",
            dst_port=443,
            protocol=6,
            mock_prob=prob + 0.010,
            label="Benign",
            attack="",
        )
    if variant == 9:
        return _row(
            day_index,
            slot,
            "benign-time-sync",
            start,
            duration_ms=80,
            src_ip=_workstation_ip(day_index, slot + 9),
            src_port=12300 + slot,
            dst_ip="129.6.15.28",
            dst_port=123,
            protocol=17,
            mock_prob=0.030,
            label="Benign",
            attack="",
        )
    return _row(
        day_index,
        slot,
        "benign-monitoring-portal",
        start,
        duration_ms=430,
        src_ip="10.42.50.9",
        src_port=src_port,
        dst_ip="203.0.113.10",
        dst_port=443,
        protocol=6,
        mock_prob=prob + 0.020,
        label="Benign",
        attack="",
    )


def _attack_row(
    day_index: int,
    slot: int,
    attack_index: int,
    start: datetime,
) -> dict[str, str]:
    src_port = _src_port(day_index, slot)
    patterns = [
        {
            "name": "attack-ml-vpn-bruteforce",
            "src_ip": "198.51.100.77",
            "dst_ip": "203.0.113.20",
            "dst_port": 443,
            "protocol": 6,
            "prob": 0.965,
            "attack": "SSH-Bruteforce",
            "duration_ms": 180,
        },
        {
            "name": "attack-context-vpn-spray",
            "src_ip": "192.0.2.44",
            "dst_ip": "203.0.113.20",
            "dst_port": 443,
            "protocol": 6,
            "prob": 0.360,
            "attack": "SSH-Bruteforce",
            "duration_ms": 220,
        },
        {
            "name": "attack-ml-external-db-probe",
            "src_ip": "198.51.100.90",
            "dst_ip": "10.42.30.25",
            "dst_port": 5432,
            "protocol": 6,
            "prob": 0.985,
            "attack": "SQL_Injection",
            "duration_ms": 120,
        },
        {
            "name": "attack-context-portal-cve-probe",
            "src_ip": "192.0.2.210",
            "dst_ip": "203.0.113.10",
            "dst_port": 80 if day_index % 2 == 0 else 443,
            "protocol": 6,
            "prob": 0.440,
            "attack": "Brute_Force_-Web",
            "duration_ms": 260,
        },
        {
            "name": "attack-ml-imds-ehr-api",
            "src_ip": "10.42.20.15",
            "dst_ip": "169.254.169.254",
            "dst_port": 80,
            "protocol": 6,
            "prob": 0.990,
            "attack": "Infilteration",
            "duration_ms": 70,
        },
        {
            "name": "attack-context-workstation-backup-smb",
            "src_ip": "10.42.100.45",
            "dst_ip": "10.42.40.12",
            "dst_port": 445,
            "protocol": 6,
            "prob": 0.420,
            "attack": "Bot",
            "duration_ms": 640,
        },
        {
            "name": "attack-ml-dns-tunnel-burst",
            "src_ip": "10.42.100.46",
            "dst_ip": "8.8.8.8",
            "dst_port": 53,
            "protocol": 17,
            "prob": 0.972,
            "attack": "Bot",
            "duration_ms": 5200,
        },
        {
            "name": "attack-context-dmz-to-db-unusual",
            "src_ip": "203.0.113.10",
            "dst_ip": "10.42.30.25",
            "dst_port": 5432,
            "protocol": 6,
            "prob": 0.520,
            "attack": "SQL_Injection",
            "duration_ms": 880,
        },
        {
            "name": "attack-ml-backup-exfil",
            "src_ip": "10.42.40.12",
            "dst_ip": "198.51.100.123",
            "dst_port": 443,
            "protocol": 6,
            "prob": 0.981,
            "attack": "Infilteration",
            "duration_ms": 8200,
        },
        {
            "name": "attack-context-jumpbox-ssh-probe",
            "src_ip": "10.42.100.45",
            "dst_ip": "10.42.50.8",
            "dst_port": 22,
            "protocol": 6,
            "prob": 0.490,
            "attack": "SSH-Bruteforce",
            "duration_ms": 240,
        },
    ]
    pattern = patterns[attack_index]
    return _row(
        day_index,
        slot,
        pattern["name"],
        start,
        duration_ms=int(pattern["duration_ms"]),
        src_ip=str(pattern["src_ip"]),
        src_port=src_port,
        dst_ip=str(pattern["dst_ip"]),
        dst_port=int(pattern["dst_port"]),
        protocol=int(pattern["protocol"]),
        mock_prob=float(pattern["prob"]) + day_index * 0.003,
        label="Malicious",
        attack=str(pattern["attack"]),
    )


def _row(
    day_index: int,
    slot: int,
    name: str,
    start: datetime,
    *,
    duration_ms: int,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    protocol: int,
    mock_prob: float,
    label: str,
    attack: str,
) -> dict[str, str]:
    start_ms = _epoch_ms(start)
    return {
        "flow_id": f"d{day_index + 1:02d}-{name}-{slot + 1:03d}",
        "FLOW_START_MILLISECONDS": str(start_ms),
        "FLOW_END_MILLISECONDS": str(start_ms + duration_ms),
        "IPV4_SRC_ADDR": src_ip,
        "L4_SRC_PORT": str(src_port),
        "IPV4_DST_ADDR": dst_ip,
        "L4_DST_PORT": str(dst_port),
        "PROTOCOL": str(protocol),
        "mock_prob": f"{mock_prob:.3f}",
        "Label": label,
        "Attack": attack,
    }


def _epoch_ms(value: datetime) -> int:
    return int(value.timestamp() * 1000)


def _src_port(day_index: int, slot: int) -> int:
    return 49152 + day_index * 1200 + slot * 11


def _external_patient_ip(day_index: int, slot: int) -> str:
    return f"198.51.100.{20 + ((slot + day_index * 7) % 45)}"


def _staff_remote_ip(day_index: int, slot: int) -> str:
    return f"192.0.2.{20 + ((slot + day_index * 11) % 60)}"


def _workstation_ip(day_index: int, slot: int) -> str:
    return f"10.42.100.{20 + ((slot + day_index * 13) % 50)}"


if __name__ == "__main__":
    raise SystemExit(main())
