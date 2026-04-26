from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from soc.models import Flow


CORE_COLUMNS = {
    "flow_id",
    "FLOW_START_MILLISECONDS",
    "FLOW_END_MILLISECONDS",
    "IPV4_SRC_ADDR",
    "IPV4_DST_ADDR",
    "L4_SRC_PORT",
    "L4_DST_PORT",
    "PROTOCOL",
    "Label",
    "Attack",
}


def _to_int(value: Any, default: int = 0) -> int:
    if value in (None, ""):
        return default
    return int(float(value))


def _to_optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    return int(float(value))


def read_flows_csv(path: str | Path) -> list[Flow]:
    flows: list[Flow] = []
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for index, row in enumerate(reader, start=1):
            features = {k: v for k, v in row.items() if k not in CORE_COLUMNS}
            flows.append(
                Flow(
                    flow_id=row.get("flow_id") or f"flow-{index}",
                    start_ms=_to_optional_int(row.get("FLOW_START_MILLISECONDS")),
                    end_ms=_to_optional_int(row.get("FLOW_END_MILLISECONDS")),
                    src_ip=row.get("IPV4_SRC_ADDR", ""),
                    dst_ip=row.get("IPV4_DST_ADDR", ""),
                    src_port=_to_int(row.get("L4_SRC_PORT")),
                    dst_port=_to_int(row.get("L4_DST_PORT")),
                    protocol=str(row.get("PROTOCOL", "")),
                    features=features,
                    raw_label=row.get("Label") or None,
                    raw_attack=row.get("Attack") or None,
                )
            )
    return flows
