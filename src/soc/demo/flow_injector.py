from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
from pathlib import Path
import threading
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen

from soc.io import read_flows_csv
from soc.models import Flow


Sender = Callable[[str, dict[str, Any], float], dict[str, Any]]


SCENARIO_CSVS = {
    "sample": Path("data/sample/flows.csv"),
    "clinic": Path("data/sample/clinic_telehealth_flows_xgb.csv"),
    "clinic_telehealth": Path("data/sample/clinic_telehealth_flows_xgb.csv"),
    "regional": Path("data/sample/regional_care_dynamic_cve_flows_xgb.csv"),
    "regional_care_dynamic_cve": Path("data/sample/regional_care_dynamic_cve_flows_xgb.csv"),
}


@dataclass(frozen=True)
class InjectedFlow:
    flow_id: str
    status: str
    response: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass(frozen=True)
class InjectionSummary:
    source_path: str
    target_url: str
    dry_run: bool
    attempted: int
    succeeded: int
    failed: int
    flows: list[InjectedFlow]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inject scenario flow CSV rows into the product API one row at a time."
    )
    parser.add_argument(
        "--target",
        default="http://127.0.0.1:8080/api/flows",
        help="Product API flow endpoint or API base URL.",
    )
    parser.add_argument("--input", type=Path, help="Explicit flow CSV path.")
    parser.add_argument(
        "--scenario",
        choices=sorted(SCENARIO_CSVS),
        default="regional_care_dynamic_cve",
        help="Built-in demo scenario to use when --input is omitted.",
    )
    parser.add_argument(
        "--day",
        help="Optional day filter such as 1, 01, d01, or day01. Matches flow_id tokens.",
    )
    parser.add_argument("--limit", type=int, default=0, help="Maximum rows to send. 0 sends all.")
    parser.add_argument(
        "--interval",
        type=float,
        default=0.25,
        help="Seconds to wait between rows.",
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout in seconds.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Read and filter rows without calling the API.",
    )
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Keep sending rows after a failed API call.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        summary = inject_from_args(args)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}")
        return 2

    for item in summary.flows:
        if item.status == "ok":
            print(f"ok {item.flow_id}")
        elif item.status == "dry-run":
            print(f"dry-run {item.flow_id}")
        else:
            print(f"failed {item.flow_id}: {item.error}")

    print(
        "summary: "
        f"attempted={summary.attempted} succeeded={summary.succeeded} "
        f"failed={summary.failed} source={summary.source_path} target={summary.target_url}"
    )
    return 1 if summary.failed else 0


def inject_from_args(args: argparse.Namespace, sender: Sender | None = None) -> InjectionSummary:
    source_path = resolve_source_csv(args.input, args.scenario)
    flows = filter_flows_by_day(read_flows_csv(source_path), args.day)
    if args.limit and args.limit > 0:
        flows = flows[: args.limit]
    return inject_flows(
        flows=flows,
        source_path=source_path,
        target_url=normalize_flow_endpoint(args.target),
        interval_seconds=max(args.interval, 0.0),
        timeout_seconds=args.timeout,
        dry_run=args.dry_run,
        continue_on_error=args.continue_on_error,
        sender=sender or post_json,
    )


def resolve_source_csv(input_path: Path | None, scenario: str) -> Path:
    path = input_path or SCENARIO_CSVS[scenario]
    if not path.exists():
        raise FileNotFoundError(f"flow CSV not found: {path}")
    return path


def filter_flows_by_day(flows: list[Flow], day: str | None) -> list[Flow]:
    if not day:
        return flows
    token = _day_token(day)
    filtered = [flow for flow in flows if token in flow.flow_id.lower()]
    if not filtered:
        raise ValueError(f"no flows matched day filter {day!r} ({token})")
    return filtered


def normalize_flow_endpoint(target: str) -> str:
    parsed = urlparse(target)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"target must be an absolute HTTP URL: {target}")
    path = parsed.path.rstrip("/")
    if path in ("", "/"):
        path = "/api/flows"
    elif path.endswith("/api"):
        path = f"{path}/flows"
    elif not path.endswith("/api/flows"):
        path = f"{path}/api/flows"
    return urlunparse(parsed._replace(path=path, params="", query="", fragment=""))


def inject_flows(
    *,
    flows: list[Flow],
    source_path: Path,
    target_url: str,
    interval_seconds: float,
    timeout_seconds: float,
    dry_run: bool,
    continue_on_error: bool,
    sender: Sender,
    cancel_event: threading.Event | None = None,
    on_progress: Callable[[InjectedFlow], None] | None = None,
) -> InjectionSummary:
    results: list[InjectedFlow] = []
    for index, flow in enumerate(flows):
        if cancel_event is not None and cancel_event.is_set():
            break
        if dry_run:
            flow_item = InjectedFlow(flow_id=flow.flow_id, status="dry-run")
            results.append(flow_item)
            if on_progress is not None:
                on_progress(flow_item)
        else:
            try:
                response = sender(target_url, flow_to_payload(flow), timeout_seconds)
                flow_item = InjectedFlow(flow_id=flow.flow_id, status="ok", response=response)
                results.append(flow_item)
                if on_progress is not None:
                    on_progress(flow_item)
            except Exception as exc:
                flow_item = InjectedFlow(
                    flow_id=flow.flow_id,
                    status="failed",
                    error=f"{type(exc).__name__}: {exc}",
                )
                results.append(flow_item)
                if on_progress is not None:
                    on_progress(flow_item)
                if not continue_on_error:
                    break
        if interval_seconds > 0 and index < len(flows) - 1:
            if cancel_event is not None:
                cancel_event.wait(interval_seconds)
                if cancel_event.is_set():
                    break
            else:
                time.sleep(interval_seconds)

    succeeded = sum(1 for item in results if item.status in {"ok", "dry-run"})
    failed = sum(1 for item in results if item.status == "failed")
    return InjectionSummary(
        source_path=str(source_path),
        target_url=target_url,
        dry_run=dry_run,
        attempted=len(results),
        succeeded=succeeded,
        failed=failed,
        flows=results,
    )



def flow_to_payload(flow: Flow) -> dict[str, Any]:
    return {
        "flow_id": flow.flow_id,
        "start_ms": flow.start_ms,
        "end_ms": flow.end_ms,
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "features": dict(flow.features),
        "raw_label": flow.raw_label,
        "raw_attack": flow.raw_attack,
    }


def post_json(target_url: str, payload: dict[str, Any], timeout_seconds: float) -> dict[str, Any]:
    encoded = json.dumps(payload).encode("utf-8")
    request = Request(
        target_url,
        data=encoded,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            body = response.read().decode("utf-8")
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {body}") from exc
    except URLError as exc:
        raise RuntimeError(str(exc.reason)) from exc
    data = json.loads(body) if body else {}
    if not isinstance(data, dict):
        raise RuntimeError("API response JSON must be an object")
    return data


def _day_token(day: str) -> str:
    digits = "".join(ch for ch in day if ch.isdigit())
    if not digits:
        raise ValueError(f"day must contain a number: {day}")
    return f"d{int(digits):02d}"


if __name__ == "__main__":
    raise SystemExit(main())

