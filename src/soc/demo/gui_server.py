"""Demo GUI server – standalone test/presentation controller.

Runs on a separate port (default 8081) and communicates with the Product API
(default http://127.0.0.1:8080) to copy scenario source inputs and inject flows.

This module intentionally uses only the Python stdlib so it adds zero
dependencies to the project.
"""
from __future__ import annotations

import argparse
import json
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from soc.demo.flow_injector import (
    SCENARIO_CSVS,
    InjectionSummary,
    filter_flows_by_day,
    inject_flows,
    normalize_flow_endpoint,
    post_json,
)
from soc.io import read_flows_csv

SOURCE_INPUT_NAMES = ("organization", "assets", "policy", "cve_feed", "threat_feed")
SCENARIO_SOURCE_DIRS = {
    "sample": Path("config"),
    "clinic": Path("config/scenarios/clinic_telehealth"),
    "clinic_telehealth": Path("config/scenarios/clinic_telehealth"),
    "regional": Path("config/scenarios/regional_care_dynamic_cve/base"),
    "regional_care_dynamic_cve": Path("config/scenarios/regional_care_dynamic_cve/base"),
}
REGIONAL_GENERATED_DIR = Path("config/scenarios/regional_care_dynamic_cve/generated")

# ---------------------------------------------------------------------------
# Injection runner – manages a background thread
# ---------------------------------------------------------------------------

_STATIC_DIR = Path(__file__).resolve().parent / "demo_static"

class InjectionRunner:
    """Manages a single background injection thread."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self._thread: threading.Thread | None = None
        self._total: int = 0
        self._attempted: int = 0
        self._succeeded: int = 0
        self._failed: int = 0
        self._summary: InjectionSummary | None = None
        self._error: str | None = None
        self._running: bool = False

    @property
    def is_running(self) -> bool:
        return self._running

    def start(
        self,
        *,
        target_url: str,
        scenario: str,
        input_path: str | None,
        day: str | None,
        limit: int,
        interval: float,
        timeout: float,
        continue_on_error: bool,
        dry_run: bool,
    ) -> dict[str, Any]:
        with self._lock:
            if self._running:
                return {"error": "injection already running"}

            self._cancel.clear()
            self._summary = None
            self._error = None
            self._attempted = 0
            self._succeeded = 0
            self._failed = 0
            self._running = True

        def _on_progress(item: Any) -> None:
            with self._lock:
                self._attempted += 1
                if item.status in ("ok", "dry-run"):
                    self._succeeded += 1
                else:
                    self._failed += 1

        def _run() -> None:
            try:
                csv_path = Path(input_path) if input_path else SCENARIO_CSVS.get(scenario)
                if csv_path is None:
                    raise ValueError(f"unknown scenario: {scenario}")
                if not csv_path.exists():
                    raise FileNotFoundError(f"CSV not found: {csv_path}")
                flows = filter_flows_by_day(read_flows_csv(csv_path), day)
                if limit and limit > 0:
                    flows = flows[:limit]
                self._total = len(flows)
                url = normalize_flow_endpoint(target_url)
                summary = inject_flows(
                    flows=flows,
                    source_path=csv_path,
                    target_url=url,
                    interval_seconds=max(interval, 0.0),
                    timeout_seconds=timeout,
                    dry_run=dry_run,
                    continue_on_error=continue_on_error,
                    sender=post_json,
                    cancel_event=self._cancel,
                    on_progress=_on_progress,
                )
                self._summary = summary
            except Exception as exc:
                self._error = f"{type(exc).__name__}: {exc}"
            finally:
                self._running = False

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        self._thread = thread
        return {"started": True, "total_flows": 0}

    def stop(self) -> dict[str, Any]:
        if not self._running:
            return {"stopped": False, "reason": "not running"}
        self._cancel.set()
        return {"stopped": True}

    def status(self) -> dict[str, Any]:
        with self._lock:
            result: dict[str, Any] = {
                "running": self._running,
                "total": self._total,
                "attempted": self._attempted,
                "succeeded": self._succeeded,
                "failed": self._failed,
            }
            if self._summary is not None:
                result["summary"] = {
                    "source_path": self._summary.source_path,
                    "target_url": self._summary.target_url,
                    "dry_run": self._summary.dry_run,
                    "attempted": self._summary.attempted,
                    "succeeded": self._summary.succeeded,
                    "failed": self._summary.failed,
                }
            if self._error is not None:
                result["error"] = self._error
            return result


# ---------------------------------------------------------------------------
# Product API proxy helpers
# ---------------------------------------------------------------------------


def _proxy_get(product_url: str, path: str, timeout: float = 10.0) -> dict[str, Any]:
    """GET from a product API endpoint and return the parsed response."""
    parsed = urlparse(product_url)
    url = f"{parsed.scheme}://{parsed.netloc}{path}"
    req = Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return {"error": f"HTTP {exc.code}: {body}"}
    except URLError as exc:
        return {"error": str(exc.reason)}
    try:
        return json.loads(body) if body else {}
    except json.JSONDecodeError:
        return {"raw": body}


def _proxy_post(product_url: str, path: str, payload: dict[str, Any], timeout: float = 10.0) -> dict[str, Any]:
    """POST JSON to a product API endpoint and return the parsed response."""
    parsed = urlparse(product_url)
    url = f"{parsed.scheme}://{parsed.netloc}{path}"
    encoded = json.dumps(payload).encode("utf-8")
    req = Request(
        url,
        data=encoded,
        headers={"Content-Type": "application/json; charset=utf-8", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return {"error": f"HTTP {exc.code}: {body}"}
    except URLError as exc:
        return {"error": str(exc.reason)}
    try:
        return json.loads(body) if body else {}
    except json.JSONDecodeError:
        return {"raw": body}


def _scenario_source_paths(scenario: str, day: str | None = None) -> dict[str, str]:
    if scenario == "sample":
        return {
            name: str(Path("config") / f"{name}.example.yaml")
            for name in SOURCE_INPUT_NAMES
        }
    source_dir = _scenario_source_dir(scenario, day)
    paths: dict[str, str] = {}
    for name in SOURCE_INPUT_NAMES:
        path = source_dir / f"{name}.yaml"
        if not path.exists():
            raise FileNotFoundError(f"scenario source file not found: {path}")
        paths[name] = str(path)
    return paths


def _scenario_source_dir(scenario: str, day: str | None = None) -> Path:
    if scenario in {"regional", "regional_care_dynamic_cve"} and day:
        generated = REGIONAL_GENERATED_DIR / _day_dir_name(day)
        if generated.exists():
            return generated
    try:
        return SCENARIO_SOURCE_DIRS[scenario]
    except KeyError as exc:
        raise ValueError(f"unknown scenario: {scenario}") from exc


def _day_dir_name(day: str) -> str:
    digits = "".join(ch for ch in str(day).lower() if ch.isdigit())
    if not digits:
        raise ValueError(f"invalid day filter: {day}")
    return f"day{int(digits):02d}"


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}


def _handler_for(runner: InjectionRunner, product_url: str):
    """Return a handler class bound to the runner and product URL."""

    class DemoHandler(BaseHTTPRequestHandler):
        def do_OPTIONS(self) -> None:
            self._cors(204)
            self.end_headers()

        def do_GET(self) -> None:
            path = self.path.split("?")[0].rstrip("/") or "/"

            if path == "/api/demo/status":
                status_data = runner.status()
                status_data["product_url"] = product_url
                return self._json_response(200, status_data)

            if path == "/api/demo/scenarios":
                return self._json_response(200, {
                    "scenarios": sorted(SCENARIO_CSVS.keys()),
                })

            if path == "/api/demo/product-status":
                data = _proxy_get(product_url, "/api/status")
                return self._json_response(200, data)

            # Static file serving
            self._serve_static(path)

        def do_POST(self) -> None:
            path = self.path.split("?")[0].rstrip("/") or "/"
            body = self._read_body()

            if path == "/api/demo/start":
                result = runner.start(
                    target_url=body.get("target_url", product_url),
                    scenario=body.get("scenario", "regional_care_dynamic_cve"),
                    input_path=body.get("input_path"),
                    day=body.get("day"),
                    limit=int(body.get("limit", 0)),
                    interval=float(body.get("interval", 0.25)),
                    timeout=float(body.get("timeout", 30.0)),
                    continue_on_error=bool(body.get("continue_on_error", True)),
                    dry_run=bool(body.get("dry_run", False)),
                )
                return self._json_response(200, result)

            if path == "/api/demo/stop":
                return self._json_response(200, runner.stop())

            if path == "/api/demo/reset-db":
                if runner.is_running:
                    return self._json_response(409, {"error": "stop injection before resetting the DB"})
                data = _proxy_post(product_url, "/api/admin/reset", {}, timeout=30.0)
                return self._json_response(200, data)

            if path == "/api/demo/reset-all":
                if runner.is_running:
                    return self._json_response(409, {"error": "stop injection before resetting all artifacts"})
                data = _proxy_post(product_url, "/api/admin/reset-all", {}, timeout=30.0)
                return self._json_response(200, data)

            if path == "/api/demo/apply-scenario-inputs":
                scenario = str(body.get("scenario") or "regional_care_dynamic_cve")
                try:
                    sources = _scenario_source_paths(scenario, body.get("day"))
                except (FileNotFoundError, ValueError) as exc:
                    return self._json_response(400, {"error": str(exc)})
                data = _proxy_post(
                    product_url,
                    "/api/admin/source-inputs",
                    {
                        "scenario": scenario,
                        "day": body.get("day"),
                        "sources": sources,
                    },
                    timeout=30.0,
                )
                return self._json_response(200, data)

            self._json_response(404, {"error": f"unknown: POST {path}"})

        # -- helpers --

        def _read_body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", 0))
            if length == 0:
                return {}
            raw = self.rfile.read(length).decode("utf-8")
            try:
                data = json.loads(raw)
                return data if isinstance(data, dict) else {}
            except json.JSONDecodeError:
                return {}

        def _json_response(self, status: int, body: dict[str, Any]) -> None:
            encoded = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self._cors(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _cors(self, status: int) -> None:
            self.send_response(status)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")

        def _serve_static(self, path: str) -> None:
            if path == "/":
                path = "/index.html"
            file_path = (_STATIC_DIR / path.lstrip("/")).resolve()
            try:
                file_path.relative_to(_STATIC_DIR.resolve())
            except ValueError:
                self._json_response(403, {"error": "forbidden"})
                return
            if not file_path.is_file():
                self._json_response(404, {"error": f"not found: {path}"})
                return
            content_type = _CONTENT_TYPES.get(file_path.suffix, "application/octet-stream")
            data = file_path.read_bytes()
            self._cors(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format: str, *args: Any) -> None:
            pass  # suppress default stderr logging

    return DemoHandler


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Demo Injector GUI server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument(
        "--product-url",
        default="http://127.0.0.1:8080",
        help="Base URL of the running Product API server.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    runner = InjectionRunner()
    handler_cls = _handler_for(runner, args.product_url)
    server = ThreadingHTTPServer((args.host, args.port), handler_cls)
    print(f"Demo GUI: http://{args.host}:{args.port}")
    print(f"Product API target: {args.product_url}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        runner.stop()
        server.server_close()
    return 0
