from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from soc.config.settings import PipelineSettings, load_pipeline_settings, validate_pipeline_settings
from soc.io import _to_int, _to_optional_int
from soc.llm.provider import FakeLLMProvider, OllamaProvider
from soc.ml.detector import DummyDetector, XGBoostDetector
from soc.models import Flow
from soc.realtime.service import RealtimeIngestService, Tier1RuntimeInfo
from soc.storage.sqlite import SQLiteEventStore
from soc.tier2.batch import run_tier2_from_config
from soc.tier2.input_collectors import Tier2InputCollector


@dataclass(frozen=True)
class ProductApiResponse:
    status: int
    body: dict[str, Any]


class ProductApi:
    """Small dependency-free API core used by the HTTP wrapper and tests."""

    def __init__(self, config_path: str | Path = "config/settings.example.yaml") -> None:
        self.config_path = Path(config_path)
        self.settings = load_pipeline_settings(self.config_path)
        validate_pipeline_settings(self.settings)
        self.store = self._build_store(self.settings)
        self._realtime: RealtimeIngestService | None = None

    def handle(
        self,
        method: str,
        target: str,
        body: bytes | str | None = None,
    ) -> ProductApiResponse:
        parsed = urlparse(target)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)
        try:
            if method == "GET" and path == "/api/status":
                return self._json(200, self._status_payload())
            if method == "GET" and path == "/api/dashboard":
                return self._dashboard()
            if method == "POST" and path == "/api/flows":
                return self._ingest_flow(_json_body(body))
            if method == "GET" and path == "/api/flows/recent":
                return self._recent_flows(query)
            if method == "GET" and path.startswith("/api/flows/"):
                return self._flow_detail(path.removeprefix("/api/flows/"))
            if method == "GET" and path == "/api/source-inputs/status":
                return self._source_input_status()
            if method == "GET" and path == "/api/tier2/artifacts":
                return self._tier2_artifacts()
            if method == "POST" and path == "/api/tier2/refresh":
                return self._refresh_tier2(_json_body(body))
            if method == "GET" and path == "/api/summary/latest":
                return self._latest_summary()
            if method == "GET" and path == "/api/reports":
                return self._reports()
        except ValueError as exc:
            return self._json(400, {"error": str(exc)})
        except FileNotFoundError as exc:
            return self._json(404, {"error": str(exc)})
        except Exception as exc:
            return self._json(500, {"error": f"{type(exc).__name__}: {exc}"})
        return self._json(404, {"error": f"unknown endpoint: {method} {path}"})

    def _ingest_flow(self, payload: dict[str, Any]) -> ProductApiResponse:
        flow = flow_from_payload(payload)
        result = asyncio.run(self._service().ingest_flow(flow))
        return self._json(
            201,
            {
                "flow_id": result.flow.flow_id,
                "tier1_path": result.tier1_path,
                "event": result.event,
            },
        )

    def _recent_flows(self, query: dict[str, list[str]]) -> ProductApiResponse:
        if self.store is None:
            return self._json(200, {"events": [], "storage_enabled": False})
        limit = _query_int(query, "limit", 50)
        return self._json(
            200,
            {
                "events": self.store.list_recent_flow_events(limit),
                "storage_enabled": True,
            },
        )

    def _flow_detail(self, flow_id: str) -> ProductApiResponse:
        if self.store is None:
            return self._json(404, {"error": "storage is disabled"})
        detail = self.store.get_flow_event_detail(flow_id)
        if detail is None:
            return self._json(404, {"error": f"flow not found: {flow_id}"})
        return self._json(200, {"event": detail})

    def _source_input_status(self) -> ProductApiResponse:
        snapshots = Tier2InputCollector(_raw_config(self.config_path)).collect()
        return self._json(
            200,
            {
                "sources": [
                    {
                        "name": snapshot.name,
                        "status": snapshot.status,
                        "source_type": snapshot.source_type,
                        "path_or_uri": snapshot.path_or_uri,
                        "item_count": snapshot.item_count,
                        "error": snapshot.error,
                    }
                    for snapshot in snapshots
                ]
            },
        )

    def _tier2_artifacts(self) -> ProductApiResponse:
        return self._json(
            200,
            {
                "watchlist": _artifact_payload(self.settings.tier2.watchlist),
                "brief": _artifact_payload(self.settings.tier2.brief),
                "memory": _artifact_payload(self.settings.tier2.memory),
            },
        )

    def _refresh_tier2(self, payload: dict[str, Any]) -> ProductApiResponse:
        output_dir = str(payload.get("output_dir") or _default_tier2_output_dir(self.settings))
        overrides = {
            "provider": payload.get("provider"),
            "model": payload.get("model"),
            "ollama_url": payload.get("ollama_url"),
            "gemini_api_key_env": payload.get("gemini_api_key_env"),
            "gemini_api_base_url": payload.get("gemini_api_base_url"),
            "timeout_seconds": payload.get("timeout_seconds"),
            "max_tokens": payload.get("max_tokens"),
            "temperature": payload.get("temperature"),
            "response_format": payload.get("response_format"),
        }
        result = run_tier2_from_config(
            config_path=self.config_path,
            output_dir=output_dir,
            overrides=overrides,
        )
        self._realtime = None
        return self._json(
            200,
            {
                "cycle_id": result.cycle_id,
                "metadata": result.metadata,
                "paths": {
                    "watchlist": str(Path(output_dir) / "watchlists" / "latest.yaml"),
                    "brief": str(Path(output_dir) / "briefs" / "latest.md"),
                    "memory": str(Path(output_dir) / "memory" / "latest.md"),
                },
            },
        )

    def _latest_summary(self) -> ProductApiResponse:
        json_path = Path("output/daily_summaries/latest.json")
        md_path = Path("output/daily_summaries/latest.md")
        return self._json(
            200,
            {
                "json": _artifact_payload(json_path),
                "markdown": _artifact_payload(md_path),
            },
        )

    def _reports(self) -> ProductApiResponse:
        report_dir = Path(self.settings.runtime.output)
        html_reports = []
        if report_dir.exists():
            html_reports = [
                {"path": str(path), "name": path.name}
                for path in sorted(report_dir.glob("*.html"))
            ]
        daily_dir = Path("output/daily_summaries")
        daily_summaries = []
        if daily_dir.exists():
            daily_summaries = [
                {"path": str(path), "name": path.name}
                for path in sorted(daily_dir.glob("summary_*.md"))
            ]
        return self._json(
            200,
            {
                "html_reports": html_reports,
                "daily_summaries": daily_summaries,
            },
        )

    def _dashboard(self) -> ProductApiResponse:
        recent_response = self._recent_flows({"limit": ["50"]}).body
        source_response = self._source_input_status().body
        artifact_response = self._tier2_artifacts().body
        summary_response = self._latest_summary().body
        reports_response = self._reports().body
        events = recent_response.get("events", [])
        counters = _dashboard_counters(events)
        return self._json(
            200,
            {
                "status": self._status_payload(),
                "counters": counters,
                "recent_flows": events,
                "source_inputs": source_response,
                "tier2_artifacts": artifact_response,
                "latest_summary": summary_response,
                "reports": reports_response,
            },
        )

    def _status_payload(self) -> dict[str, Any]:
        storage_status = (
            self.store.get_runtime_status()
            if self.store is not None
            else {"enabled": False, "sqlite_path": self.settings.storage.sqlite_path}
        )
        return {
            "service": "mini-llm-soc-product-api",
            "config_path": str(self.config_path),
            "detector": self.settings.detector.provider,
            "tier1_provider": self.settings.tier1.llm.provider,
            "tier1_queue_mode": self.settings.tier1.queue.mode,
            "tier2_provider": self.settings.tier2.provider,
            "storage": storage_status,
            "artifacts": {
                "watchlist": self.settings.tier2.watchlist,
                "brief": self.settings.tier2.brief,
                "memory": self.settings.tier2.memory,
            },
        }

    def _service(self) -> RealtimeIngestService:
        if self._realtime is None:
            self._realtime = RealtimeIngestService.from_artifacts(
                detector=_build_detector(self.settings),
                provider=_build_provider(self.settings),
                store=self.store,
                watchlist_path=self.settings.tier2.watchlist,
                brief_context=_read_text(self.settings.tier2.brief),
                threshold_low=self.settings.routing.threshold_low,
                threshold_high=self.settings.routing.threshold_high,
                priority_1_llm_threshold=self.settings.routing.priority_1_llm_threshold,
                tier1_runtime=Tier1RuntimeInfo(
                    provider=self.settings.tier1.llm.provider,
                    model_name=_tier1_model_name(self.settings),
                ),
            )
        return self._realtime

    @staticmethod
    def _build_store(settings: PipelineSettings) -> SQLiteEventStore | None:
        if not settings.storage.enabled:
            return None
        store = SQLiteEventStore(settings.storage.sqlite_path)
        store.initialize()
        return store

    @staticmethod
    def _json(status: int, body: dict[str, Any]) -> ProductApiResponse:
        return ProductApiResponse(status=status, body=body)


def flow_from_payload(payload: dict[str, Any]) -> Flow:
    features = dict(payload.get("features") or {})
    for key, value in payload.items():
        if key not in {
            "flow_id",
            "start_ms",
            "end_ms",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "features",
            "raw_label",
            "raw_attack",
            "FLOW_START_MILLISECONDS",
            "FLOW_END_MILLISECONDS",
            "IPV4_SRC_ADDR",
            "IPV4_DST_ADDR",
            "L4_SRC_PORT",
            "L4_DST_PORT",
            "PROTOCOL",
            "Label",
            "Attack",
        }:
            features.setdefault(key, value)
    flow_id = str(payload.get("flow_id") or payload.get("id") or "")
    if not flow_id:
        raise ValueError("flow_id is required")
    return Flow(
        flow_id=flow_id,
        start_ms=_to_optional_int(payload.get("start_ms", payload.get("FLOW_START_MILLISECONDS"))),
        end_ms=_to_optional_int(payload.get("end_ms", payload.get("FLOW_END_MILLISECONDS"))),
        src_ip=str(payload.get("src_ip", payload.get("IPV4_SRC_ADDR", ""))),
        dst_ip=str(payload.get("dst_ip", payload.get("IPV4_DST_ADDR", ""))),
        src_port=_to_int(payload.get("src_port", payload.get("L4_SRC_PORT"))),
        dst_port=_to_int(payload.get("dst_port", payload.get("L4_DST_PORT"))),
        protocol=str(payload.get("protocol", payload.get("PROTOCOL", ""))),
        features=features,
        raw_label=payload.get("raw_label", payload.get("Label")),
        raw_attack=payload.get("raw_attack", payload.get("Attack")),
    )


def _build_detector(settings: PipelineSettings):
    if settings.detector.provider == "dummy":
        return DummyDetector()
    if settings.detector.provider == "xgboost":
        return XGBoostDetector(
            settings.detector.model,
            settings.detector.metadata,
            category_model_path=settings.detector.category_model,
            category_metadata_path=settings.detector.category_metadata,
        )
    raise ValueError(f"unsupported detector: {settings.detector.provider}")


def _build_provider(settings: PipelineSettings):
    if settings.tier1.llm.provider == "fake":
        return FakeLLMProvider()
    if settings.tier1.llm.provider == "ollama":
        return OllamaProvider(
            model=settings.tier1.llm.model,
            base_url=settings.tier1.llm.ollama_url,
            timeout_seconds=settings.tier1.llm.timeout_seconds,
        )
    raise ValueError(f"unsupported Tier 1 provider: {settings.tier1.llm.provider}")


def _tier1_model_name(settings: PipelineSettings) -> str:
    if settings.tier1.llm.provider == "fake":
        return "fake-llm"
    return settings.tier1.llm.model


def _json_body(body: bytes | str | None) -> dict[str, Any]:
    if body in (None, b"", ""):
        return {}
    if isinstance(body, bytes):
        body = body.decode("utf-8")
    data = json.loads(body)
    if not isinstance(data, dict):
        raise ValueError("JSON body must be an object")
    return data


def _query_int(query: dict[str, list[str]], key: str, default: int) -> int:
    values = query.get(key)
    if not values:
        return default
    return int(values[0])


def _artifact_payload(path: str | Path) -> dict[str, Any]:
    artifact_path = Path(path)
    payload: dict[str, Any] = {
        "path": str(artifact_path),
        "exists": artifact_path.exists(),
        "content": "",
    }
    if artifact_path.exists():
        payload["content"] = artifact_path.read_text(encoding="utf-8")
    return payload


def _read_text(path: str | Path) -> str:
    file_path = Path(path)
    if not file_path.exists():
        return ""
    return file_path.read_text(encoding="utf-8")


def _default_tier2_output_dir(settings: PipelineSettings) -> str:
    watchlist_path = Path(settings.tier2.watchlist)
    if len(watchlist_path.parts) >= 2 and watchlist_path.parts[-2] == "watchlists":
        return str(watchlist_path.parent.parent)
    return "output"


def _raw_config(path: Path) -> dict[str, Any]:
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return {
            "storage": {"enabled": False},
            "tier2": {"sources": {}},
        }
    return data if isinstance(data, dict) else {}


def _dashboard_counters(events: list[dict[str, Any]]) -> dict[str, Any]:
    routes: dict[str, int] = {}
    verdicts: dict[str, int] = {}
    severities: dict[str, int] = {}
    watchlist_hits = 0
    fallbacks = 0
    for event in events:
        _increment(routes, event.get("route"))
        _increment(verdicts, event.get("verdict"))
        _increment(severities, event.get("severity"))
        if event.get("watchlist_matched"):
            watchlist_hits += 1
        if event.get("fallback_source"):
            fallbacks += 1
    return {
        "total_recent": len(events),
        "routes": routes,
        "verdicts": verdicts,
        "severities": severities,
        "watchlist_hits": watchlist_hits,
        "fallbacks": fallbacks,
    }


def _increment(counter: dict[str, int], value: Any) -> None:
    key = str(value or "unknown")
    counter[key] = counter.get(key, 0) + 1
