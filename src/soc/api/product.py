from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
import json
from pathlib import Path
from typing import Any
from urllib import error as urlerror, request as urlrequest
from urllib.parse import parse_qs, urlparse

from soc.context.watchlist import load_watchlist, match_watchlist
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
            if method == "GET" and path == "/api/source-inputs":
                return self._source_inputs()
            if method == "GET" and path == "/api/tier2/artifacts":
                return self._tier2_artifacts()
            if method == "POST" and path == "/api/tier2/refresh":
                return self._refresh_tier2(_json_body(body))
            if method == "POST" and path == "/api/admin/reset":
                return self._admin_reset()
            if method == "POST" and path == "/api/admin/config":
                return self._admin_config(_json_body(body))
            if method == "GET" and path == "/api/admin/llm-options":
                return self._admin_llm_options()
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
        service = self._service()
        prepared = service.prepare_flow(flow)

        if service.store is not None:
            service.store.save_flow(prepared.flow)
            service.store.save_ml_result(prepared.flow.flow_id, prepared.ml)
            service.store.save_route_decision(prepared.flow.flow_id, prepared.route)

        if prepared.route.route != "tier1_llm":
            result = asyncio.run(service.process_prepared(prepared))
            return self._json(
                200,
                {
                    "flow_id": flow.flow_id,
                    "tier1_path": False,
                    "processing_state": "complete",
                    "event": result.event,
                },
            )

        import threading

        def _background_task() -> None:
            asyncio.run(service.process_prepared(prepared))

        threading.Thread(target=_background_task, daemon=True).start()

        return self._json(
            202,
            {
                "flow_id": flow.flow_id,
                "tier1_path": True,
                "processing_state": "tier1_processing",
                "event": {
                    "flow_id": flow.flow_id,
                    "route": prepared.route.route,
                    "verdict": "processing",
                    "severity": "pending",
                    "processing_state": "tier1_processing",
                },
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
        detail["watchlist_detail"] = _watchlist_detail_for_stored_event(detail, self.settings)
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

    def _source_inputs(self) -> ProductApiResponse:
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
                        "content": snapshot.content,
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
            "provider": payload.get("provider", self.settings.tier2.provider),
            "model": payload.get("model", self.settings.tier2.model),
            "ollama_url": payload.get("ollama_url", self.settings.tier2.ollama_url),
            "gemini_api_key_env": payload.get(
                "gemini_api_key_env",
                self.settings.tier2.gemini_api_key_env,
            ),
            "gemini_api_base_url": payload.get(
                "gemini_api_base_url",
                self.settings.tier2.gemini_api_base_url,
            ),
            "timeout_seconds": payload.get(
                "timeout_seconds",
                self.settings.tier2.timeout_seconds,
            ),
            "max_tokens": payload.get("max_tokens", self.settings.tier2.max_tokens),
            "temperature": payload.get("temperature", self.settings.tier2.temperature),
            "response_format": payload.get(
                "response_format",
                self.settings.tier2.response_format,
            ),
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

    def _admin_reset(self) -> ProductApiResponse:
        """Clear all flow events from the database and reset in-memory state."""
        deleted: dict[str, int] = {}
        if self.store is not None:
            deleted = self.store.clear_all_events()
        self._realtime = None
        return self._json(200, {"reset": True, "deleted": deleted})

    def _admin_llm_options(self) -> ProductApiResponse:
        """Return configured and discoverable LLM choices for the demo controller."""
        tier1_ollama = _ollama_catalog(self.settings.tier1.llm.ollama_url)
        tier2_ollama = _ollama_catalog(self.settings.tier2.ollama_url)
        tier1_models = _ollama_model_choices(
            tier1_ollama,
            fallback_model=self.settings.tier1.llm.model,
            fallback_url=self.settings.tier1.llm.ollama_url,
        )
        tier2_models = (
            _gemini_model_choices(self.settings.tier2.model)
            + _ollama_model_choices(
                tier2_ollama,
                fallback_model="gemma4:26b",
                fallback_url=self.settings.tier2.ollama_url,
            )
        )
        return self._json(
            200,
            {
                "tier1": {
                    "provider": self.settings.tier1.llm.provider,
                    "model": self.settings.tier1.llm.model,
                    "ollama_url": self.settings.tier1.llm.ollama_url,
                    "models": tier1_models,
                },
                "tier2": {
                    "provider": self.settings.tier2.provider,
                    "model": self.settings.tier2.model,
                    "ollama_url": self.settings.tier2.ollama_url,
                    "models": tier2_models,
                },
                "ollama": {
                    "tier1": tier1_ollama,
                    "tier2": tier2_ollama,
                },
            },
        )

    def _admin_config(self, payload: dict[str, Any]) -> ProductApiResponse:
        """Apply runtime configuration overrides and rebuild services."""
        changes: dict[str, str] = {}

        # Update Tier 1 LLM settings
        old_llm = self.settings.tier1.llm
        tier1_provider = payload.get("tier1_provider") or old_llm.provider
        tier1_model = payload.get("tier1_model") or old_llm.model
        tier1_ollama_url = payload.get("tier1_ollama_url") or old_llm.ollama_url
        if payload.get("tier1_provider"):
            changes["tier1_provider"] = tier1_provider
        if payload.get("tier1_model"):
            changes["tier1_model"] = tier1_model
        if payload.get("tier1_ollama_url"):
            changes["tier1_ollama_url"] = tier1_ollama_url

        from soc.config.settings import (
            RoutingSettings,
            Tier1LLMSettings,
            Tier1Settings,
            Tier2Settings,
        )

        new_llm = Tier1LLMSettings(
            provider=tier1_provider,
            model=tier1_model,
            ollama_url=tier1_ollama_url,
            timeout_seconds=old_llm.timeout_seconds,
        )
        new_tier1 = Tier1Settings(
            llm=new_llm,
            queue=self.settings.tier1.queue,
        )

        # Update Tier 2 settings
        old_tier2 = self.settings.tier2
        tier2_provider = payload.get("tier2_provider") or old_tier2.provider
        tier2_model = payload.get("tier2_model") or old_tier2.model
        tier2_ollama_url = payload.get("tier2_ollama_url") or old_tier2.ollama_url
        if payload.get("tier2_provider"):
            changes["tier2_provider"] = tier2_provider
        if payload.get("tier2_model"):
            changes["tier2_model"] = tier2_model
        if payload.get("tier2_ollama_url"):
            changes["tier2_ollama_url"] = tier2_ollama_url

        new_tier2 = Tier2Settings(
            provider=tier2_provider,
            model=tier2_model,
            ollama_url=tier2_ollama_url,
            gemini_api_key_env=old_tier2.gemini_api_key_env,
            gemini_api_base_url=old_tier2.gemini_api_base_url,
            timeout_seconds=old_tier2.timeout_seconds,
            max_tokens=old_tier2.max_tokens,
            attack_surface_memory_max_chars=old_tier2.attack_surface_memory_max_chars,
            temperature=old_tier2.temperature,
            response_format=old_tier2.response_format,
            watchlist=old_tier2.watchlist,
            brief=old_tier2.brief,
            memory=old_tier2.memory,
        )

        # Update Routing Settings
        old_routing = self.settings.routing
        try:
            threshold_low = float(payload.get("threshold_low") or old_routing.threshold_low)
            threshold_high = float(payload.get("threshold_high") or old_routing.threshold_high)
        except (ValueError, TypeError):
            threshold_low = old_routing.threshold_low
            threshold_high = old_routing.threshold_high

        if payload.get("threshold_low"):
            changes["threshold_low"] = str(threshold_low)
        if payload.get("threshold_high"):
            changes["threshold_high"] = str(threshold_high)

        new_routing = RoutingSettings(
            threshold_low=threshold_low,
            threshold_high=threshold_high,
            priority_1_llm_threshold=old_routing.priority_1_llm_threshold,
        )

        # Re-assemble settings and save
        self.settings = replace(
            self.settings,
            tier1=new_tier1,
            tier2=new_tier2,
            routing=new_routing,
        )

        # Rebuild the realtime service with new settings
        self._realtime = None
        return self._json(200, {"applied": changes, "status": self._status_payload()})

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
            "tier1_model": self.settings.tier1.llm.model,
            "tier1_ollama_url": self.settings.tier1.llm.ollama_url,
            "tier1_queue_mode": self.settings.tier1.queue.mode,
            "tier2_provider": self.settings.tier2.provider,
            "tier2_model": self.settings.tier2.model,
            "tier2_ollama_url": self.settings.tier2.ollama_url,
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


def _ollama_catalog(configured_url: str) -> dict[str, Any]:
    candidates = _unique_values(
        [
            configured_url,
            "http://host.docker.internal:11434",
            "http://localhost:11434",
            "http://127.0.0.1:11434",
        ]
    )
    attempts = []
    for base_url in candidates:
        result = _fetch_ollama_tags(base_url)
        attempts.append(result)
        if result["reachable"]:
            return {
                "reachable": True,
                "url": base_url,
                "models": result["models"],
                "attempts": attempts,
            }
    return {
        "reachable": False,
        "url": configured_url,
        "models": [],
        "attempts": attempts,
    }


def _fetch_ollama_tags(base_url: str) -> dict[str, Any]:
    url = f"{str(base_url).rstrip('/')}/api/tags"
    req = urlrequest.Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        with urlrequest.urlopen(req, timeout=0.25) as resp:
            raw = resp.read().decode("utf-8")
    except (urlerror.URLError, TimeoutError, OSError) as exc:
        return {
            "reachable": False,
            "url": base_url,
            "models": [],
            "error": str(exc),
        }

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {
            "reachable": False,
            "url": base_url,
            "models": [],
            "error": f"invalid JSON: {exc}",
        }

    models = data.get("models") if isinstance(data, dict) else []
    names = [
        str(item.get("name"))
        for item in models
        if isinstance(item, dict) and item.get("name")
    ]
    return {
        "reachable": True,
        "url": base_url,
        "models": sorted(names),
    }


def _ollama_model_choices(
    catalog: dict[str, Any],
    *,
    fallback_model: str,
    fallback_url: str,
) -> list[dict[str, str]]:
    model_names = catalog.get("models") or [fallback_model]
    url = str(catalog.get("url") or fallback_url)
    return [
        {
            "label": f"Ollama Local - {name}",
            "provider": "ollama",
            "model": str(name),
            "ollama_url": url,
        }
        for name in _unique_values([str(name) for name in model_names if str(name)])
    ]


def _gemini_model_choices(current_model: str) -> list[dict[str, str]]:
    names = _unique_values(
        [
            current_model,
            "gemini-3.5-flash",
            "gemini-3-flash-preview",
        ]
    )
    return [
        {
            "label": f"Gemini API - {name}",
            "provider": "gemini",
            "model": name,
            "ollama_url": "",
        }
        for name in names
    ]


def _unique_values(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def _dashboard_counters(events: list[dict[str, Any]]) -> dict[str, Any]:
    routes: dict[str, int] = {}
    verdicts: dict[str, int] = {}
    severities: dict[str, int] = {}
    watchlist_hits = 0
    fallbacks = 0
    pending_tier1 = 0
    for event in events:
        _increment(routes, event.get("route"))
        if event.get("processing_state") == "tier1_processing":
            pending_tier1 += 1
        else:
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
        "pending_tier1": pending_tier1,
    }


def _increment(counter: dict[str, int], value: Any) -> None:
    key = str(value or "unknown")
    counter[key] = counter.get(key, 0) + 1


def _watchlist_detail_for_stored_event(
    detail: dict[str, Any],
    settings: PipelineSettings,
) -> dict[str, Any]:
    try:
        flow = Flow(
            flow_id=str(detail.get("flow_id") or ""),
            start_ms=_to_optional_int(detail.get("start_ms")),
            end_ms=_to_optional_int(detail.get("end_ms")),
            src_ip=str(detail.get("src_ip") or ""),
            dst_ip=str(detail.get("dst_ip") or ""),
            src_port=_to_int(detail.get("src_port")),
            dst_port=_to_int(detail.get("dst_port")),
            protocol=str(detail.get("protocol") or ""),
            features=dict(detail.get("features") or {}),
            raw_label=detail.get("raw_label"),
            raw_attack=detail.get("raw_attack"),
        )
        match = match_watchlist(
            flow,
            load_watchlist(settings.tier2.watchlist),
            ml_prob=detail.get("prob"),
        )
    except Exception as exc:
        return {"matched": False, "error": f"{type(exc).__name__}: {exc}"}

    return {
        "matched": match.matched,
        "priority": match.priority,
        "item_id": match.item_id,
        "reason": match.reason,
        "matched_conditions": match.matched_conditions,
        "scope_conditions": match.scope_conditions,
        "matched_trigger_hints": match.matched_trigger_hints,
        "unmatched_trigger_hints": match.unmatched_trigger_hints,
        "matched_benign_hints": match.matched_benign_hints,
        "trigger_completeness": match.trigger_completeness,
        "match_strength": match.match_strength,
        "scope_matched": match.scope_matched,
        "trigger_matched": match.trigger_matched,
        "context_only": match.context_only,
        "linter_warnings": match.linter_warnings,
        "escalation_hint": match.escalation_hint,
        "routing_policy": match.routing_policy,
    }
