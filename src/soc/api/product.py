from __future__ import annotations

import asyncio
import queue
from dataclasses import dataclass, replace
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time
from typing import Any
from urllib import error as urlerror, request as urlrequest
from urllib.parse import parse_qs, urlparse

from soc.context.watchlist import REVIEWABLE_MATCH_STRENGTHS, load_watchlist, match_watchlist
from soc.config.settings import PipelineSettings, load_pipeline_settings, validate_pipeline_settings
from soc.io import _to_int, _to_optional_int
from soc.llm.provider import FakeLLMProvider, GeminiProvider, OllamaProvider
from soc.ml.detector import DummyDetector, XGBoostDetector
from soc.models import Flow
from soc.realtime.service import (
    PreparedRealtimeFlow,
    RealtimeIngestService,
    Tier1RuntimeInfo,
    queue_fallback_verdict,
)
from soc.storage.sqlite import SQLiteEventStore
from soc.summary.daily import run_daily_summary
from soc.api.topology import build_topology_payload
from soc.tier2.batch import run_tier2_from_config
from soc.tier2.input_collectors import Tier2InputCollector

_SOURCE_INPUT_NAMES = ("organization", "assets", "policy", "cve_feed", "threat_feed")
_DEFAULT_PRODUCT_CONFIG = Path("config/settings.example.yaml")
_RUNTIME_CONFIG_OVERRIDE_KEYS = {
    "tier1_provider",
    "tier1_model",
    "tier1_ollama_url",
    "tier1_max_tokens",
    "tier1_retry_attempts",
    "tier1_retry_backoff_seconds",
    "tier1_workers",
    "tier1_queue_max_size",
    "tier1_queue_timeout",
    "tier2_provider",
    "tier2_model",
    "tier2_ollama_url",
    "tier2_max_tokens",
    "threshold_low",
    "threshold_high",
    "activity_window_minutes",
}


@dataclass(frozen=True)
class ProductApiResponse:
    status: int
    body: dict[str, Any]


@dataclass(frozen=True)
class ProductTier1Job:
    sequence: int
    priority: tuple[float, float, int]
    enqueued_at: float
    prepared: PreparedRealtimeFlow


ProductTier1QueueItem = tuple[tuple[float, float, int], int, ProductTier1Job | None]


class ProductApi:
    """Small dependency-free API core used by the HTTP wrapper and tests."""

    def __init__(self, config_path: str | Path = "config/settings.example.yaml") -> None:
        self._configured_config_path = Path(config_path)
        self.config_path = _resolve_initial_product_config_path(self._configured_config_path)
        self.settings = load_pipeline_settings(self.config_path)
        validate_pipeline_settings(self.settings)
        self.store = self._build_store(self.settings)
        self._realtime: RealtimeIngestService | None = None
        self._tier1_queue: ProductTier1Queue | None = None

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
            if method == "POST" and path.startswith("/api/source-inputs/"):
                return self._update_source_input(
                    path.removeprefix("/api/source-inputs/"),
                    _json_body(body),
                )
            if method == "GET" and path == "/api/topology":
                return self._topology()
            if method == "GET" and path == "/api/tier2/artifacts":
                return self._tier2_artifacts()
            if method == "POST" and path == "/api/tier2/refresh":
                return self._refresh_tier2(_json_body(body))
            if method == "POST" and path == "/api/admin/reset":
                return self._admin_reset()
            if method == "POST" and path == "/api/admin/reset-all":
                return self._admin_reset_all()
            if method == "POST" and path == "/api/admin/config":
                return self._admin_config(_json_body(body))
            if method == "POST" and path == "/api/admin/source-inputs":
                return self._admin_source_inputs(_json_body(body))
            if method == "GET" and path == "/api/admin/llm-options":
                return self._admin_llm_options()
            if method == "GET" and path == "/api/summary/latest":
                return self._latest_summary()
            if method == "POST" and path == "/api/summary/generate":
                return self._generate_summary(_json_body(body))
            if method == "GET" and path == "/api/reports":
                return self._reports(query)
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

        queued = self._tier1_work_queue(service).submit(prepared)
        if not queued:
            verdict = queue_fallback_verdict(
                prepared.match,
                "Tier 1 queue is full; overflow policy=fallback.",
            )
            result = service.complete(prepared, verdict, tier1_path=True)
            return self._json(
                200,
                {
                    "flow_id": flow.flow_id,
                    "tier1_path": True,
                    "processing_state": "complete",
                    "event": result.event,
                },
            )

        return self._json(
            202,
            {
                "flow_id": flow.flow_id,
                "tier1_path": True,
                "processing_state": "tier1_queued",
                "event": {
                    "flow_id": flow.flow_id,
                    "route": prepared.route.route,
                    "verdict": "processing",
                    "severity": "pending",
                    "processing_state": "tier1_queued",
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
                        "data": _source_data_payload(snapshot),
                        "error": snapshot.error,
                    }
                    for snapshot in snapshots
                ]
            },
        )

    def _update_source_input(self, source_name: str, payload: dict[str, Any]) -> ProductApiResponse:
        name = source_name.strip()
        if name not in _SOURCE_INPUT_NAMES:
            raise ValueError(f"unsupported source input: {name}")

        raw = _raw_config(self.config_path)
        _sync_raw_config_with_settings(raw, self.settings)
        source_path, config_changed = _source_input_target_path(raw, self.config_path, name)

        if "content" in payload:
            content = str(payload.get("content") or "")
            _validate_yaml_mapping(content, name)
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_text(content, encoding="utf-8")
            change = "raw_saved"
        elif isinstance(payload.get("append"), dict):
            data = _read_source_yaml_mapping(source_path)
            _append_source_item(name, data, dict(payload["append"]))
            _write_yaml(source_path, data)
            change = "item_added"
        elif isinstance(payload.get("delete"), dict):
            data = _read_source_yaml_mapping(source_path)
            _delete_source_item(name, data, dict(payload["delete"]))
            _write_yaml(source_path, data)
            change = "item_deleted"
        else:
            raise ValueError("content, append, or delete is required")

        _enable_source_path(raw, name, source_path)
        if config_changed or not self.config_path.exists():
            active_config_path = _product_runtime_dir(self.config_path) / "settings.active.yaml"
            _write_yaml(active_config_path, raw)
            self.config_path = active_config_path
        elif self.config_path.name == "settings.active.yaml":
            _write_yaml(self.config_path, raw)

        self.settings = load_pipeline_settings(self.config_path)
        validate_pipeline_settings(self.settings)
        self.store = self._build_store(self.settings)
        self._reset_realtime_runtime()
        snapshots = Tier2InputCollector(_raw_config(self.config_path)).collect()
        snapshot = next((item for item in snapshots if item.name == name), None)
        return self._json(
            200,
            {
                "updated": True,
                "change": change,
                "source": {
                    "name": snapshot.name if snapshot else name,
                    "status": snapshot.status if snapshot else "missing",
                    "source_type": snapshot.source_type if snapshot else "yaml",
                    "path_or_uri": snapshot.path_or_uri if snapshot else str(source_path),
                    "item_count": snapshot.item_count if snapshot else 0,
                    "content": snapshot.content if snapshot else "",
                    "data": _source_data_payload(snapshot) if snapshot else {},
                    "error": snapshot.error if snapshot else None,
                },
                "status": self._status_payload(),
            },
        )

    def _topology(self) -> ProductApiResponse:
        events = self._recent_events_for_topology()
        return self._json(200, build_topology_payload(self._source_snapshots(), events))

    def _tier2_artifacts(self) -> ProductApiResponse:
        topology_path, topology_map_path = _topology_artifact_paths(self.settings)
        return self._json(
            200,
            {
                "watchlist": _artifact_payload(self.settings.tier2.watchlist),
                "brief": _artifact_payload(self.settings.tier2.brief),
                "memory": _artifact_payload(self.settings.tier2.memory),
                "topology": _artifact_payload(topology_path),
                "topology_map": _json_artifact_payload(topology_map_path),
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
        self._reset_realtime_runtime()
        return self._json(
            200,
            {
                "cycle_id": result.cycle_id,
                "metadata": result.metadata,
                "paths": {
                    "watchlist": str(Path(output_dir) / "watchlists" / "latest.yaml"),
                    "brief": str(Path(output_dir) / "briefs" / "latest.md"),
                    "memory": str(Path(output_dir) / "memory" / "latest.md"),
                    "topology": str(Path(output_dir) / "topology" / "latest.mmd"),
                    "topology_map": str(Path(output_dir) / "topology" / "latest.json"),
                },
            },
        )

    def _admin_reset(self) -> ProductApiResponse:
        """Clear all flow events from the database and reset in-memory state."""
        deleted: dict[str, int] = {}
        if self.store is not None:
            deleted = self.store.clear_all_events()
        self._reset_realtime_runtime()
        return self._json(200, {"reset": True, "deleted": deleted})

    def _admin_reset_all(self) -> ProductApiResponse:
        """Clear stored events and remove generated runtime scenario artifacts."""
        reset_response = self._admin_reset()
        removed = _clear_product_runtime_artifacts(self.settings, self.config_path)
        self.config_path = _resolve_reset_config_path(self._configured_config_path)
        self.settings = load_pipeline_settings(self.config_path)
        validate_pipeline_settings(self.settings)
        self.store = self._build_store(self.settings)
        self._reset_realtime_runtime()
        return self._json(
            200,
            {
                "reset": True,
                "deleted": reset_response.body.get("deleted", {}),
                "removed": removed,
                "config_path": str(self.config_path),
                "status": self._status_payload(),
            },
        )

    def _admin_source_inputs(self, payload: dict[str, Any]) -> ProductApiResponse:
        """Copy external source input files into the product runtime workspace."""
        sources = payload.get("sources")
        if not isinstance(sources, dict) or not sources:
            raise ValueError("sources must be a non-empty mapping")

        runtime_dir = Path(str(payload.get("runtime_dir") or "output/product_runtime"))
        input_dir = runtime_dir / "inputs"
        input_dir.mkdir(parents=True, exist_ok=True)

        copied: dict[str, dict[str, str]] = {}
        for name in _SOURCE_INPUT_NAMES:
            source_value = sources.get(name)
            if source_value in (None, ""):
                continue
            source_path = Path(str(source_value))
            if not source_path.exists():
                raise FileNotFoundError(f"source input not found for {name}: {source_path}")
            if not source_path.is_file():
                raise ValueError(f"source input must be a file for {name}: {source_path}")
            target_path = input_dir / f"{name}{source_path.suffix or '.yaml'}"
            shutil.copyfile(source_path, target_path)
            copied[name] = {
                "source": str(source_path),
                "target": str(target_path),
            }

        if not copied:
            raise ValueError("no supported source inputs were provided")

        raw = _raw_config(self.config_path)
        _sync_raw_config_with_settings(raw, self.settings)
        tier2_config = raw.setdefault("tier2", {})
        if not isinstance(tier2_config, dict):
            tier2_config = {}
            raw["tier2"] = tier2_config
        sources_config = tier2_config.setdefault("sources", {})
        if not isinstance(sources_config, dict):
            sources_config = {}
            tier2_config["sources"] = sources_config

        for name, paths in copied.items():
            source_config = sources_config.setdefault(name, {})
            if not isinstance(source_config, dict):
                source_config = {}
                sources_config[name] = source_config
            source_config["enabled"] = True
            source_config["path"] = paths["target"]

        active_config_path = runtime_dir / "settings.active.yaml"
        _write_yaml(active_config_path, raw)
        self.config_path = active_config_path
        self.settings = load_pipeline_settings(self.config_path)
        validate_pipeline_settings(self.settings)
        self.store = self._build_store(self.settings)
        self._reset_realtime_runtime()
        return self._json(
            200,
            {
                "applied": True,
                "scenario": payload.get("scenario"),
                "config_path": str(active_config_path),
                "input_dir": str(input_dir),
                "copied": copied,
                "status": self._status_payload(),
            },
        )

    def _admin_llm_options(self) -> ProductApiResponse:
        """Return configured and discoverable LLM choices for the product settings UI."""
        tier1_ollama = _ollama_catalog(self.settings.tier1.llm.ollama_url)
        tier2_ollama = _ollama_catalog(self.settings.tier2.ollama_url)
        tier1_models = (
            _gemini_tier1_model_choices(self.settings.tier1.llm.model)
            + _ollama_model_choices(tier1_ollama)
        )
        tier2_models = (
            _gemini_model_choices(self.settings.tier2.model)
            + _ollama_model_choices(tier2_ollama)
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
                "gemini": {
                    "api_key_env": self.settings.tier2.gemini_api_key_env,
                    "has_key": _has_gemini_api_key(self.settings.tier2.gemini_api_key_env),
                    "base_url": self.settings.tier2.gemini_api_base_url,
                },
            },
        )

    def _admin_config(self, payload: dict[str, Any]) -> ProductApiResponse:
        """Apply runtime configuration overrides and rebuild services."""
        changes: dict[str, str] = {}

        # Handle config path update
        config_path_str = payload.get("config_path")
        if config_path_str:
            new_path = Path(config_path_str)
            if not new_path.exists():
                raise FileNotFoundError(f"Config path does not exist: {config_path_str}")
            self.config_path = new_path
            self.settings = load_pipeline_settings(self.config_path)
            validate_pipeline_settings(self.settings)
            self.store = self._build_store(self.settings)
            self._reset_realtime_runtime()
            changes["config_path"] = str(self.config_path)

        gemini_api_key = str(payload.get("gemini_api_key") or "").strip()
        if gemini_api_key:
            _set_gemini_api_key(self.settings.tier2.gemini_api_key_env, gemini_api_key)

        # Update Tier 1 LLM settings
        old_llm = self.settings.tier1.llm
        tier1_provider = payload.get("tier1_provider") or old_llm.provider
        tier1_model = payload.get("tier1_model") or old_llm.model
        tier1_ollama_url = _normalize_ollama_url_for_runtime(
            payload.get("tier1_ollama_url") or old_llm.ollama_url
        )
        try:
            tier1_max_tokens = int(payload.get("tier1_max_tokens") or old_llm.max_tokens)
        except (TypeError, ValueError):
            tier1_max_tokens = old_llm.max_tokens
        if tier1_max_tokens < 1:
            raise ValueError("tier1_max_tokens must be >= 1")
        try:
            tier1_retry_attempts = int(
                old_llm.retry_attempts
                if payload.get("tier1_retry_attempts") in (None, "")
                else payload.get("tier1_retry_attempts")
            )
        except (TypeError, ValueError):
            tier1_retry_attempts = old_llm.retry_attempts
        if tier1_retry_attempts < 0:
            raise ValueError("tier1_retry_attempts must be >= 0")
        try:
            tier1_retry_backoff_seconds = float(
                old_llm.retry_backoff_seconds
                if payload.get("tier1_retry_backoff_seconds") in (None, "")
                else payload.get("tier1_retry_backoff_seconds")
            )
        except (TypeError, ValueError):
            tier1_retry_backoff_seconds = old_llm.retry_backoff_seconds
        if tier1_retry_backoff_seconds < 0:
            raise ValueError("tier1_retry_backoff_seconds must be >= 0")
        tier1_llm_requested = any(
            payload.get(key) not in (None, "")
            for key in (
                "tier1_provider",
                "tier1_model",
                "tier1_ollama_url",
                "tier1_max_tokens",
                "tier1_retry_attempts",
                "tier1_retry_backoff_seconds",
            )
        )
        if tier1_llm_requested and tier1_provider == "ollama":
            _ensure_ollama_ready("Tier 1", tier1_ollama_url, tier1_model)
        if tier1_llm_requested and tier1_provider == "gemini":
            _ensure_gemini_ready(
                "Tier 1",
                self.settings.tier2.gemini_api_key_env,
                self.settings.tier2.gemini_api_base_url,
            )
        if payload.get("tier1_provider"):
            changes["tier1_provider"] = tier1_provider
        if payload.get("tier1_model"):
            changes["tier1_model"] = tier1_model
        if payload.get("tier1_ollama_url"):
            changes["tier1_ollama_url"] = tier1_ollama_url
        if payload.get("tier1_max_tokens"):
            changes["tier1_max_tokens"] = str(tier1_max_tokens)
        if payload.get("tier1_retry_attempts") not in (None, ""):
            changes["tier1_retry_attempts"] = str(tier1_retry_attempts)
        if payload.get("tier1_retry_backoff_seconds") not in (None, ""):
            changes["tier1_retry_backoff_seconds"] = str(tier1_retry_backoff_seconds)

        from soc.config.settings import (
            RealtimeSettings,
            RoutingSettings,
            Tier1LLMSettings,
            Tier1QueueSettings,
            Tier1Settings,
            Tier2Settings,
        )

        old_queue = self.settings.tier1.queue
        try:
            tier1_workers = int(payload.get("tier1_workers") or old_queue.workers)
        except (TypeError, ValueError):
            tier1_workers = old_queue.workers
        if tier1_workers < 1:
            raise ValueError("tier1_workers must be >= 1")
        try:
            tier1_queue_max_size = int(payload.get("tier1_queue_max_size") or old_queue.max_size)
        except (TypeError, ValueError):
            tier1_queue_max_size = old_queue.max_size
        if tier1_queue_max_size < 1:
            raise ValueError("tier1_queue_max_size must be >= 1")
        try:
            tier1_queue_timeout = float(
                payload.get("tier1_queue_timeout") or old_queue.timeout_seconds
            )
        except (TypeError, ValueError):
            tier1_queue_timeout = old_queue.timeout_seconds
        if tier1_queue_timeout < 0:
            raise ValueError("tier1_queue_timeout must be >= 0")

        if payload.get("tier1_workers"):
            changes["tier1_workers"] = str(tier1_workers)
        if payload.get("tier1_queue_max_size"):
            changes["tier1_queue_max_size"] = str(tier1_queue_max_size)
        if payload.get("tier1_queue_timeout"):
            changes["tier1_queue_timeout"] = str(tier1_queue_timeout)

        new_llm = Tier1LLMSettings(
            provider=tier1_provider,
            model=tier1_model,
            ollama_url=tier1_ollama_url,
            timeout_seconds=old_llm.timeout_seconds,
            max_tokens=tier1_max_tokens,
            retry_attempts=tier1_retry_attempts,
            retry_backoff_seconds=tier1_retry_backoff_seconds,
        )
        new_queue = Tier1QueueSettings(
            mode=old_queue.mode,
            workers=tier1_workers,
            max_size=tier1_queue_max_size,
            timeout_seconds=tier1_queue_timeout,
            overflow_policy=old_queue.overflow_policy,
            priority_policy=old_queue.priority_policy,
            max_calls_per_run=old_queue.max_calls_per_run,
        )
        new_tier1 = Tier1Settings(
            llm=new_llm,
            queue=new_queue,
        )

        # Update Tier 2 settings
        old_tier2 = self.settings.tier2
        tier2_provider = payload.get("tier2_provider") or old_tier2.provider
        tier2_model = payload.get("tier2_model") or old_tier2.model
        tier2_ollama_url = _normalize_ollama_url_for_runtime(
            payload.get("tier2_ollama_url") or old_tier2.ollama_url
        )
        try:
            tier2_max_tokens = int(payload.get("tier2_max_tokens") or old_tier2.max_tokens)
        except (TypeError, ValueError):
            tier2_max_tokens = old_tier2.max_tokens
        if tier2_max_tokens < 1:
            raise ValueError("tier2_max_tokens must be >= 1")
        tier2_llm_requested = any(
            payload.get(key) not in (None, "")
            for key in ("tier2_provider", "tier2_model", "tier2_ollama_url")
        )
        if tier2_llm_requested and tier2_provider == "ollama":
            _ensure_ollama_ready("Tier 2", tier2_ollama_url, tier2_model)
        if tier2_llm_requested and tier2_provider == "gemini":
            _ensure_gemini_ready(
                "Tier 2",
                old_tier2.gemini_api_key_env,
                old_tier2.gemini_api_base_url,
            )
        if payload.get("tier2_provider"):
            changes["tier2_provider"] = tier2_provider
        if payload.get("tier2_model"):
            changes["tier2_model"] = tier2_model
        if payload.get("tier2_ollama_url"):
            changes["tier2_ollama_url"] = tier2_ollama_url
        if payload.get("tier2_max_tokens"):
            changes["tier2_max_tokens"] = str(tier2_max_tokens)

        new_tier2 = Tier2Settings(
            provider=tier2_provider,
            model=tier2_model,
            ollama_url=tier2_ollama_url,
            gemini_api_key_env=old_tier2.gemini_api_key_env,
            gemini_api_base_url=old_tier2.gemini_api_base_url,
            timeout_seconds=old_tier2.timeout_seconds,
            max_tokens=tier2_max_tokens,
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

        old_realtime = self.settings.realtime
        try:
            activity_window_minutes = int(
                payload.get("activity_window_minutes") or old_realtime.activity_window_minutes
            )
        except (TypeError, ValueError):
            activity_window_minutes = old_realtime.activity_window_minutes
        if activity_window_minutes < 1:
            raise ValueError("activity_window_minutes must be >= 1")
        if payload.get("activity_window_minutes"):
            changes["activity_window_minutes"] = str(activity_window_minutes)
        new_realtime = RealtimeSettings(activity_window_minutes=activity_window_minutes)

        # Re-assemble settings and save
        new_settings = replace(
            self.settings,
            tier1=new_tier1,
            tier2=new_tier2,
            routing=new_routing,
            realtime=new_realtime,
        )
        validate_pipeline_settings(new_settings)
        self.settings = new_settings
        if _should_persist_runtime_config(self.config_path, payload):
            self.config_path = _persist_runtime_config(self.config_path, self.settings)
            self.settings = load_pipeline_settings(self.config_path)
            validate_pipeline_settings(self.settings)
            self.store = self._build_store(self.settings)

        # Rebuild the realtime service with new settings
        self._reset_realtime_runtime()
        return self._json(200, {"applied": changes, "status": self._status_payload()})

    def _latest_summary(self) -> ProductApiResponse:
        json_path = Path("output/daily_summaries/latest.json")
        md_path = Path("output/daily_summaries/latest.md")
        return self._json(
            200,
            {
                "json": _json_artifact_payload(json_path),
                "markdown": _artifact_payload(md_path),
            },
        )

    def _generate_summary(self, payload: dict[str, Any]) -> ProductApiResponse:
        if not self.settings.storage.enabled:
            raise ValueError("daily summary requires storage.enabled=true")
        sqlite_path = Path(self.settings.storage.sqlite_path)
        if not sqlite_path.exists():
            raise FileNotFoundError(f"SQLite event store not found: {sqlite_path}")
        summary_date = payload.get("date") or _latest_stored_flow_date(self.store)
        tier2_summary_provider = _build_tier2_summary_provider(self.settings)
        summary = run_daily_summary(
            sqlite_path,
            "output/daily_summaries",
            summary_date=summary_date,
            timezone_name=str(payload.get("timezone") or "Asia/Seoul"),
            llm_provider=tier2_summary_provider,
            llm_provider_name=self.settings.tier2.provider,
            llm_model=self.settings.tier2.model,
            llm_max_tokens=self.settings.tier2.max_tokens,
            llm_temperature=self.settings.tier2.temperature,
        )
        return self._json(
            200,
            {
                "generated": True,
                "generation_mode": summary.get("generation", {}).get("mode", "deterministic_sqlite"),
                "llm_called": bool(summary.get("generation", {}).get("llm_called", False)),
                "summary": summary,
                "latest_summary": self._latest_summary().body,
                "reports": self._reports({}).body,
            },
        )

    def _reports(self, query: dict[str, list[str]] | None = None) -> ProductApiResponse:
        query = query or {}
        filters = _report_filters(query)
        daily_dir = Path("output/daily_summaries")
        daily_summaries = []
        if daily_dir.exists():
            for json_path in sorted(daily_dir.glob("summary_*.json"), reverse=True):
                data = _read_json(json_path)
                markdown_path = json_path.with_suffix(".md")
                daily_summaries.append(
                    {
                        "path": str(markdown_path if markdown_path.exists() else json_path),
                        "json_path": str(json_path),
                        "name": markdown_path.name if markdown_path.exists() else json_path.name,
                        "date": str(data.get("date") or json_path.stem.removeprefix("summary_")),
                        "risk_label": str(data.get("risk_label") or "Unknown"),
                        "flow_count": int(data.get("flow_count") or 0),
                        "watchlist_hit_count": int(data.get("watchlist_hit_count") or 0),
                    }
                )
        event_reports: list[dict[str, Any]] = []
        filter_options = {"dates": [], "severities": [], "verdicts": [], "assets": []}
        if self.store is not None:
            event_reports = self.store.list_report_events(
                limit=_query_int(query, "limit", 250),
                date=filters["date"] or None,
                severity=filters["severity"] or None,
                verdict=filters["verdict"] or None,
                asset=filters["asset"] or None,
                watchlist_hit=filters["watchlist_hit"],
            )
            filter_options = self.store.get_report_filter_options()
        return self._json(
            200,
            {
                "filters": filters,
                "filter_options": filter_options,
                "daily_summaries": daily_summaries,
                "event_reports": event_reports,
            },
        )

    def _dashboard(self) -> ProductApiResponse:
        recent_response = self._recent_flows({"limit": ["100"]}).body
        source_response = self._source_input_status().body
        artifact_response = self._tier2_artifacts().body
        summary_response = self._latest_summary().body
        reports_response = self._reports({}).body
        events = recent_response.get("events", [])
        counters = _dashboard_counters(events)
        topology = build_topology_payload(self._source_snapshots(), events)
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
                "topology": topology,
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
            "source_input_dir": str(_product_runtime_dir(self.config_path) / "inputs"),
            "detector": self.settings.detector.provider,
            "tier1_provider": self.settings.tier1.llm.provider,
            "tier1_model": self.settings.tier1.llm.model,
            "tier1_ollama_url": self.settings.tier1.llm.ollama_url,
            "tier1_max_tokens": self.settings.tier1.llm.max_tokens,
            "tier1_retry_attempts": self.settings.tier1.llm.retry_attempts,
            "tier1_retry_backoff_seconds": self.settings.tier1.llm.retry_backoff_seconds,
            "tier1_queue_mode": self.settings.tier1.queue.mode,
            "tier1_queue_workers": self.settings.tier1.queue.workers,
            "tier1_queue_max_size": self.settings.tier1.queue.max_size,
            "tier1_queue_timeout": self.settings.tier1.queue.timeout_seconds,
            "tier1_queue_priority_policy": self.settings.tier1.queue.priority_policy,
            "tier1_queue": self._tier1_queue_status(),
            "tier2_provider": self.settings.tier2.provider,
            "tier2_model": self.settings.tier2.model,
            "tier2_ollama_url": self.settings.tier2.ollama_url,
            "tier2_max_tokens": self.settings.tier2.max_tokens,
            "gemini_api_key_env": self.settings.tier2.gemini_api_key_env,
            "gemini_has_key": _has_gemini_api_key(self.settings.tier2.gemini_api_key_env),
            "routing": {
                "threshold_low": self.settings.routing.threshold_low,
                "threshold_high": self.settings.routing.threshold_high,
                "priority_1_llm_threshold": self.settings.routing.priority_1_llm_threshold,
            },
            "realtime": {
                "activity_window_minutes": self.settings.realtime.activity_window_minutes,
            },
            "storage": storage_status,
            "artifacts": {
                "watchlist": self.settings.tier2.watchlist,
                "brief": self.settings.tier2.brief,
                "memory": self.settings.tier2.memory,
                "topology": str(_topology_artifact_paths(self.settings)[0]),
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
                activity_window_minutes=self.settings.realtime.activity_window_minutes,
                tier1_runtime=Tier1RuntimeInfo(
                    provider=self.settings.tier1.llm.provider,
                    model_name=_tier1_model_name(self.settings),
                    max_tokens=self.settings.tier1.llm.max_tokens,
                    retry_attempts=self.settings.tier1.llm.retry_attempts,
                    retry_backoff_seconds=self.settings.tier1.llm.retry_backoff_seconds,
                ),
            )
        return self._realtime

    def _tier1_work_queue(self, service: RealtimeIngestService) -> ProductTier1Queue:
        if self._tier1_queue is None or not self._tier1_queue.matches(self.settings):
            if self._tier1_queue is not None:
                self._tier1_queue.shutdown()
            self._tier1_queue = ProductTier1Queue(self.settings, service)
        return self._tier1_queue

    def _tier1_queue_status(self) -> dict[str, Any]:
        if self._tier1_queue is None:
            return ProductTier1Queue.empty_status(self.settings)
        return self._tier1_queue.status()

    def _reset_realtime_runtime(self) -> None:
        if self._tier1_queue is not None:
            self._tier1_queue.shutdown()
            self._tier1_queue = None
        self._realtime = None

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

    def _source_snapshots(self) -> list[Any]:
        return Tier2InputCollector(_raw_config(self.config_path)).collect()

    def _recent_events_for_topology(self) -> list[dict[str, Any]]:
        if self.store is None:
            return []
        return self.store.list_recent_flow_events(80)


class ProductTier1Queue:
    """Settings-driven Tier 1 worker queue for live Product API ingestion."""

    def __init__(self, settings: PipelineSettings, service: RealtimeIngestService) -> None:
        self._settings_key = _product_queue_config_key(settings)
        self._service = service
        self._workers = max(1, int(settings.tier1.queue.workers))
        self._timeout_seconds = float(settings.tier1.queue.timeout_seconds)
        self._call_limit = int(settings.tier1.queue.max_calls_per_run)
        self._priority_policy = settings.tier1.queue.priority_policy
        self._queue: queue.PriorityQueue[ProductTier1QueueItem] = queue.PriorityQueue(
            maxsize=max(1, int(settings.tier1.queue.max_size))
        )
        self._lock = threading.Lock()
        self._closed = False
        self._next_sequence = 0
        self._stats = _new_product_queue_stats(settings)
        self._threads = [
            threading.Thread(
                target=self._worker_loop,
                name=f"tier1-api-worker-{index + 1}",
                daemon=True,
            )
            for index in range(self._workers)
        ]
        for thread in self._threads:
            thread.start()

    def matches(self, settings: PipelineSettings) -> bool:
        return self._settings_key == _product_queue_config_key(settings)

    def submit(self, prepared: PreparedRealtimeFlow) -> bool:
        with self._lock:
            if self._closed:
                return False
            sequence = self._next_sequence
            self._next_sequence += 1
            job = ProductTier1Job(
                sequence=sequence,
                priority=_tier1_queue_priority(
                    sequence,
                    prepared.ml.prob,
                    prepared.match,
                    self._priority_policy,
                ),
                enqueued_at=time.perf_counter(),
                prepared=prepared,
            )
        try:
            self._queue.put_nowait((job.priority, job.sequence, job))
        except queue.Full:
            with self._lock:
                self._stats["tier1_overflow_count"] += 1
                _record_product_queue_fallback(self._stats)
            return False

        with self._lock:
            self._stats["tier1_queued"] += 1
            self._stats["current_queue_depth"] = self._queue.qsize()
            self._stats["max_queue_depth"] = max(
                int(self._stats["max_queue_depth"]),
                int(self._stats["current_queue_depth"]),
            )
        return True

    def status(self) -> dict[str, Any]:
        with self._lock:
            status = dict(self._stats)
            status["current_queue_depth"] = self._queue.qsize()
            return status

    def wait_until_idle(self, timeout_seconds: float = 2.0) -> bool:
        deadline = time.perf_counter() + max(0.0, timeout_seconds)
        while time.perf_counter() <= deadline:
            with self._lock:
                if (
                    int(self._stats["tier1_completed"]) >= int(self._stats["tier1_queued"])
                    and int(self._stats["current_active_workers"]) == 0
                ):
                    return True
            time.sleep(0.01)
        return False

    def shutdown(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        sentinel_priority = (float("inf"), float("inf"), 10**12)
        for worker_index in range(self._workers):
            item: ProductTier1QueueItem = (sentinel_priority, worker_index, None)
            try:
                self._queue.put_nowait(item)
            except queue.Full:
                threading.Thread(
                    target=self._queue.put,
                    args=(item,),
                    name=f"tier1-api-worker-stop-{worker_index + 1}",
                    daemon=True,
                ).start()

    @staticmethod
    def empty_status(settings: PipelineSettings) -> dict[str, Any]:
        return _new_product_queue_stats(settings)

    def _worker_loop(self) -> None:
        while True:
            _, _, job = self._queue.get()
            try:
                if job is None:
                    return
                self._process_job(job)
            finally:
                self._queue.task_done()

    def _process_job(self, job: ProductTier1Job) -> None:
        with self._lock:
            self._stats["current_active_workers"] += 1
            self._stats["current_queue_depth"] = self._queue.qsize()
        try:
            wait_ms = (time.perf_counter() - job.enqueued_at) * 1000
            with self._lock:
                self._stats["avg_wait_ms"] = _rolling_average(
                    float(self._stats["avg_wait_ms"]),
                    max(0, int(self._stats["tier1_completed"])),
                    wait_ms,
                )
                self._stats["max_wait_ms"] = max(float(self._stats["max_wait_ms"]), wait_ms)

            verdict = None
            if wait_ms > self._timeout_seconds * 1000:
                with self._lock:
                    self._stats["tier1_queue_timeouts"] += 1
                    _record_product_queue_fallback(self._stats)
                verdict = queue_fallback_verdict(
                    job.prepared.match,
                    f"Tier 1 queue wait exceeded {self._timeout_seconds:.1f}s.",
                )
            else:
                with self._lock:
                    if self._call_limit > 0 and self._stats["tier1_calls"] >= self._call_limit:
                        self._stats["tier1_skipped_by_call_limit"] += 1
                        _record_product_queue_fallback(self._stats)
                        verdict = queue_fallback_verdict(
                            job.prepared.match,
                            f"Tier 1 max calls per API run reached ({self._call_limit}).",
                        )
                    else:
                        self._stats["tier1_calls"] += 1

            if verdict is None:
                verdict = asyncio.run(self._service.judge_tier1(job.prepared))
                with self._lock:
                    _record_product_llm_fallback_if_needed(self._stats, verdict)

            self._service.complete(job.prepared, verdict, tier1_path=True)
        except Exception as exc:
            verdict = queue_fallback_verdict(
                job.prepared.match,
                f"Tier 1 queue worker failed: {type(exc).__name__}: {exc}",
            )
            try:
                self._service.complete(job.prepared, verdict, tier1_path=True)
            except Exception:
                pass
        finally:
            with self._lock:
                self._stats["tier1_completed"] += 1
                self._stats["current_active_workers"] -= 1
                self._stats["current_queue_depth"] = self._queue.qsize()


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
    if settings.tier1.llm.provider == "gemini":
        return GeminiProvider(
            model=settings.tier1.llm.model,
            api_key_env=settings.tier2.gemini_api_key_env,
            base_url=settings.tier2.gemini_api_base_url,
            timeout_seconds=settings.tier1.llm.timeout_seconds,
        )
    raise ValueError(f"unsupported Tier 1 provider: {settings.tier1.llm.provider}")


def _build_tier2_summary_provider(settings: PipelineSettings):
    if settings.tier2.provider in {"deterministic", "fake"}:
        return None
    if settings.tier2.provider == "ollama":
        return OllamaProvider(
            model=settings.tier2.model,
            base_url=settings.tier2.ollama_url,
            timeout_seconds=settings.tier2.timeout_seconds,
        )
    if settings.tier2.provider == "gemini":
        return GeminiProvider(
            model=settings.tier2.model,
            api_key_env=settings.tier2.gemini_api_key_env,
            base_url=settings.tier2.gemini_api_base_url,
            timeout_seconds=settings.tier2.timeout_seconds,
        )
    raise ValueError(f"unsupported Tier 2 provider: {settings.tier2.provider}")


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


def _query_str(query: dict[str, list[str]], key: str) -> str:
    values = query.get(key)
    return str(values[0]).strip() if values else ""


def _query_bool(query: dict[str, list[str]], key: str) -> bool | None:
    value = _query_str(query, key).lower()
    if value in {"1", "true", "yes", "hit"}:
        return True
    if value in {"0", "false", "no", "none"}:
        return False
    return None


def _report_filters(query: dict[str, list[str]]) -> dict[str, Any]:
    return {
        "date": _query_str(query, "date"),
        "severity": _query_str(query, "severity"),
        "verdict": _query_str(query, "verdict"),
        "asset": _query_str(query, "asset"),
        "watchlist_hit": _query_bool(query, "watchlist_hit"),
    }


def _latest_stored_flow_date(store: SQLiteEventStore | None) -> str | None:
    if store is None:
        return None
    try:
        dates = store.get_report_filter_options().get("dates") or []
    except Exception:
        return None
    values = [str(value) for value in dates if str(value)]
    return max(values) if values else None


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


def _topology_artifact_paths(settings: PipelineSettings) -> tuple[Path, Path]:
    output_dir = Path(_default_tier2_output_dir(settings))
    topology_dir = output_dir / "topology"
    return topology_dir / "latest.mmd", topology_dir / "latest.json"


def _json_artifact_payload(path: str | Path) -> dict[str, Any]:
    payload = _artifact_payload(path)
    payload["data"] = {}
    if payload["exists"] and payload["content"]:
        try:
            data = json.loads(str(payload["content"]))
        except json.JSONDecodeError as exc:
            payload["error"] = f"invalid JSON: {exc}"
        else:
            payload["data"] = data if isinstance(data, dict) else {}
    return payload


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


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


def _source_data_payload(snapshot: Any) -> dict[str, Any]:
    if snapshot is None or not str(snapshot.content or "").strip():
        return {}
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(snapshot.content)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _validate_yaml_mapping(content: str, name: str) -> None:
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(content) if content.strip() else {}
    except Exception as exc:
        raise ValueError(f"{name} YAML is invalid: {exc}") from exc
    if data is not None and not isinstance(data, dict):
        raise ValueError(f"{name} YAML root must be a mapping")


def _read_source_yaml_mapping(path: Path) -> dict[str, Any]:
    if not path.exists() or not path.read_text(encoding="utf-8").strip():
        return {}
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"source YAML is invalid: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError("source YAML root must be a mapping")
    return data


def _source_input_target_path(
    raw: dict[str, Any],
    config_path: Path,
    name: str,
) -> tuple[Path, bool]:
    tier2_config = raw.get("tier2") if isinstance(raw.get("tier2"), dict) else {}
    sources_config = (
        tier2_config.get("sources")
        if isinstance(tier2_config.get("sources"), dict)
        else {}
    )
    source_config = sources_config.get(name) if isinstance(sources_config.get(name), dict) else {}
    existing_path = str(source_config.get("path") or "").strip()
    if existing_path:
        return Path(existing_path), not bool(source_config.get("enabled", False))
    return _product_runtime_dir(config_path) / "inputs" / f"{name}.yaml", True


def _enable_source_path(raw: dict[str, Any], name: str, path: Path) -> None:
    tier2_config = raw.setdefault("tier2", {})
    if not isinstance(tier2_config, dict):
        tier2_config = {}
        raw["tier2"] = tier2_config
    sources_config = tier2_config.setdefault("sources", {})
    if not isinstance(sources_config, dict):
        sources_config = {}
        tier2_config["sources"] = sources_config
    source_config = sources_config.setdefault(name, {})
    if not isinstance(source_config, dict):
        source_config = {}
        sources_config[name] = source_config
    source_config["enabled"] = True
    source_config["path"] = str(path)


def _append_source_item(name: str, data: dict[str, Any], item: dict[str, Any]) -> None:
    clean_item = _clean_source_item(item)
    if not clean_item:
        raise ValueError("new source item is empty")

    if name == "organization":
        organization = data.setdefault("organization", {})
        if not isinstance(organization, dict):
            organization = {}
            data["organization"] = organization
        organization.update(clean_item)
        return

    list_key = {
        "assets": "assets",
        "policy": "policies",
        "cve_feed": "cves",
    }.get(name)
    if list_key:
        values = data.setdefault(list_key, [])
        if not isinstance(values, list):
            values = []
            data[list_key] = values
        values.append(clean_item)
        return

    if name == "threat_feed":
        list_key = "known_malicious_ips" if clean_item.get("ip") else "suspicious_patterns"
        values = data.setdefault(list_key, [])
        if not isinstance(values, list):
            values = []
            data[list_key] = values
        values.append(clean_item)
        return

    raise ValueError(f"unsupported source input: {name}")


def _delete_source_item(name: str, data: dict[str, Any], payload: dict[str, Any]) -> None:
    list_key = str(payload.get("list_key") or "").strip()
    try:
        index = int(payload.get("index"))
    except (TypeError, ValueError) as exc:
        raise ValueError("delete index must be an integer") from exc

    allowed = {
        "assets": {"assets"},
        "policy": {"policies", "elevated_risk_rules", "asset_specific_policies"},
        "cve_feed": {"cves", "advisories"},
        "threat_feed": {"known_malicious_ips", "suspicious_patterns", "custom_threat_context"},
    }.get(name, set())
    if list_key not in allowed:
        raise ValueError(f"delete is not supported for {name} list {list_key!r}")

    values = data.get(list_key)
    if not isinstance(values, list):
        raise ValueError(f"{list_key} is not a list")
    if index < 0 or index >= len(values):
        raise ValueError(f"delete index out of range for {list_key}")
    del values[index]


def _clean_source_item(item: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    list_fields = {"services", "affected_assets", "ports", "tags"}
    for key, value in item.items():
        if value in (None, ""):
            continue
        if key in list_fields:
            if isinstance(value, list):
                values = [str(part).strip() for part in value if str(part).strip()]
            else:
                values = [part.strip() for part in str(value).split(",") if part.strip()]
            if values:
                clean[key] = values
            continue
        clean[key] = value
    return clean


def _write_yaml(path: Path, data: dict[str, Any]) -> None:
    import yaml  # type: ignore

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def _product_runtime_dir(config_path: Path) -> Path:
    if config_path.name == "settings.active.yaml" and config_path.parent.name == "product_runtime":
        return config_path.parent
    return Path("output/product_runtime")


def _resolve_reset_config_path(config_path: Path) -> Path:
    if config_path.exists():
        return config_path
    if _DEFAULT_PRODUCT_CONFIG.exists():
        return _DEFAULT_PRODUCT_CONFIG
    return config_path


def _resolve_initial_product_config_path(config_path: Path) -> Path:
    if _is_default_product_config(config_path):
        active_config = _product_runtime_dir(config_path) / "settings.active.yaml"
        if active_config.exists():
            return active_config
    return config_path


def _is_default_product_config(config_path: Path) -> bool:
    normalized = config_path.as_posix().replace("\\", "/")
    default = _DEFAULT_PRODUCT_CONFIG.as_posix()
    return normalized == default or normalized.endswith(f"/{default}")


def _is_product_runtime_config(config_path: Path) -> bool:
    return config_path.name == "settings.active.yaml" and config_path.parent.name == "product_runtime"


def _clear_product_runtime_artifacts(settings: PipelineSettings, config_path: Path) -> dict[str, str]:
    removed: dict[str, str] = {}
    candidates: list[tuple[str, Path | None]] = [
        ("runtime", _runtime_reset_path_for(config_path)),
        ("watchlists", Path(settings.tier2.watchlist).parent),
        ("briefs", Path(settings.tier2.brief).parent),
        ("memory", Path(settings.tier2.memory).parent),
        ("topology", _topology_artifact_paths(settings)[0].parent),
        ("daily_summaries", Path("output/daily_summaries")),
    ]
    for label, path in candidates:
        if path is not None and _clear_resettable_path(path):
            removed[label] = str(path)
    return removed


def _runtime_reset_path_for(config_path: Path) -> Path | None:
    if _is_default_product_config(config_path) or _is_product_runtime_config(config_path):
        return _product_runtime_dir(config_path)
    return None


def _clear_resettable_path(path: Path) -> bool:
    if not path.exists():
        return False
    if not _is_resettable_output_path(path):
        raise ValueError(f"refusing to reset non-output path: {path}")
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()
    return True


def _is_resettable_output_path(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    if path.name.lower() == "output" or "models" in parts:
        return False
    return "output" in parts or path.name == "product_runtime" or path.parent.name == "product_runtime"


def _should_persist_runtime_config(config_path: Path, payload: dict[str, Any]) -> bool:
    if _is_product_runtime_config(config_path) or _is_default_product_config(config_path):
        return any(payload.get(key) not in (None, "") for key in _RUNTIME_CONFIG_OVERRIDE_KEYS)
    return False


def _persist_runtime_config(config_path: Path, settings: PipelineSettings) -> Path:
    raw = _raw_config(config_path)
    _sync_raw_config_with_settings(raw, settings)
    active_config_path = _product_runtime_dir(config_path) / "settings.active.yaml"
    _write_yaml(active_config_path, raw)
    return active_config_path


def _sync_raw_config_with_settings(raw: dict[str, Any], settings: PipelineSettings) -> None:
    raw["schema_version"] = settings.schema_version

    runtime = raw.setdefault("runtime", {})
    if isinstance(runtime, dict):
        runtime["input"] = settings.runtime.input
        runtime["output"] = settings.runtime.output

    storage = raw.setdefault("storage", {})
    if isinstance(storage, dict):
        storage["enabled"] = settings.storage.enabled
        storage["sqlite_path"] = settings.storage.sqlite_path

    routing = raw.setdefault("routing", {})
    if isinstance(routing, dict):
        routing["threshold_low"] = settings.routing.threshold_low
        routing["threshold_high"] = settings.routing.threshold_high
        routing["priority_1_llm_threshold"] = settings.routing.priority_1_llm_threshold

    realtime = raw.setdefault("realtime", {})
    if isinstance(realtime, dict):
        realtime["activity_window_minutes"] = settings.realtime.activity_window_minutes

    tier1 = raw.setdefault("tier1", {})
    if isinstance(tier1, dict):
        llm = tier1.setdefault("llm", {})
        if isinstance(llm, dict):
            llm["provider"] = settings.tier1.llm.provider
            llm["model"] = settings.tier1.llm.model
            llm["ollama_url"] = settings.tier1.llm.ollama_url
            llm["timeout_seconds"] = settings.tier1.llm.timeout_seconds
            llm["max_tokens"] = settings.tier1.llm.max_tokens
            llm["retry_attempts"] = settings.tier1.llm.retry_attempts
            llm["retry_backoff_seconds"] = settings.tier1.llm.retry_backoff_seconds
        tier1_queue = tier1.setdefault("queue", {})
        if isinstance(tier1_queue, dict):
            tier1_queue["mode"] = settings.tier1.queue.mode
            tier1_queue["workers"] = settings.tier1.queue.workers
            tier1_queue["max_size"] = settings.tier1.queue.max_size
            tier1_queue["timeout_seconds"] = settings.tier1.queue.timeout_seconds
            tier1_queue["overflow_policy"] = settings.tier1.queue.overflow_policy
            tier1_queue["priority_policy"] = settings.tier1.queue.priority_policy
            tier1_queue["max_calls_per_run"] = settings.tier1.queue.max_calls_per_run

    tier2 = raw.setdefault("tier2", {})
    if isinstance(tier2, dict):
        tier2["provider"] = settings.tier2.provider
        tier2["model"] = settings.tier2.model
        tier2["ollama_url"] = settings.tier2.ollama_url
        tier2["gemini_api_key_env"] = settings.tier2.gemini_api_key_env
        tier2["gemini_api_base_url"] = settings.tier2.gemini_api_base_url
        tier2["timeout_seconds"] = settings.tier2.timeout_seconds
        tier2["max_tokens"] = settings.tier2.max_tokens
        tier2["attack_surface_memory_max_chars"] = settings.tier2.attack_surface_memory_max_chars
        tier2["temperature"] = settings.tier2.temperature
        tier2["response_format"] = settings.tier2.response_format
        tier2["watchlist"] = settings.tier2.watchlist
        tier2["brief"] = settings.tier2.brief
        tier2["memory"] = settings.tier2.memory


def _ollama_catalog(configured_url: str) -> dict[str, Any]:
    candidates = _ollama_candidate_urls(configured_url)
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
    return _fetch_ollama_tags_with_timeout(base_url, timeout_seconds=0.25)


def _ollama_candidate_urls(configured_url: str) -> list[str]:
    normalized = _normalize_ollama_url_for_runtime(configured_url)
    return _unique_values(
        [
            normalized,
            configured_url,
            "http://host.docker.internal:11434",
            "http://localhost:11434",
            "http://127.0.0.1:11434",
        ]
    )


def _normalize_ollama_url_for_runtime(base_url: str) -> str:
    value = str(base_url or "http://localhost:11434").strip()
    if not _running_in_container():
        return value
    parsed = urlparse(value)
    if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        return value
    port = f":{parsed.port}" if parsed.port else ""
    scheme = parsed.scheme or "http"
    return f"{scheme}://host.docker.internal{port}"


def _running_in_container() -> bool:
    return Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()


def _fetch_ollama_tags_with_timeout(
    base_url: str,
    *,
    timeout_seconds: float,
) -> dict[str, Any]:
    url = f"{str(base_url).rstrip('/')}/api/tags"
    req = urlrequest.Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        with urlrequest.urlopen(req, timeout=timeout_seconds) as resp:
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


def _ensure_ollama_ready(scope: str, base_url: str, model: str) -> None:
    result = _fetch_ollama_tags_with_timeout(base_url, timeout_seconds=1.5)
    if not result["reachable"]:
        startup = _try_start_local_ollama(base_url)
        if startup["attempted"]:
            result = _fetch_ollama_tags_with_timeout(base_url, timeout_seconds=1.5)
        if result["reachable"]:
            result["startup"] = startup
        else:
            startup_error = startup.get("error")
            startup_hint = f" Auto-start failed: {startup_error}" if startup_error else ""
            error = result.get("error") or "unknown error"
            docker_hint = _ollama_docker_hint(base_url)
            raise ValueError(
                f"{scope} Ollama is not reachable at {base_url}. "
                f"{docker_hint}Start Ollama, fix the URL, or switch {scope} to a mock provider. "
                f"Last error: {error}.{startup_hint}"
            )

    models = [str(name) for name in result.get("models") or []]
    if model and models and model not in models:
        available = ", ".join(models[:8])
        suffix = "..." if len(models) > 8 else ""
        raise ValueError(
            f"{scope} Ollama model {model!r} is not installed at {base_url}. "
            f"Available models: {available}{suffix}"
        )

    preflight = _preflight_ollama_generate(base_url, model, timeout_seconds=90.0)
    if not preflight["ok"]:
        error = preflight.get("error") or "unknown error"
        raise ValueError(
            f"{scope} Ollama model {model!r} is installed but cannot run at {base_url}. "
            "Free system memory, choose a smaller model, or switch to a mock provider. "
            f"Last error: {error}"
        )


def _try_start_local_ollama(base_url: str) -> dict[str, Any]:
    parsed = urlparse(base_url)
    if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        return {
            "attempted": False,
            "reason": "configured URL is not local to this process",
        }

    ollama_exe = shutil.which("ollama")
    if not ollama_exe:
        return {
            "attempted": False,
            "reason": "ollama CLI not found in PATH",
        }

    try:
        subprocess.Popen(
            [ollama_exe, "serve"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )
    except OSError as exc:
        return {
            "attempted": True,
        "error": str(exc),
    }


def _ollama_docker_hint(base_url: str) -> str:
    parsed = urlparse(base_url)
    if _running_in_container() and parsed.hostname == "host.docker.internal":
        return "The API is running in Docker, so it can check the Windows host but cannot launch the Windows Ollama process. "
    return ""

    deadline = time.monotonic() + 25.0
    while time.monotonic() < deadline:
        time.sleep(1.0)
        result = _fetch_ollama_tags_with_timeout(base_url, timeout_seconds=1.5)
        if result["reachable"]:
            return {
                "attempted": True,
                "started": True,
            }
    return {
        "attempted": True,
        "error": "ollama serve did not become reachable within 25 seconds",
    }


def _set_gemini_api_key(primary_env: str, api_key: str) -> None:
    os.environ[primary_env] = api_key
    os.environ["GEMINI_API_KEY"] = api_key


def _has_gemini_api_key(primary_env: str) -> bool:
    return any(os.environ.get(env_name) for env_name in (primary_env, "GEMINI_API_KEY", "GOOGLE_API_KEY"))


def _gemini_api_key(primary_env: str) -> str:
    for env_name in (primary_env, "GEMINI_API_KEY", "GOOGLE_API_KEY"):
        api_key = os.environ.get(env_name)
        if api_key:
            return api_key
    raise ValueError(
        "Gemini API key is not set. "
        f"Set {primary_env}, GEMINI_API_KEY, or GOOGLE_API_KEY before applying this model."
    )


def _ensure_gemini_ready(scope: str, api_key_env: str, base_url: str) -> None:
    try:
        api_key = _gemini_api_key(api_key_env)
    except ValueError as exc:
        raise ValueError(f"{scope} {exc}") from exc
    preflight = _preflight_gemini_connection(base_url, api_key, timeout_seconds=8.0)
    if not preflight["ok"]:
        error = preflight.get("error") or "unknown error"
        raise ValueError(
            f"{scope} Gemini API key was provided, but the Gemini API is not reachable. "
            f"Last error: {error}"
        )


def _preflight_gemini_connection(
    base_url: str,
    api_key: str,
    *,
    timeout_seconds: float,
) -> dict[str, Any]:
    url = f"{str(base_url).rstrip('/')}/models"
    req = urlrequest.Request(
        url,
        headers={"Accept": "application/json", "x-goog-api-key": api_key},
        method="GET",
    )
    try:
        with urlrequest.urlopen(req, timeout=timeout_seconds) as resp:
            raw = resp.read().decode("utf-8")
    except urlerror.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        return {"ok": False, "error": f"HTTP {exc.code}: {detail}"}
    except (urlerror.URLError, TimeoutError, OSError) as exc:
        return {"ok": False, "error": str(exc)}

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"invalid JSON: {exc}"}
    if not isinstance(data, dict):
        return {"ok": False, "error": "unexpected response shape"}
    if data.get("error"):
        return {"ok": False, "error": str(data["error"])}
    return {"ok": True}


def _preflight_ollama_generate(
    base_url: str,
    model: str,
    *,
    timeout_seconds: float,
) -> dict[str, Any]:
    url = f"{str(base_url).rstrip('/')}/api/generate"
    payload = {
        "model": model,
        "prompt": "Reply with OK.",
        "stream": False,
        "options": {
            "temperature": 0,
            "num_predict": 1,
        },
        "keep_alive": "5m",
    }
    req = urlrequest.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urlrequest.urlopen(req, timeout=timeout_seconds) as resp:
            raw = resp.read().decode("utf-8")
    except urlerror.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        return {
            "ok": False,
            "url": base_url,
            "model": model,
            "error": f"HTTP {exc.code}: {detail}",
        }
    except (urlerror.URLError, TimeoutError, OSError) as exc:
        return {
            "ok": False,
            "url": base_url,
            "model": model,
            "error": str(exc),
        }

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {
            "ok": False,
            "url": base_url,
            "model": model,
            "error": f"invalid JSON: {exc}",
        }
    if not isinstance(data, dict):
        return {
            "ok": False,
            "url": base_url,
            "model": model,
            "error": "unexpected response shape",
        }
    if data.get("error"):
        return {
            "ok": False,
            "url": base_url,
            "model": model,
            "error": str(data["error"]),
        }
    return {
        "ok": True,
        "url": base_url,
        "model": str(data.get("model") or model),
    }


def _ollama_model_choices(
    catalog: dict[str, Any],
) -> list[dict[str, str]]:
    model_names = catalog.get("models") or []
    url = str(catalog.get("url") or "")
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


def _gemini_tier1_model_choices(current_model: str) -> list[dict[str, str]]:
    names = _unique_values(
        [
            current_model if current_model.startswith("gemma-4") else "",
            "gemma-4-26b-a4b-it",
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


def _product_queue_config_key(settings: PipelineSettings) -> tuple[Any, ...]:
    queue_settings = settings.tier1.queue
    llm_settings = settings.tier1.llm
    return (
        queue_settings.mode,
        int(queue_settings.workers),
        int(queue_settings.max_size),
        float(queue_settings.timeout_seconds),
        queue_settings.overflow_policy,
        queue_settings.priority_policy,
        int(queue_settings.max_calls_per_run),
        llm_settings.provider,
        llm_settings.model,
        llm_settings.ollama_url,
        float(llm_settings.timeout_seconds),
        int(llm_settings.max_tokens),
        int(llm_settings.retry_attempts),
        float(llm_settings.retry_backoff_seconds),
        settings.tier2.watchlist,
        settings.tier2.brief,
    )


def _new_product_queue_stats(settings: PipelineSettings) -> dict[str, Any]:
    return {
        "tier1_mode": settings.tier1.queue.mode,
        "tier1_workers": max(1, int(settings.tier1.queue.workers)),
        "tier1_queue_max_size": int(settings.tier1.queue.max_size),
        "tier1_queue_timeout": float(settings.tier1.queue.timeout_seconds),
        "tier1_overflow_policy": settings.tier1.queue.overflow_policy,
        "tier1_priority_policy": settings.tier1.queue.priority_policy,
        "tier1_max_calls_per_run": int(settings.tier1.queue.max_calls_per_run),
        "tier1_calls": 0,
        "tier1_queued": 0,
        "tier1_completed": 0,
        "tier1_fallbacks": 0,
        "tier1_queue_fallbacks": 0,
        "tier1_llm_fallbacks": 0,
        "tier1_queue_timeouts": 0,
        "tier1_overflow_count": 0,
        "tier1_skipped_by_call_limit": 0,
        "current_queue_depth": 0,
        "max_queue_depth": 0,
        "current_active_workers": 0,
        "avg_wait_ms": 0.0,
        "max_wait_ms": 0.0,
    }


def _record_product_queue_fallback(stats: dict[str, Any]) -> None:
    stats["tier1_fallbacks"] += 1
    stats["tier1_queue_fallbacks"] += 1


def _record_product_llm_fallback_if_needed(stats: dict[str, Any], verdict) -> None:
    if verdict.fallback_source == "llm":
        stats["tier1_fallbacks"] += 1
        stats["tier1_llm_fallbacks"] += 1


def _rolling_average(previous_average: float, previous_count: int, value: float) -> float:
    if previous_count <= 0:
        return value
    return ((previous_average * previous_count) + value) / (previous_count + 1)


def _tier1_queue_priority(
    original_index: int,
    ml_prob: float,
    match,
    priority_policy: str,
) -> tuple[float, float, int]:
    if priority_policy == "fifo":
        return (0.0, 0.0, original_index)

    watchlist_rank = (
        0.0
        if (
            match.matched
            and match.priority == "priority_1"
            and match.match_strength in REVIEWABLE_MATCH_STRENGTHS
            and match.trigger_matched
            and not match.context_only
        )
        else 1.0
    )
    return (watchlist_rank, -float(ml_prob), original_index)


def _dashboard_counters(events: list[dict[str, Any]]) -> dict[str, Any]:
    routes: dict[str, int] = {}
    verdicts: dict[str, int] = {}
    severities: dict[str, int] = {}
    watchlist_hits = 0
    fallbacks = 0
    pending_tier1 = 0
    for event in events:
        _increment(routes, event.get("route"))
        if event.get("processing_state") in {"tier1_processing", "tier1_queued"}:
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
