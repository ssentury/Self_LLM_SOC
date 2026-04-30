from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RuntimeSettings:
    input: str = "data/sample/flows.csv"
    output: str = "output/reports"


@dataclass(frozen=True)
class DetectorSettings:
    provider: str = "dummy"
    model: str = "output/models/xgb_binary_v1.json"
    metadata: str = "output/models/xgb_binary_v1_metadata.json"
    thresholds: str = "output/models/xgb_binary_v1_thresholds_routing_default.json"


@dataclass(frozen=True)
class Tier1LLMSettings:
    provider: str = "fake"
    model: str = "gemma4:e4b"
    ollama_url: str = "http://localhost:11434"
    timeout_seconds: float = 180.0


@dataclass(frozen=True)
class Tier1QueueSettings:
    mode: str = "sequential"
    workers: int = 1
    max_size: int = 100
    timeout_seconds: float = 300.0
    overflow_policy: str = "fallback"
    priority_policy: str = "watchlist_first"
    max_calls_per_run: int = 0


@dataclass(frozen=True)
class Tier1Settings:
    llm: Tier1LLMSettings = field(default_factory=Tier1LLMSettings)
    queue: Tier1QueueSettings = field(default_factory=Tier1QueueSettings)


@dataclass(frozen=True)
class Tier2Settings:
    provider: str = "fake"
    model: str = "fake-tier2"
    watchlist: str = "output/watchlists/latest.yaml"
    brief: str = "output/briefs/latest.md"
    memory: str = "output/memory/latest.md"


@dataclass(frozen=True)
class RoutingSettings:
    threshold_low: float = 0.30
    threshold_high: float = 0.95
    priority_1_llm_threshold: float = 0.20


@dataclass(frozen=True)
class PipelineSettings:
    schema_version: int = 1
    runtime: RuntimeSettings = field(default_factory=RuntimeSettings)
    detector: DetectorSettings = field(default_factory=DetectorSettings)
    tier1: Tier1Settings = field(default_factory=Tier1Settings)
    tier2: Tier2Settings = field(default_factory=Tier2Settings)
    routing: RoutingSettings = field(default_factory=RoutingSettings)


def load_pipeline_settings(path: str | Path | None = None) -> PipelineSettings:
    settings = PipelineSettings()
    if path is None:
        return settings

    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"settings file not found: {config_path}")
    data = _load_yaml(config_path)
    if data is None:
        return settings
    if not isinstance(data, dict):
        raise ValueError(f"settings file must contain a mapping: {config_path}")
    return _settings_from_dict(data)


def apply_pipeline_overrides(settings: PipelineSettings, overrides: dict[str, Any]) -> PipelineSettings:
    runtime = settings.runtime
    detector = settings.detector
    tier1_llm = settings.tier1.llm
    tier1_queue = settings.tier1.queue
    tier2 = settings.tier2

    if overrides.get("input") is not None:
        runtime = replace(runtime, input=overrides["input"])
    if overrides.get("output") is not None:
        runtime = replace(runtime, output=overrides["output"])

    if overrides.get("detector") is not None:
        detector = replace(detector, provider=overrides["detector"])
    if overrides.get("model") is not None:
        detector = replace(detector, model=overrides["model"])
    if overrides.get("metadata") is not None:
        detector = replace(detector, metadata=overrides["metadata"])
    if overrides.get("thresholds") is not None:
        detector = replace(detector, thresholds=overrides["thresholds"])

    if overrides.get("llm") is not None:
        tier1_llm = replace(tier1_llm, provider=overrides["llm"])
    if overrides.get("llm_model") is not None:
        tier1_llm = replace(tier1_llm, model=overrides["llm_model"])
    if overrides.get("ollama_url") is not None:
        tier1_llm = replace(tier1_llm, ollama_url=overrides["ollama_url"])
    if overrides.get("ollama_timeout") is not None:
        tier1_llm = replace(tier1_llm, timeout_seconds=float(overrides["ollama_timeout"]))

    if overrides.get("tier1_mode") is not None:
        tier1_queue = replace(tier1_queue, mode=overrides["tier1_mode"])
    if overrides.get("tier1_workers") is not None:
        tier1_queue = replace(tier1_queue, workers=int(overrides["tier1_workers"]))
    if overrides.get("tier1_queue_max_size") is not None:
        tier1_queue = replace(tier1_queue, max_size=int(overrides["tier1_queue_max_size"]))
    if overrides.get("tier1_queue_timeout") is not None:
        tier1_queue = replace(tier1_queue, timeout_seconds=float(overrides["tier1_queue_timeout"]))
    if overrides.get("tier1_overflow_policy") is not None:
        tier1_queue = replace(tier1_queue, overflow_policy=overrides["tier1_overflow_policy"])
    if overrides.get("tier1_priority_policy") is not None:
        tier1_queue = replace(tier1_queue, priority_policy=overrides["tier1_priority_policy"])
    if overrides.get("tier1_max_calls_per_run") is not None:
        tier1_queue = replace(
            tier1_queue,
            max_calls_per_run=int(overrides["tier1_max_calls_per_run"]),
        )

    if overrides.get("watchlist") is not None:
        tier2 = replace(tier2, watchlist=overrides["watchlist"])
    if overrides.get("brief") is not None:
        tier2 = replace(tier2, brief=overrides["brief"])

    return replace(
        settings,
        runtime=runtime,
        detector=detector,
        tier1=replace(settings.tier1, llm=tier1_llm, queue=tier1_queue),
        tier2=tier2,
    )


def validate_pipeline_settings(settings: PipelineSettings) -> None:
    _validate_choice(settings.detector.provider, {"dummy", "xgboost"}, "detector.provider")
    _validate_choice(settings.tier1.llm.provider, {"fake", "ollama"}, "tier1.llm.provider")
    _validate_choice(settings.tier1.queue.mode, {"sequential", "queue"}, "tier1.queue.mode")
    _validate_choice(
        settings.tier1.queue.overflow_policy,
        {"fallback"},
        "tier1.queue.overflow_policy",
    )
    _validate_choice(
        settings.tier1.queue.priority_policy,
        {"fifo", "watchlist_first"},
        "tier1.queue.priority_policy",
    )
    if settings.tier1.queue.workers < 1:
        raise ValueError("tier1.queue.workers must be >= 1")
    if settings.tier1.queue.max_size < 1:
        raise ValueError("tier1.queue.max_size must be >= 1")
    if settings.tier1.queue.timeout_seconds < 0:
        raise ValueError("tier1.queue.timeout_seconds must be >= 0")
    if settings.tier1.queue.max_calls_per_run < 0:
        raise ValueError("tier1.queue.max_calls_per_run must be >= 0")


def _settings_from_dict(data: dict[str, Any]) -> PipelineSettings:
    runtime_data = _mapping(data.get("runtime"))
    detector_data = _mapping(data.get("detector"))
    tier1_data = _mapping(data.get("tier1"))
    tier1_llm_data = _mapping(tier1_data.get("llm"))
    tier1_queue_data = _mapping(tier1_data.get("queue"))
    tier2_data = _mapping(data.get("tier2"))
    routing_data = _mapping(data.get("routing"))

    return PipelineSettings(
        schema_version=int(data.get("schema_version", 1)),
        runtime=RuntimeSettings(
            input=str(runtime_data.get("input", RuntimeSettings.input)),
            output=str(runtime_data.get("output", RuntimeSettings.output)),
        ),
        detector=DetectorSettings(
            provider=str(detector_data.get("provider", DetectorSettings.provider)),
            model=str(detector_data.get("model", DetectorSettings.model)),
            metadata=str(detector_data.get("metadata", DetectorSettings.metadata)),
            thresholds=str(detector_data.get("thresholds", DetectorSettings.thresholds)),
        ),
        tier1=Tier1Settings(
            llm=Tier1LLMSettings(
                provider=str(tier1_llm_data.get("provider", Tier1LLMSettings.provider)),
                model=str(tier1_llm_data.get("model", Tier1LLMSettings.model)),
                ollama_url=str(tier1_llm_data.get("ollama_url", Tier1LLMSettings.ollama_url)),
                timeout_seconds=float(
                    tier1_llm_data.get("timeout_seconds", Tier1LLMSettings.timeout_seconds)
                ),
            ),
            queue=Tier1QueueSettings(
                mode=str(tier1_queue_data.get("mode", Tier1QueueSettings.mode)),
                workers=int(tier1_queue_data.get("workers", Tier1QueueSettings.workers)),
                max_size=int(tier1_queue_data.get("max_size", Tier1QueueSettings.max_size)),
                timeout_seconds=float(
                    tier1_queue_data.get("timeout_seconds", Tier1QueueSettings.timeout_seconds)
                ),
                overflow_policy=str(
                    tier1_queue_data.get("overflow_policy", Tier1QueueSettings.overflow_policy)
                ),
                priority_policy=str(
                    tier1_queue_data.get("priority_policy", Tier1QueueSettings.priority_policy)
                ),
                max_calls_per_run=int(
                    tier1_queue_data.get(
                        "max_calls_per_run",
                        Tier1QueueSettings.max_calls_per_run,
                    )
                ),
            ),
        ),
        tier2=Tier2Settings(
            provider=str(tier2_data.get("provider", Tier2Settings.provider)),
            model=str(tier2_data.get("model", Tier2Settings.model)),
            watchlist=str(tier2_data.get("watchlist", Tier2Settings.watchlist)),
            brief=str(tier2_data.get("brief", Tier2Settings.brief)),
            memory=str(tier2_data.get("memory", Tier2Settings.memory)),
        ),
        routing=RoutingSettings(
            threshold_low=float(routing_data.get("threshold_low", RoutingSettings.threshold_low)),
            threshold_high=float(routing_data.get("threshold_high", RoutingSettings.threshold_high)),
            priority_1_llm_threshold=float(
                routing_data.get(
                    "priority_1_llm_threshold",
                    RoutingSettings.priority_1_llm_threshold,
                )
            ),
        ),
    )


def _load_yaml(path: Path) -> Any:
    try:
        import yaml  # type: ignore
    except ImportError as exc:
        return _load_simple_yaml(path.read_text(encoding="utf-8"), path, exc)
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _load_simple_yaml(text: str, path: Path, original_error: ImportError) -> Any:
    """Small fallback for the project's simple settings YAML.

    It supports nested mappings with scalar values. PyYAML remains the preferred
    parser for comments, lists, anchors, and richer YAML syntax.
    """

    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if "\t" in raw_line:
            raise RuntimeError(
                f"PyYAML is required for tabs in settings file {path}:{line_number}"
            ) from original_error
        indent = len(line) - len(line.lstrip(" "))
        content = line.strip()
        if ":" not in content:
            raise RuntimeError(
                f"PyYAML is required for this settings syntax at {path}:{line_number}"
            ) from original_error
        key, value = content.split(":", 1)
        key = key.strip()
        value = value.strip()
        while indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if not value:
            child: dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            parent[key] = _parse_simple_yaml_scalar(value)
    return root


def _parse_simple_yaml_scalar(value: str) -> Any:
    value = value.strip()
    if value in {"null", "Null", "NULL", "~"}:
        return None
    if value in {"true", "True", "TRUE"}:
        return True
    if value in {"false", "False", "FALSE"}:
        return False
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def _mapping(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"settings section must be a mapping, got {type(value).__name__}")
    return value


def _validate_choice(value: str, choices: set[str], field: str) -> None:
    if value not in choices:
        raise ValueError(f"{field} must be one of {sorted(choices)}, got {value!r}")
