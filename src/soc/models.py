from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Flow:
    flow_id: str
    start_ms: int | None
    end_ms: int | None
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    features: dict[str, Any] = field(default_factory=dict)
    raw_label: str | None = None
    raw_attack: str | None = None


@dataclass(frozen=True)
class MLResult:
    prob: float
    category_hint: str
    category_confidence: float
    shap_top5: list[tuple[str, float, float]] = field(default_factory=list)


@dataclass(frozen=True)
class SourceActivitySummary:
    window_minutes: int
    flow_count: int
    distinct_dst_count: int
    top_dst_ports: list[int]
    recent_verdicts: list[str]
    summary_ko: str


@dataclass(frozen=True)
class WatchlistMatch:
    matched: bool
    priority: str | None = None
    item_id: str | None = None
    reason: str | None = None
    matched_conditions: list[str] = field(default_factory=list)
    escalation_hint: str | None = None


@dataclass(frozen=True)
class RouteDecision:
    route: str
    reason: str
    threshold_low: float
    threshold_high: float
    adjusted_by_watchlist: bool
    ml_prob: float


@dataclass(frozen=True)
class Tier1Input:
    flow: Flow
    ml: MLResult
    source_activity: SourceActivitySummary
    watchlist_match: WatchlistMatch
    brief_context_excerpt: str
    route: RouteDecision


@dataclass(frozen=True)
class Verdict:
    verdict: str
    severity: str
    rationale_ko: str
    recommended_action_ko: str
    watchlist_matched: str | None = None
    confidence: float = 0.5
    fallback_source: str | None = None
    fallback_reason: str | None = None
    llm_model_name: str | None = None
    llm_latency_ms: float | None = None
    llm_tokens_used: int | None = None
    llm_prompt_tokens: int | None = None
    llm_completion_tokens: int | None = None


@dataclass(frozen=True)
class Tier2Output:
    cycle_id: str
    watchlist: dict[str, Any]
    brief_context: str
    attack_surface_memory: str
    summary_html: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SourceSnapshot:
    name: str
    status: str  # "used", "missing", "disabled", "error"
    source_type: str  # "yaml", "db", "api"
    path_or_uri: str | None
    item_count: int
    content: str
    error: str | None = None
