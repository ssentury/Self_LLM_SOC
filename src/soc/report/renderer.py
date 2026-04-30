from __future__ import annotations

from abc import ABC, abstractmethod
from html import escape
from pathlib import Path
from typing import Any


class ReportRenderer(ABC):
    @abstractmethod
    def render_event(self, event: dict[str, Any], output_path: str | Path) -> None:
        raise NotImplementedError

    @abstractmethod
    def render_summary(self, summary_data: dict[str, Any], output_path: str | Path) -> None:
        raise NotImplementedError


class HTMLRenderer(ReportRenderer):
    def render_event(self, event: dict[str, Any], output_path: str | Path) -> None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_event_html(event), encoding="utf-8")

    def render_summary(self, summary_data: dict[str, Any], output_path: str | Path) -> None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        rows = "\n".join(
            f"<li>{escape(str(item['flow_id']))}: {escape(str(item['verdict']))} / "
            f"{escape(str(item['severity']))} "
            f"({escape(str(item.get('route', 'unknown')))}, "
            f"prob={_format_prob(item.get('ml_prob'))})</li>"
            for item in summary_data.get("events", [])
        )
        queue_html = _queue_summary_html(summary_data.get("tier1_queue") or {})
        path.write_text(
            "<!doctype html><html><head><meta charset='utf-8'><title>Mini SOC Summary</title>"
            "<style>body{font-family:Arial,sans-serif;line-height:1.5;margin:32px}</style></head>"
            f"<body><h1>Mini SOC Summary</h1>{queue_html}<ul>{rows}</ul></body></html>",
            encoding="utf-8",
        )


def _event_html(event: dict[str, Any]) -> str:
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>Flow {escape(str(event['flow_id']))}</title>"
        "<style>body{font-family:Arial,sans-serif;line-height:1.5;margin:32px}"
        "code{background:#f4f4f4;padding:2px 4px}</style></head><body>"
        f"<h1>Flow {escape(str(event['flow_id']))}</h1>"
        f"<p><strong>Verdict:</strong> {escape(str(event['verdict']))} / {escape(str(event['severity']))}</p>"
        f"<p><strong>Route:</strong> {escape(str(event['route']))}</p>"
        f"<p><strong>ML probability:</strong> {escape(_format_prob(event.get('ml_prob')))}</p>"
        f"{_shap_html(event.get('shap_top5') or [])}"
        f"<p><strong>Flow:</strong> <code>{escape(str(event['src_ip']))}:{escape(str(event['src_port']))}"
        f" -> {escape(str(event['dst_ip']))}:{escape(str(event['dst_port']))}</code></p>"
        f"<p><strong>Reason:</strong> {escape(str(event['rationale_ko']))}</p>"
        f"<p><strong>Action:</strong> {escape(str(event['recommended_action_ko']))}</p>"
        f"<p><strong>Watchlist:</strong> {escape(str(event.get('watchlist_matched') or 'none'))}</p>"
        "</body></html>"
    )


def _format_prob(value: Any) -> str:
    if value is None:
        return "n/a"
    return f"{float(value):.6f}"


def _shap_html(shap_top5: list[tuple[str, float, float]]) -> str:
    if not shap_top5:
        return "<p><strong>SHAP top5:</strong> n/a</p>"
    rows = "".join(
        "<li>"
        f"{escape(str(feature))}: value={escape(_format_prob(value))}, "
        f"contribution={escape(_format_prob(contribution))}"
        "</li>"
        for feature, value, contribution in shap_top5
    )
    return f"<p><strong>SHAP top5:</strong></p><ol>{rows}</ol>"


def _queue_summary_html(stats: dict[str, Any]) -> str:
    if not stats:
        return ""
    keys = [
        "tier1_mode",
        "tier1_workers",
        "tier1_queued",
        "tier1_calls",
        "tier1_fallbacks",
        "tier1_queue_fallbacks",
        "tier1_llm_fallbacks",
        "tier1_queue_timeouts",
        "tier1_overflow_count",
        "tier1_skipped_by_call_limit",
        "avg_wait_ms",
        "max_wait_ms",
    ]
    rows = "".join(
        f"<li>{escape(key)}: {escape(_format_stat(stats.get(key)))}</li>"
        for key in keys
        if key in stats
    )
    return f"<h2>Tier 1 Queue</h2><ul>{rows}</ul>"


def _format_stat(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.2f}"
    return str(value)
