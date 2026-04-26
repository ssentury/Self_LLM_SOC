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
            f"{escape(str(item['severity']))}</li>"
            for item in summary_data.get("events", [])
        )
        path.write_text(
            "<!doctype html><html><head><meta charset='utf-8'><title>Mini SOC Summary</title>"
            "<style>body{font-family:Arial,sans-serif;line-height:1.5;margin:32px}</style></head>"
            f"<body><h1>Mini SOC Summary</h1><ul>{rows}</ul></body></html>",
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
        f"<p><strong>Flow:</strong> <code>{escape(str(event['src_ip']))}:{escape(str(event['src_port']))}"
        f" -> {escape(str(event['dst_ip']))}:{escape(str(event['dst_port']))}</code></p>"
        f"<p><strong>Reason:</strong> {escape(str(event['rationale_ko']))}</p>"
        f"<p><strong>Action:</strong> {escape(str(event['recommended_action_ko']))}</p>"
        f"<p><strong>Watchlist:</strong> {escape(str(event.get('watchlist_matched') or 'none'))}</p>"
        "</body></html>"
    )
