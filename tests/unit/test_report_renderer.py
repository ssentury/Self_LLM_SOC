from pathlib import Path

from soc.report.renderer import HTMLRenderer


def test_event_report_renders_category_hint(tmp_path: Path) -> None:
    output_path = tmp_path / "event.html"

    HTMLRenderer().render_event(
        {
            "flow_id": "flow-1",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 40000,
            "dst_port": 443,
            "route": "tier1_llm",
            "ml_prob": 0.6,
            "category_hint": "WebAttack",
            "category_confidence": 0.87,
            "shap_top5": [],
            "verdict": "uncertain",
            "severity": "medium",
            "rationale_ko": "review",
            "recommended_action_ko": "check",
            "watchlist_matched": None,
        },
        output_path,
    )

    html = output_path.read_text(encoding="utf-8")
    assert "Category hint:</strong> WebAttack" in html
    assert "87.0% confidence" in html
