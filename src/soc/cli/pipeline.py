from __future__ import annotations

import argparse
import asyncio
from dataclasses import replace
import json
from pathlib import Path

from soc.context.activity import summarize_source_activity
from soc.context.watchlist import load_watchlist, match_watchlist
from soc.io import read_flows_csv
from soc.llm.provider import FakeLLMProvider
from soc.llm.tier1 import judge_flow
from soc.ml.detector import DummyDetector, MLDetector, XGBoostDetector
from soc.ml.features import build_ml_feature_dict
from soc.models import Tier1Input, Verdict
from soc.report.renderer import HTMLRenderer
from soc.routing.router import route_flow


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the mini LLM SOC real-time loop scaffold.")
    parser.add_argument("--input", required=True, help="Input flow CSV path.")
    parser.add_argument("--output", required=True, help="Report output directory.")
    parser.add_argument("--detector", default="dummy", choices=["dummy", "xgboost"])
    parser.add_argument("--model", default="output/models/xgb_binary_v1.json")
    parser.add_argument("--metadata", default="output/models/xgb_binary_v1_metadata.json")
    parser.add_argument(
        "--thresholds",
        default="output/models/xgb_binary_v1_thresholds_routing_default.json",
    )
    parser.add_argument("--llm", default="fake", choices=["fake"])
    parser.add_argument("--watchlist", default="output/watchlists/latest.yaml")
    parser.add_argument("--brief", default="output/briefs/latest.md")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    asyncio.run(_run(args))
    return 0


async def _run(args: argparse.Namespace) -> None:
    flows = read_flows_csv(args.input)
    detector = _build_detector(args)
    threshold_low, threshold_high = _load_thresholds(args.thresholds)
    provider = FakeLLMProvider()
    renderer = HTMLRenderer()
    watchlist = load_watchlist(args.watchlist)
    brief = _read_optional_text(args.brief)
    output_dir = Path(args.output)
    events: list[dict] = []
    previous_flows = []

    for flow in flows:
        ml_features = build_ml_feature_dict(flow)
        ml = detector.predict(ml_features)
        match = match_watchlist(flow, watchlist)
        route = route_flow(
            ml,
            match,
            threshold_low=threshold_low,
            threshold_high=threshold_high,
        )
        if route.route == "tier1_llm":
            ml = replace(ml, shap_top5=detector.explain(ml_features))
        else:
            ml = replace(ml, shap_top5=[])
        activity = summarize_source_activity(flow, previous_flows)

        if route.route == "auto_dismiss":
            verdict = Verdict(
                verdict="benign",
                severity="low",
                rationale_ko="ML 확률이 낮아 자동 기각했습니다.",
                recommended_action_ko="추가 조치 없이 모니터링합니다.",
                confidence=0.8,
            )
        elif route.route == "auto_alert":
            verdict = Verdict(
                verdict="alert",
                severity="high",
                rationale_ko="ML 확률이 높아 자동 경보로 분류했습니다.",
                recommended_action_ko="보안 담당자가 즉시 대상 자산과 출발지를 확인하세요.",
                confidence=0.8,
            )
        else:
            verdict = await judge_flow(
                Tier1Input(
                    flow=flow,
                    ml=ml,
                    source_activity=activity,
                    watchlist_match=match,
                    brief_context_excerpt=brief,
                    route=route,
                ),
                provider,
            )

        event = {
            "flow_id": flow.flow_id,
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "route": route.route,
            "ml_prob": ml.prob,
            "shap_top5": ml.shap_top5,
            "verdict": verdict.verdict,
            "severity": verdict.severity,
            "rationale_ko": verdict.rationale_ko,
            "recommended_action_ko": verdict.recommended_action_ko,
            "watchlist_matched": verdict.watchlist_matched or match.item_id,
        }
        renderer.render_event(event, output_dir / f"{flow.flow_id}.html")
        events.append(event)
        previous_flows.append(flow)

    renderer.render_summary({"events": events}, output_dir / "summary.html")
    print(f"processed={len(events)} reports={output_dir}")


def _build_detector(args: argparse.Namespace) -> MLDetector:
    if args.detector == "dummy":
        return DummyDetector()
    if args.detector == "xgboost":
        return XGBoostDetector(args.model, args.metadata)
    raise ValueError(f"unsupported detector: {args.detector}")


def _load_thresholds(path: str | Path) -> tuple[float, float]:
    threshold_path = Path(path)
    if not threshold_path.exists():
        return 0.30, 0.95
    data = json.loads(threshold_path.read_text(encoding="utf-8"))
    return float(data["low_threshold"]), float(data["high_threshold"])


def _read_optional_text(path: str | Path) -> str:
    file_path = Path(path)
    if not file_path.exists():
        return ""
    return file_path.read_text(encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
