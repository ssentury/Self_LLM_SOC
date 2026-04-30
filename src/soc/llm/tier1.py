from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from soc.llm.provider import LLMProvider
from soc.models import Tier1Input, Verdict


DEFAULT_SYSTEM_PROMPT = (
    "You are Tier 1 in a mini LLM SOC. Return only JSON with verdict, severity, "
    "rationale_ko, recommended_action_ko, and confidence."
)


async def judge_flow(tier1_input: Tier1Input, provider: LLMProvider) -> Verdict:
    try:
        response = await provider.generate(
            system_prompt=_load_system_prompt(),
            user_prompt=json.dumps(_to_prompt_payload(tier1_input), ensure_ascii=False),
            response_format="json",
        )
    except Exception as exc:
        return _fallback_verdict(tier1_input, f"LLM provider call failed: {exc}")

    data = _parse_json_object(response.content)
    if data is None:
        return _fallback_verdict(tier1_input, "LLM JSON response parsing failed.")

    return _verdict_from_data(data, tier1_input)


def _load_system_prompt() -> str:
    prompt_path = Path("prompts/tier1_system.md")
    if not prompt_path.exists():
        return DEFAULT_SYSTEM_PROMPT
    text = prompt_path.read_text(encoding="utf-8").strip()
    return text or DEFAULT_SYSTEM_PROMPT


def _parse_json_object(text: str) -> dict[str, Any] | None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None
        try:
            data = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None
    return data if isinstance(data, dict) else None


def _verdict_from_data(data: dict[str, Any], tier1_input: Tier1Input) -> Verdict:
    try:
        confidence = float(data.get("confidence") or 0.5)
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))

    return Verdict(
        verdict=str(data.get("verdict") or "uncertain"),
        severity=str(data.get("severity") or "medium"),
        rationale_ko=str(
            data.get("rationale_ko")
            or "LLM 응답에 판단 근거가 없어 보수적으로 확인이 필요합니다."
        ),
        recommended_action_ko=str(
            data.get("recommended_action_ko") or "보안 담당자의 수동 검토가 필요합니다."
        ),
        watchlist_matched=tier1_input.watchlist_match.item_id,
        confidence=confidence,
    )


def _fallback_verdict(tier1_input: Tier1Input, reason: str) -> Verdict:
    return Verdict(
        verdict="uncertain",
        severity="medium",
        rationale_ko=f"Tier 1 LLM 호출 또는 응답 처리에 실패했습니다. 원인: {reason}",
        recommended_action_ko=(
            "자동 판단 대신 보안 담당자가 flow, ML 근거, watchlist 매칭을 수동으로 확인하세요."
        ),
        watchlist_matched=tier1_input.watchlist_match.item_id,
        confidence=0.5,
    )


def _to_prompt_payload(tier1_input: Tier1Input) -> dict:
    return {
        "flow": {
            "flow_id": tier1_input.flow.flow_id,
            "src_ip": tier1_input.flow.src_ip,
            "dst_ip": tier1_input.flow.dst_ip,
            "src_port": tier1_input.flow.src_port,
            "dst_port": tier1_input.flow.dst_port,
            "protocol": tier1_input.flow.protocol,
        },
        "ml": {
            "prob": tier1_input.ml.prob,
            "category_hint": tier1_input.ml.category_hint,
            "shap_top5": tier1_input.ml.shap_top5,
        },
        "source_activity": tier1_input.source_activity.summary_ko,
        "watchlist_match": {
            "matched": tier1_input.watchlist_match.matched,
            "priority": tier1_input.watchlist_match.priority,
            "item_id": tier1_input.watchlist_match.item_id,
            "reason": tier1_input.watchlist_match.reason,
            "matched_conditions": tier1_input.watchlist_match.matched_conditions,
        },
        "brief_context_excerpt": tier1_input.brief_context_excerpt[:1200],
        "route": {
            "route": tier1_input.route.route,
            "reason": tier1_input.route.reason,
        },
    }
