from __future__ import annotations

import json

from soc.llm.provider import LLMProvider
from soc.models import Tier1Input, Verdict


SYSTEM_PROMPT = (
    "You are Tier 1 in a mini LLM SOC. Return only JSON with verdict, severity, "
    "rationale_ko, recommended_action_ko, and confidence."
)


async def judge_flow(tier1_input: Tier1Input, provider: LLMProvider) -> Verdict:
    response = await provider.generate(
        system_prompt=SYSTEM_PROMPT,
        user_prompt=json.dumps(_to_prompt_payload(tier1_input), ensure_ascii=False),
        response_format="json",
    )
    try:
        data = json.loads(response.content)
    except json.JSONDecodeError:
        data = {}
    return Verdict(
        verdict=str(data.get("verdict") or "uncertain"),
        severity=str(data.get("severity") or "medium"),
        rationale_ko=str(data.get("rationale_ko") or "LLM 응답 파싱에 실패했습니다."),
        recommended_action_ko=str(data.get("recommended_action_ko") or "수동 검토가 필요합니다."),
        watchlist_matched=tier1_input.watchlist_match.item_id,
        confidence=float(data.get("confidence") or 0.5),
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
