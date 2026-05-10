from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from soc.llm.provider import LLMProvider, LLMResponse
from soc.models import Tier1Input, Verdict


DEFAULT_SYSTEM_PROMPT = (
    "You are Tier 1 in a mini LLM SOC. Return only JSON with verdict, severity, "
    "rationale_ko, recommended_action_ko, and confidence."
)
VALID_VERDICTS = {"benign", "alert", "uncertain"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}


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
        return _fallback_verdict(
            tier1_input,
            "LLM JSON response parsing failed.",
            response=response,
        )

    return _verdict_from_data(data, tier1_input, response)


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


def _verdict_from_data(
    data: dict[str, Any],
    tier1_input: Tier1Input,
    response: LLMResponse,
) -> Verdict:
    verdict = str(data.get("verdict") or "").strip()
    severity = str(data.get("severity") or "").strip()
    if verdict not in VALID_VERDICTS:
        return _fallback_verdict(
            tier1_input,
            f"LLM verdict field is missing or invalid: {verdict!r}.",
            response=response,
        )
    if severity not in VALID_SEVERITIES:
        return _fallback_verdict(
            tier1_input,
            f"LLM severity field is missing or invalid: {severity!r}.",
            response=response,
        )

    try:
        confidence = float(data.get("confidence") or 0.5)
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))

    raw_verdict = Verdict(
        verdict=verdict,
        severity=severity,
        rationale_ko=str(
            data.get("rationale_ko")
            or "LLM 응답에 판단 근거가 없어 보수적으로 확인이 필요합니다."
        ),
        recommended_action_ko=str(
            data.get("recommended_action_ko") or "보안 담당자의 수동 검토가 필요합니다."
        ),
        watchlist_matched=tier1_input.watchlist_match.item_id,
        confidence=confidence,
        **_response_metadata(response),
    )
    return _apply_watchlist_only_guard(raw_verdict, tier1_input)


def _fallback_verdict(
    tier1_input: Tier1Input,
    reason: str,
    response: LLMResponse | None = None,
) -> Verdict:
    return Verdict(
        verdict="uncertain",
        severity="medium",
        rationale_ko=f"Tier 1 LLM 호출 또는 응답 처리에 실패했습니다. 원인: {reason}",
        recommended_action_ko=(
            "자동 판단 대신 보안 담당자가 flow, ML 근거, watchlist 매칭을 수동으로 확인하세요."
        ),
        watchlist_matched=tier1_input.watchlist_match.item_id,
        confidence=0.5,
        fallback_source="llm",
        fallback_reason=reason,
        **_response_metadata(response),
    )


def _apply_watchlist_only_guard(verdict: Verdict, tier1_input: Tier1Input) -> Verdict:
    match = tier1_input.watchlist_match
    route = tier1_input.route
    if verdict.verdict != "alert":
        return verdict
    if not route.adjusted_by_watchlist:
        return verdict
    if tier1_input.ml.prob >= route.threshold_low:
        return verdict
    if match.match_strength not in {"asset_only", "asset_service"}:
        return verdict

    rationale = (
        verdict.rationale_ko
        + " Watchlist-only alert downgraded: the watchlist match was scope/service context "
        "without a strong machine-readable behavior, threat-source, or policy trigger."
    )
    return Verdict(
        verdict="uncertain",
        severity="medium",
        rationale_ko=rationale,
        recommended_action_ko=verdict.recommended_action_ko,
        watchlist_matched=verdict.watchlist_matched,
        confidence=min(verdict.confidence, 0.5),
        fallback_source=verdict.fallback_source,
        fallback_reason=verdict.fallback_reason,
        llm_model_name=verdict.llm_model_name,
        llm_latency_ms=verdict.llm_latency_ms,
        llm_tokens_used=verdict.llm_tokens_used,
        llm_prompt_tokens=verdict.llm_prompt_tokens,
        llm_completion_tokens=verdict.llm_completion_tokens,
    )


def _response_metadata(response: LLMResponse | None) -> dict[str, Any]:
    if response is None:
        return {}
    return {
        "llm_model_name": response.model_name,
        "llm_latency_ms": response.latency_ms,
        "llm_tokens_used": response.tokens_used,
        "llm_prompt_tokens": response.prompt_tokens,
        "llm_completion_tokens": response.completion_tokens,
    }


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
            "category_confidence": tier1_input.ml.category_confidence,
            "shap_top5": tier1_input.ml.shap_top5,
        },
        "source_activity": asdict(tier1_input.source_activity),
        "watchlist_match": {
            "matched": tier1_input.watchlist_match.matched,
            "priority": tier1_input.watchlist_match.priority,
            "item_id": tier1_input.watchlist_match.item_id,
            "reason": tier1_input.watchlist_match.reason,
            "matched_conditions": tier1_input.watchlist_match.matched_conditions,
            "match_strength": tier1_input.watchlist_match.match_strength,
            "watchlist_scope_match": tier1_input.watchlist_match.scope_matched,
            "watchlist_trigger_match": tier1_input.watchlist_match.trigger_matched,
            "context_only": tier1_input.watchlist_match.context_only,
            "linter_warnings": tier1_input.watchlist_match.linter_warnings,
            "alert_when": tier1_input.watchlist_match.alert_when,
            "likely_benign_when": tier1_input.watchlist_match.likely_benign_when,
            "escalation_hint": tier1_input.watchlist_match.escalation_hint,
        },
        "brief_context_excerpt": tier1_input.brief_context_excerpt[:1200],
        "route": {
            "route": tier1_input.route.route,
            "reason": tier1_input.route.reason,
        },
    }
