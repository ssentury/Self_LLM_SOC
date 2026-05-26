from __future__ import annotations

import asyncio
import json
import ipaddress
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
DEFAULT_MAX_TOKENS = 4096
DEFAULT_RETRY_ATTEMPTS = 1
DEFAULT_RETRY_BACKOFF_SECONDS = 2.0


async def judge_flow(
    tier1_input: Tier1Input,
    provider: LLMProvider,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    retry_attempts: int = DEFAULT_RETRY_ATTEMPTS,
    retry_backoff_seconds: float = DEFAULT_RETRY_BACKOFF_SECONDS,
) -> Verdict:
    system_prompt = _load_system_prompt()
    user_prompt = json.dumps(_to_prompt_payload(tier1_input), ensure_ascii=False)
    max_attempts = max(1, int(retry_attempts) + 1)
    retry_backoff_seconds = max(0.0, float(retry_backoff_seconds))

    response: LLMResponse | None = None
    for attempt_index in range(max_attempts):
        try:
            response = await provider.generate(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
                response_format="json",
            )
            break
        except Exception as exc:
            attempts_made = attempt_index + 1
            if attempts_made >= max_attempts or not _is_retryable_provider_error(exc):
                return _fallback_verdict(
                    tier1_input,
                    _provider_failure_reason(exc, attempts_made),
                )
            delay = retry_backoff_seconds * (2**attempt_index)
            if delay > 0:
                await asyncio.sleep(delay)
    if response is None:
        return _fallback_verdict(tier1_input, "LLM provider call failed without a response.")

    data = _parse_json_object(response.content)
    if data is None:
        return _fallback_verdict(
            tier1_input,
            "LLM JSON response parsing failed.",
            response=response,
        )

    return _verdict_from_data(data, tier1_input, response)


def _is_retryable_provider_error(exc: Exception) -> bool:
    text = f"{type(exc).__name__}: {exc}".lower()
    if "finishreason=max_tokens" in text or "max_tokens" in text:
        return False
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return True
    retry_markers = (
        "timed out",
        "timeout",
        "connection reset",
        "connection aborted",
        "remote end closed",
        "temporarily unavailable",
        "resource_exhausted",
        "rate limit",
        "http 408",
        "http 409",
        "http 425",
        "http 429",
        "http 500",
        "http 502",
        "http 503",
        "http 504",
    )
    return any(marker in text for marker in retry_markers)


def _provider_failure_reason(exc: Exception, attempts_made: int) -> str:
    if attempts_made > 1:
        return f"LLM provider call failed after {attempts_made} attempts: {exc}"
    return f"LLM provider call failed: {exc}"


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
        return _parse_embedded_json_object(text)
    return data if isinstance(data, dict) else None


def _parse_embedded_json_object(text: str) -> dict[str, Any] | None:
    decoder = json.JSONDecoder()
    fallback: dict[str, Any] | None = None
    verdict_candidate: dict[str, Any] | None = None
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            data, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        if fallback is None:
            fallback = data
        if data.get("verdict") in VALID_VERDICTS and data.get("severity") in VALID_SEVERITIES:
            verdict_candidate = data
    return verdict_candidate or fallback


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
    weak_or_partial = match.match_strength in {"asset_only", "asset_service"} or (
        match.trigger_completeness in {"scope_only", "partial"} and bool(match.matched_benign_hints)
    )
    if not weak_or_partial:
        return verdict

    rationale = (
        verdict.rationale_ko
        + " Watchlist-only or partial-trigger alert downgraded: the current flow has "
        "scope/service context without complete machine-readable attack evidence, and "
        "matched benign guidance should be reviewed before alerting."
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
        "flow_context": _flow_context(tier1_input),
        "watchlist_match": {
            "matched": tier1_input.watchlist_match.matched,
            "priority": tier1_input.watchlist_match.priority,
            "item_id": tier1_input.watchlist_match.item_id,
            "reason": tier1_input.watchlist_match.reason,
            "matched_conditions": tier1_input.watchlist_match.matched_conditions,
            "scope_conditions": tier1_input.watchlist_match.scope_conditions,
            "matched_trigger_hints": tier1_input.watchlist_match.matched_trigger_hints,
            "unmatched_trigger_hints": tier1_input.watchlist_match.unmatched_trigger_hints,
            "matched_benign_hints": tier1_input.watchlist_match.matched_benign_hints,
            "trigger_completeness": tier1_input.watchlist_match.trigger_completeness,
            "match_strength": tier1_input.watchlist_match.match_strength,
            "watchlist_scope_match": tier1_input.watchlist_match.scope_matched,
            "watchlist_trigger_match": tier1_input.watchlist_match.trigger_matched,
            "context_only": tier1_input.watchlist_match.context_only,
            "linter_warnings": tier1_input.watchlist_match.linter_warnings,
            "alert_when": tier1_input.watchlist_match.alert_when,
            "likely_benign_when": tier1_input.watchlist_match.likely_benign_when,
            "escalation_hint": tier1_input.watchlist_match.escalation_hint,
            "routing_policy": tier1_input.watchlist_match.routing_policy,
        },
        "brief_context_excerpt": tier1_input.brief_context_excerpt[:1200],
        "route": {
            "route": tier1_input.route.route,
            "reason": tier1_input.route.reason,
            "effective_review_threshold": tier1_input.route.effective_review_threshold,
            "dynamic_threshold_applied": tier1_input.route.dynamic_threshold_applied,
            "dynamic_threshold_reason": tier1_input.route.dynamic_threshold_reason,
        },
    }


def _flow_context(tier1_input: Tier1Input) -> dict[str, Any]:
    flow = tier1_input.flow
    src_internal = _is_internal_address(flow.src_ip)
    dst_internal = _is_internal_address(flow.dst_ip)
    if src_internal and dst_internal:
        direction = "internal_to_internal"
    elif src_internal and not dst_internal:
        direction = "internal_to_external"
    elif not src_internal and dst_internal:
        direction = "external_to_internal"
    else:
        direction = "external_to_external"
    return {
        "protocol_name": _protocol_name(flow.protocol),
        "dst_service_guess": _service_guess(flow.dst_port),
        "direction": direction,
        "src_is_internal": src_internal,
        "dst_is_internal": dst_internal,
        "has_matched_benign_guidance": bool(tier1_input.watchlist_match.matched_benign_hints),
        "has_unmatched_trigger_hints": bool(tier1_input.watchlist_match.unmatched_trigger_hints),
        "binary_ml_probability_is_below_review_band": tier1_input.ml.prob < tier1_input.route.threshold_low,
    }


def _protocol_name(protocol: str) -> str:
    value = str(protocol).strip().lower()
    if value in {"6", "tcp"}:
        return "tcp"
    if value in {"17", "udp"}:
        return "udp"
    return value or "unknown"


def _service_guess(dst_port: int) -> str:
    services = {
        22: "ssh",
        53: "dns",
        80: "http",
        104: "dicom",
        123: "ntp",
        443: "https",
        445: "smb",
        541: "fortimanager",
        1433: "mssql",
        3306: "mysql",
        3389: "rdp",
        5432: "postgres",
        8080: "http-alt",
        8443: "https-alt",
    }
    return services.get(int(dst_port), "unknown")


def _is_internal_address(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    internal_ranges = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("169.254.0.0/16"),
    )
    return any(ip in network for network in internal_ranges)
