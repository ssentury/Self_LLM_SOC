import asyncio

from soc.llm.provider import LLMProvider, LLMResponse
from soc.llm.tier1 import judge_flow
from soc.models import (
    Flow,
    MLResult,
    RouteDecision,
    SourceActivitySummary,
    Tier1Input,
    WatchlistMatch,
)


class StaticProvider(LLMProvider):
    def __init__(self, content: str | None = None, fail: bool = False) -> None:
        self.content = content or "{}"
        self.fail = fail
        self.user_prompt: str | None = None

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2048,
        temperature: float = 0.3,
        response_format: str = "text",
    ) -> LLMResponse:
        if self.fail:
            raise RuntimeError("provider unavailable")
        self.user_prompt = user_prompt
        return LLMResponse(
            content=self.content,
            tokens_used=1,
            model_name="static",
            latency_ms=1.0,
        )


def test_judge_flow_extracts_json_from_ollama_style_response() -> None:
    verdict = asyncio.run(
        judge_flow(
            _tier1_input(),
            StaticProvider(
                'Here is JSON: {"verdict":"alert","severity":"high",'
                '"rationale_ko":"watchlist match",'
                '"recommended_action_ko":"inspect host","confidence":0.9}'
            ),
        )
    )

    assert verdict.verdict == "alert"
    assert verdict.severity == "high"
    assert verdict.rationale_ko == "watchlist match"
    assert verdict.recommended_action_ko == "inspect host"
    assert verdict.confidence == 0.9


def test_judge_flow_falls_back_when_provider_fails() -> None:
    verdict = asyncio.run(judge_flow(_tier1_input(), StaticProvider(fail=True)))

    assert verdict.verdict == "uncertain"
    assert verdict.severity == "medium"
    assert verdict.confidence == 0.5
    assert verdict.watchlist_matched == "P1-test"


def test_judge_flow_includes_category_confidence_in_prompt() -> None:
    provider = StaticProvider('{"verdict":"uncertain","severity":"medium","confidence":0.5}')

    asyncio.run(judge_flow(_tier1_input(), provider))

    assert provider.user_prompt is not None
    assert '"category_hint": "mock"' in provider.user_prompt
    assert '"category_confidence": 0.5' in provider.user_prompt
    assert '"match_strength": "threat_source"' in provider.user_prompt
    assert '"watchlist_scope_match": true' in provider.user_prompt
    assert '"watchlist_trigger_match": true' in provider.user_prompt
    assert '"alert_when": ["unexpected service use"]' in provider.user_prompt
    assert '"likely_benign_when": ["normal business HTTPS"]' in provider.user_prompt
    assert '"escalation_hint": "review only"' in provider.user_prompt


def test_judge_flow_downgrades_watchlist_only_low_probability_alert() -> None:
    verdict = asyncio.run(
        judge_flow(
            _tier1_input(
                ml_prob=0.25,
                match_strength="asset_only",
                trigger_matched=False,
            ),
            StaticProvider(
                '{"verdict":"alert","severity":"high",'
                '"rationale_ko":"important watchlist asset",'
                '"recommended_action_ko":"inspect host","confidence":0.9}'
            ),
        )
    )

    assert verdict.verdict == "uncertain"
    assert verdict.severity == "medium"
    assert "Watchlist-only alert downgraded" in verdict.rationale_ko


def test_judge_flow_falls_back_for_invalid_schema_values() -> None:
    verdict = asyncio.run(
        judge_flow(
            _tier1_input(),
            StaticProvider(
                '{"verdict":"maybe","severity":"urgent",'
                '"rationale_ko":"bad schema","recommended_action_ko":"none"}'
            ),
        )
    )

    assert verdict.verdict == "uncertain"
    assert verdict.severity == "medium"
    assert verdict.fallback_source == "llm"
    assert "verdict field" in str(verdict.fallback_reason)
    assert verdict.llm_model_name == "static"
    assert verdict.llm_latency_ms == 1.0
    assert verdict.llm_tokens_used == 1


def _tier1_input(
    *,
    ml_prob: float = 0.42,
    match_strength: str = "threat_source",
    trigger_matched: bool = True,
) -> Tier1Input:
    return Tier1Input(
        flow=Flow(
            flow_id="flow-1",
            start_ms=None,
            end_ms=None,
            src_ip="18.221.219.4",
            dst_ip="172.31.69.28",
            src_port=51515,
            dst_port=443,
            protocol="TCP",
            features={"mock_prob": 0.42},
        ),
        ml=MLResult(
            prob=ml_prob,
            category_hint="mock",
            category_confidence=0.5,
            shap_top5=[],
        ),
        source_activity=SourceActivitySummary(
            window_minutes=10,
            flow_count=0,
            distinct_dst_count=0,
            top_dst_ports=[],
            recent_verdicts=[],
            summary_ko="no recent source activity",
        ),
        watchlist_match=WatchlistMatch(
            matched=True,
            priority="priority_1",
            item_id="P1-test",
            reason="test",
            matched_conditions=["dst_port in [443]"],
            alert_when=["unexpected service use"],
            likely_benign_when=["normal business HTTPS"],
            match_strength=match_strength,
            scope_matched=True,
            trigger_matched=trigger_matched,
            escalation_hint="review only",
        ),
        brief_context_excerpt="test brief",
        route=RouteDecision(
            route="tier1_llm",
            reason="review band",
            threshold_low=0.3,
            threshold_high=0.95,
            adjusted_by_watchlist=True,
            ml_prob=0.42,
        ),
    )
