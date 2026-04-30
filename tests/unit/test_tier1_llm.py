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


def _tier1_input() -> Tier1Input:
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
            prob=0.42,
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
