from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class LLMResponse:
    content: str
    tokens_used: int
    model_name: str
    latency_ms: float


class LLMProvider(ABC):
    @abstractmethod
    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2048,
        temperature: float = 0.3,
        response_format: str = "text",
    ) -> LLMResponse:
        raise NotImplementedError


class FakeLLMProvider(LLMProvider):
    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2048,
        temperature: float = 0.3,
        response_format: str = "text",
    ) -> LLMResponse:
        started = time.perf_counter()
        alert = '"matched": true' in user_prompt or '"route": "auto_alert"' in user_prompt
        body = {
            "verdict": "alert" if alert else "uncertain",
            "severity": "high" if alert else "medium",
            "rationale_ko": (
                "Watchlist 매칭 또는 높은 ML 확률 때문에 우선 확인이 필요합니다."
                if alert
                else "ML 확률이 중간 구간이어서 추가 맥락 확인이 필요합니다."
            ),
            "recommended_action_ko": (
                "대상 자산의 최근 접속 이력과 관련 CVE 노출 여부를 확인하세요."
                if alert
                else "동일 출발지의 반복 접속 여부를 모니터링하세요."
            ),
            "confidence": 0.6,
        }
        latency_ms = (time.perf_counter() - started) * 1000
        return LLMResponse(
            content=json.dumps(body, ensure_ascii=False),
            tokens_used=len(user_prompt.split()),
            model_name="fake-llm",
            latency_ms=latency_ms,
        )


class OllamaProvider(LLMProvider):
    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2048,
        temperature: float = 0.3,
        response_format: str = "text",
    ) -> LLMResponse:
        raise NotImplementedError("OllamaProvider will replace FakeLLMProvider after the scaffold.")
