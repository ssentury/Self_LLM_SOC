from __future__ import annotations

import asyncio
import json
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any
from urllib import parse
from urllib import error, request


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
    def __init__(
        self,
        model: str = "gemma4:e4b",
        base_url: str = "http://localhost:11434",
        timeout_seconds: float = 180.0,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2048,
        temperature: float = 0.3,
        response_format: str = "text",
    ) -> LLMResponse:
        payload: dict[str, Any] = {
            "model": self.model,
            "system": system_prompt,
            "prompt": user_prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if response_format == "json":
            payload["format"] = "json"

        started = time.perf_counter()
        data = await asyncio.to_thread(self._generate_sync, payload)
        latency_ms = (time.perf_counter() - started) * 1000
        return LLMResponse(
            content=str(data.get("response") or ""),
            tokens_used=int(data.get("prompt_eval_count") or 0)
            + int(data.get("eval_count") or 0),
            model_name=str(data.get("model") or self.model),
            latency_ms=latency_ms,
        )

    def _generate_sync(self, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url}/api/generate"
        body = json.dumps(payload).encode("utf-8")
        req = request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as response:
                raw = response.read().decode("utf-8")
        except error.URLError as exc:
            raise RuntimeError(f"Ollama request failed for {url}: {exc}") from exc

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Ollama returned non-JSON response") from exc
        if not isinstance(data, dict):
            raise RuntimeError("Ollama returned an unexpected response shape")
        if data.get("error"):
            raise RuntimeError(f"Ollama returned an error: {data['error']}")
        return data


class GeminiProvider(LLMProvider):
    def __init__(
        self,
        model: str = "gemini-3-flash-preview",
        api_key_env: str = "26_AISecApp_Project_GEMINI_API_KEY",
        base_url: str = "https://generativelanguage.googleapis.com/v1beta",
        timeout_seconds: float = 180.0,
    ) -> None:
        self.model = model
        self.api_key_env = api_key_env
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2048,
        temperature: float = 0.3,
        response_format: str = "text",
    ) -> LLMResponse:
        generation_config: dict[str, Any] = {
            "maxOutputTokens": max_tokens,
            "temperature": temperature,
        }
        if response_format == "json":
            generation_config["responseMimeType"] = "application/json"

        payload: dict[str, Any] = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": generation_config,
        }

        started = time.perf_counter()
        data = await asyncio.to_thread(self._generate_sync, payload)
        latency_ms = (time.perf_counter() - started) * 1000
        return LLMResponse(
            content=_extract_gemini_text(data),
            tokens_used=_extract_gemini_tokens(data),
            model_name=str(data.get("modelVersion") or self.model),
            latency_ms=latency_ms,
        )

    def _generate_sync(self, payload: dict[str, Any]) -> dict[str, Any]:
        api_key = _resolve_gemini_api_key(self.api_key_env)
        model_path = parse.quote(self.model, safe="")
        url = f"{self.base_url}/models/{model_path}:generateContent"
        body = json.dumps(payload).encode("utf-8")
        req = request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": api_key,
            },
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as response:
                raw = response.read().decode("utf-8")
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Gemini request failed for {url}: HTTP {exc.code}: {detail}") from exc
        except error.URLError as exc:
            raise RuntimeError(f"Gemini request failed for {url}: {exc}") from exc

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Gemini returned non-JSON response") from exc
        if not isinstance(data, dict):
            raise RuntimeError("Gemini returned an unexpected response shape")
        if data.get("error"):
            raise RuntimeError(f"Gemini returned an error: {data['error']}")
        return data


def _resolve_gemini_api_key(primary_env: str) -> str:
    for env_name in (primary_env, "GEMINI_API_KEY", "GOOGLE_API_KEY"):
        api_key = os.environ.get(env_name)
        if api_key:
            return api_key
    raise RuntimeError(
        "Gemini API key is not set. "
        f"Set {primary_env}, GEMINI_API_KEY, or GOOGLE_API_KEY before using the Gemini provider."
    )


def _extract_gemini_text(data: dict[str, Any]) -> str:
    candidates = data.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        raise RuntimeError("Gemini response did not include candidates")
    first = candidates[0]
    if not isinstance(first, dict):
        raise RuntimeError("Gemini candidate had an unexpected shape")
    content = first.get("content")
    if not isinstance(content, dict):
        raise RuntimeError("Gemini candidate did not include content")
    parts = content.get("parts")
    if not isinstance(parts, list):
        raise RuntimeError("Gemini candidate content did not include parts")
    texts = [str(part.get("text")) for part in parts if isinstance(part, dict) and part.get("text")]
    if not texts:
        raise RuntimeError("Gemini response did not include text output")
    return "".join(texts)


def _extract_gemini_tokens(data: dict[str, Any]) -> int:
    usage = data.get("usageMetadata")
    if not isinstance(usage, dict):
        return 0
    return int(
        usage.get("totalTokenCount")
        or (
            int(usage.get("promptTokenCount") or 0)
            + int(usage.get("candidatesTokenCount") or 0)
        )
    )
