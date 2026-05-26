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
    prompt_tokens: int = 0
    completion_tokens: int = 0


class LLMProvider(ABC):
    @abstractmethod
    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.3,
        response_format: str = "text",
    ) -> LLMResponse:
        raise NotImplementedError


class FakeLLMProvider(LLMProvider):
    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.3,
        response_format: str = "text",
    ) -> LLMResponse:
        started = time.perf_counter()
        payload = _load_prompt_payload(user_prompt)
        route = str(payload.get("route", {}).get("route", ""))
        ml = payload.get("ml", {})
        try:
            ml_prob = float(ml.get("prob") or 0.0)
        except (TypeError, ValueError):
            ml_prob = 0.0
        category_hint = str(ml.get("category_hint") or "").lower()
        watchlist_match = payload.get("watchlist_match", {})
        matched = bool(watchlist_match.get("matched"))
        match_strength = str(watchlist_match.get("match_strength") or "none")
        trigger_matched = bool(watchlist_match.get("watchlist_trigger_match"))

        alert = route == "auto_alert" or ml_prob >= 0.95 or (
            matched
            and trigger_matched
            and match_strength in {"behavior", "threat_source", "policy_violation"}
            and ml_prob >= 0.20
            and category_hint != "benign"
        )
        benign = category_hint == "benign" and ml_prob < 0.35 and not alert
        body = {
            "verdict": "alert" if alert else ("benign" if benign else "uncertain"),
            "severity": "high" if alert else ("low" if benign else "medium"),
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
        if benign:
            body["rationale_ko"] = (
                "The flow is explainable as benign traffic; watchlist alone is not attack evidence."
            )
            body["recommended_action_ko"] = (
                "Monitor similar flows and escalate only if additional suspicious behavior appears."
            )
        latency_ms = (time.perf_counter() - started) * 1000
        return LLMResponse(
            content=json.dumps(body, ensure_ascii=False),
            tokens_used=len(user_prompt.split()),
            model_name="fake-llm",
            latency_ms=latency_ms,
            prompt_tokens=len(user_prompt.split()),
            completion_tokens=len(json.dumps(body, ensure_ascii=False).split()),
        )


def _load_prompt_payload(user_prompt: str) -> dict[str, Any]:
    try:
        data = json.loads(user_prompt)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


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
        max_tokens: int = 4096,
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
        prompt_tokens = int(data.get("prompt_eval_count") or 0)
        completion_tokens = int(data.get("eval_count") or 0)
        return LLMResponse(
            content=str(data.get("response") or ""),
            tokens_used=prompt_tokens + completion_tokens,
            model_name=str(data.get("model") or self.model),
            latency_ms=latency_ms,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
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
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"Ollama request failed for {url}: HTTP {exc.code}: {detail}"
            ) from exc
        except error.URLError as exc:
            raise RuntimeError(f"Ollama request failed for {url}: {exc}") from exc
        except TimeoutError as exc:
            raise RuntimeError(
                f"Ollama request timed out for {url} after {self.timeout_seconds:.1f}s: {exc}"
            ) from exc
        except OSError as exc:
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
        model: str = "gemini-3.5-flash",
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
        max_tokens: int = 4096,
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
        finish_reason = _extract_gemini_finish_reason(data)
        if finish_reason and finish_reason != "STOP":
            prompt_tokens, completion_tokens = _extract_gemini_token_breakdown(data)
            raise RuntimeError(
                "Gemini stopped before completing the response "
                f"(finishReason={finish_reason}, prompt_tokens={prompt_tokens}, "
                f"completion_tokens={completion_tokens}, max_tokens={max_tokens})."
            )
        prompt_tokens, completion_tokens = _extract_gemini_token_breakdown(data)
        return LLMResponse(
            content=_extract_gemini_text(data),
            tokens_used=_extract_gemini_tokens(data),
            model_name=str(data.get("modelVersion") or self.model),
            latency_ms=latency_ms,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
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
        except TimeoutError as exc:
            raise RuntimeError(
                f"Gemini request timed out for {url} after {self.timeout_seconds:.1f}s: {exc}"
            ) from exc
        except OSError as exc:
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


def _extract_gemini_finish_reason(data: dict[str, Any]) -> str:
    candidates = data.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        return ""
    first = candidates[0]
    if not isinstance(first, dict):
        return ""
    return str(first.get("finishReason") or "")


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


def _extract_gemini_token_breakdown(data: dict[str, Any]) -> tuple[int, int]:
    usage = data.get("usageMetadata")
    if not isinstance(usage, dict):
        return 0, 0
    prompt_tokens = int(usage.get("promptTokenCount") or 0)
    completion_tokens = int(usage.get("candidatesTokenCount") or 0) + int(
        usage.get("thoughtsTokenCount") or 0
    )
    total_tokens = int(usage.get("totalTokenCount") or 0)
    if total_tokens > prompt_tokens and completion_tokens < total_tokens - prompt_tokens:
        completion_tokens = total_tokens - prompt_tokens
    return prompt_tokens, completion_tokens
