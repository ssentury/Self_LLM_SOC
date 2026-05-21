import asyncio
import json

import pytest

from soc.llm.provider import GeminiProvider


def test_gemini_provider_builds_generate_payload(monkeypatch) -> None:
    captured = {}
    provider = GeminiProvider(
        model="gemini-3.5-flash",
        api_key_env="26_AISecApp_Project_GEMINI_API_KEY",
        base_url="https://example.test/v1beta/",
        timeout_seconds=12,
    )

    def fake_generate_sync(payload):
        captured.update(payload)
        return {
            "modelVersion": "gemini-3.5-flash",
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": '{"watchlist":{"priority_1":[]},'
                                '"brief_context":"ok","attack_surface_memory":"ok"}'
                            }
                        ]
                    }
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 7,
                "candidatesTokenCount": 3,
                "totalTokenCount": 10,
            },
        }

    monkeypatch.setattr(provider, "_generate_sync", fake_generate_sync)

    response = asyncio.run(
        provider.generate(
            system_prompt="system",
            user_prompt="user",
            max_tokens=64,
            temperature=1.0,
            response_format="json",
        )
    )

    assert captured["system_instruction"] == {"parts": [{"text": "system"}]}
    assert captured["contents"] == [{"role": "user", "parts": [{"text": "user"}]}]
    assert captured["generationConfig"] == {
        "maxOutputTokens": 64,
        "temperature": 1.0,
        "responseMimeType": "application/json",
    }
    assert response.content.startswith('{"watchlist"')
    assert response.tokens_used == 10
    assert response.prompt_tokens == 7
    assert response.completion_tokens == 3
    assert response.model_name == "gemini-3.5-flash"


def test_gemini_provider_uses_project_api_key_env(monkeypatch) -> None:
    captured = {}
    provider = GeminiProvider(
        model="gemini-3.5-flash",
        base_url="https://example.test/v1beta",
        timeout_seconds=12,
    )
    monkeypatch.setenv("26_AISecApp_Project_GEMINI_API_KEY", "secret-value")

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def read(self):
            return json.dumps(
                {
                    "candidates": [{"content": {"parts": [{"text": "ok"}]}}],
                    "usageMetadata": {"totalTokenCount": 1},
                }
            ).encode("utf-8")

    def fake_urlopen(req, timeout):
        captured["url"] = req.full_url
        captured["api_key"] = req.headers["X-goog-api-key"]
        captured["timeout"] = timeout
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return FakeResponse()

    monkeypatch.setattr("soc.llm.provider.request.urlopen", fake_urlopen)

    data = provider._generate_sync({"contents": [{"parts": [{"text": "user"}]}]})

    assert captured["url"] == (
        "https://example.test/v1beta/models/gemini-3.5-flash:generateContent"
    )
    assert captured["api_key"] == "secret-value"
    assert captured["timeout"] == 12
    assert data["candidates"][0]["content"]["parts"][0]["text"] == "ok"


def test_gemini_provider_requires_api_key(monkeypatch) -> None:
    provider = GeminiProvider()
    monkeypatch.delenv("26_AISecApp_Project_GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="26_AISecApp_Project_GEMINI_API_KEY"):
        provider._generate_sync({"contents": [{"parts": [{"text": "user"}]}]})
