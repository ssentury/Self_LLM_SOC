import asyncio
from urllib.error import HTTPError

from soc.llm.provider import OllamaProvider


def test_ollama_provider_builds_generate_payload(monkeypatch) -> None:
    captured = {}
    provider = OllamaProvider(
        model="gemma4:e4b",
        base_url="http://example.test/",
        timeout_seconds=12,
    )

    def fake_generate_sync(payload):
        captured.update(payload)
        return {
            "model": "gemma4:e4b",
            "response": '{"verdict":"uncertain"}',
            "prompt_eval_count": 7,
            "eval_count": 3,
        }

    monkeypatch.setattr(provider, "_generate_sync", fake_generate_sync)

    response = asyncio.run(
        provider.generate(
            system_prompt="system",
            user_prompt="user",
            max_tokens=64,
            temperature=0.2,
            response_format="json",
        )
    )

    assert captured["model"] == "gemma4:e4b"
    assert captured["system"] == "system"
    assert captured["prompt"] == "user"
    assert captured["stream"] is False
    assert captured["format"] == "json"
    assert captured["options"] == {"temperature": 0.2, "num_predict": 64}
    assert response.content == '{"verdict":"uncertain"}'
    assert response.tokens_used == 10
    assert response.prompt_tokens == 7
    assert response.completion_tokens == 3
    assert response.model_name == "gemma4:e4b"


def test_ollama_provider_includes_http_error_body(monkeypatch) -> None:
    provider = OllamaProvider(
        model="gemma4:e4b",
        base_url="http://example.test/",
        timeout_seconds=12,
    )

    class Body:
        def read(self):
            return b'{"error":"model requires more system memory"}'

        def close(self):
            pass

    def fake_urlopen(req, timeout):
        raise HTTPError(req.full_url, 500, "Internal Server Error", {}, Body())

    monkeypatch.setattr("soc.llm.provider.request.urlopen", fake_urlopen)

    try:
        asyncio.run(provider.generate("system", "user"))
    except RuntimeError as exc:
        assert "HTTP 500" in str(exc)
        assert "model requires more system memory" in str(exc)
    else:
        raise AssertionError("expected RuntimeError")
