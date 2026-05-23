import asyncio
import json

from soc.llm.provider import FakeLLMProvider


def test_fake_provider_does_not_alert_on_watchlist_match_alone() -> None:
    payload = {
        "ml": {"prob": 0.25, "category_hint": "benign"},
        "watchlist_match": {"matched": True, "priority": "priority_1"},
        "route": {"route": "tier1_llm"},
    }

    response = asyncio.run(
        FakeLLMProvider().generate("", json.dumps(payload), response_format="json")
    )
    verdict = json.loads(response.content)

    assert verdict["verdict"] == "benign"
    assert verdict["severity"] == "low"


def test_fake_provider_alerts_on_strong_ml_evidence() -> None:
    payload = {
        "ml": {"prob": 0.98, "category_hint": "mock"},
        "watchlist_match": {"matched": False},
        "route": {"route": "tier1_llm"},
    }

    response = asyncio.run(
        FakeLLMProvider().generate("", json.dumps(payload), response_format="json")
    )
    verdict = json.loads(response.content)

    assert verdict["verdict"] == "alert"
    assert verdict["severity"] == "high"
