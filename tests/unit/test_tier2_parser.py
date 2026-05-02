from datetime import datetime, timezone
import json

from soc.tier2.parser import normalize_watchlist, parse_tier2_response


def test_parse_tier2_response_normalizes_watchlist() -> None:
    now = datetime(2026, 5, 2, tzinfo=timezone.utc)
    response = json.dumps(
        {
            "watchlist": {
                "priority_1": [
                    {
                        "target_assets": [{"ip": "172.31.69.28", "role": "web"}],
                        "reason": "critical public web asset",
                        "detection_hints": [
                            {"field": "dst_port", "operator": "in", "value": [80, 443]},
                            {"field": "dst_port", "operator": "in", "value": "bad"},
                        ],
                    },
                    {"reason": "missing target asset"},
                ],
                "priority_2": "bad-shape",
            },
            "brief_context": "# Brief\n\nCurated context.",
            "attack_surface_memory": "# Memory\n\nObserved state.",
        },
        ensure_ascii=False,
    )

    parsed = parse_tier2_response(
        response,
        week_id="2026-W18",
        now=now,
        source_status={"assets": "used"},
        generated_by="stub-model",
    )

    assert parsed.parse_error is None
    assert parsed.watchlist["generated_by"] == "stub-model"
    assert parsed.watchlist["source_status"] == {"assets": "used"}
    assert len(parsed.watchlist["priority_1"]) == 1
    assert parsed.watchlist["priority_1"][0]["id"] == "P1-2026W18-001"
    assert parsed.watchlist["priority_1"][0]["detection_hints"] == [
        {"field": "dst_port", "operator": "in", "value": [80, 443]}
    ]
    assert parsed.watchlist["priority_2"] == []


def test_parse_tier2_response_returns_safe_fallback_on_malformed_text() -> None:
    now = datetime(2026, 5, 2, tzinfo=timezone.utc)

    parsed = parse_tier2_response(
        "not json",
        week_id="2026-W18",
        now=now,
        source_status={"assets": "error"},
        generated_by="stub-model",
    )

    assert parsed.parse_error is not None
    assert parsed.watchlist["priority_1"] == []
    assert parsed.watchlist["source_status"] == {"assets": "error"}
    assert "Tier 2 LLM output was unavailable" in parsed.brief_context


def test_parse_tier2_response_accepts_memory_alias() -> None:
    now = datetime(2026, 5, 2, tzinfo=timezone.utc)
    response = json.dumps(
        {
            "watchlist": {},
            "brief": "# Brief",
            "memory_context": "# Memory Alias",
        }
    )

    parsed = parse_tier2_response(
        response,
        week_id="2026-W18",
        now=now,
        source_status={},
        generated_by="stub",
    )

    assert parsed.attack_surface_memory == "# Memory Alias"


def test_normalize_watchlist_preserves_empty_priority_lists() -> None:
    now = datetime(2026, 5, 2, tzinfo=timezone.utc)

    watchlist = normalize_watchlist(
        {"priority_1": None},
        week_id="2026-W18",
        now=now,
        source_status={"policy": "missing"},
        generated_by="model",
    )

    assert watchlist["priority_1"] == []
    assert watchlist["priority_2"] == []
    assert watchlist["priority_3"] == []
