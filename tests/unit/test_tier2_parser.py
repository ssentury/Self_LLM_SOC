from datetime import datetime, timezone
import json

from soc.tier2.parser import normalize_watchlist, parse_tier2_response
from soc.models import SourceSnapshot


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
                        "alert_when": ["repeated attempts"],
                        "likely_benign_when": ["approved source"],
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
        cycle_id="20260502T000000+0000",
        now=now,
        source_status={"assets": "used"},
        generated_by="stub-model",
    )

    assert parsed.parse_error is None
    assert parsed.watchlist["generated_by"] == "stub-model"
    assert parsed.watchlist["source_status"] == {"assets": "used"}
    assert len(parsed.watchlist["priority_1"]) == 1
    assert parsed.watchlist["priority_1"][0]["id"] == "P1-20260502T000000+0000-001"
    assert parsed.watchlist["priority_1"][0]["detection_hints"] == [
        {"field": "dst_port", "operator": "in", "value": [80, 443]}
    ]
    assert parsed.watchlist["priority_1"][0]["alert_when"] == ["repeated attempts"]
    assert parsed.watchlist["priority_1"][0]["likely_benign_when"] == ["approved source"]
    assert parsed.watchlist["priority_2"] == []


def test_parse_tier2_response_returns_safe_fallback_on_malformed_text() -> None:
    now = datetime(2026, 5, 2, tzinfo=timezone.utc)

    parsed = parse_tier2_response(
        "not json",
        cycle_id="20260502T000000+0000",
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
        cycle_id="20260502T000000+0000",
        now=now,
        source_status={},
        generated_by="stub",
    )

    assert parsed.attack_surface_memory == "# Memory Alias"


def test_normalize_watchlist_preserves_empty_priority_lists() -> None:
    now = datetime(2026, 5, 2, tzinfo=timezone.utc)

    watchlist = normalize_watchlist(
        {"priority_1": None},
        cycle_id="20260502T000000+0000",
        now=now,
        source_status={"policy": "missing"},
        generated_by="model",
    )

    assert watchlist["priority_1"] == []
    assert watchlist["priority_2"] == []
    assert watchlist["priority_3"] == []


def test_parse_tier2_response_enriches_weak_p1_from_source_snapshots() -> None:
    now = datetime(2026, 5, 2, tzinfo=timezone.utc)
    response = json.dumps(
        {
            "watchlist": {
                "priority_1": [
                    {
                        "target_assets": [{"ip": "10.42.30.25", "role": "billing-postgres"}],
                        "reason": "Direct DB access from unauthorized sources is a policy concern.",
                        "detection_hints": [{"field": "dst_port", "operator": "eq", "value": 5432}],
                    }
                ],
            },
            "brief_context": "# Brief",
            "attack_surface_memory": "# Memory",
        }
    )
    snapshots = [
        SourceSnapshot(
            name="assets",
            status="used",
            source_type="yaml",
            path_or_uri="assets.yaml",
            item_count=1,
            content=(
                'assets:\n  - ip: "10.42.30.25"\n    role: "billing-postgres"\n'
                "trust_zones:\n"
                '  - cidr: "10.42.20.0/24"\n    zone: "internal-app"\n'
                '  - cidr: "10.42.50.0/24"\n    zone: "admin"\n'
            ),
        ),
        SourceSnapshot(
            name="policy",
            status="used",
            source_type="yaml",
            path_or_uri="policy.yaml",
            item_count=1,
            content=(
                "asset_specific_policies:\n"
                '  - asset: "10.42.30.25"\n'
                '    rule: "Postgres access is allowed only from 10.42.20.15 and approved admin hosts."\n'
            ),
        ),
    ]

    parsed = parse_tier2_response(
        response,
        cycle_id="20260502T000000+0000",
        now=now,
        source_status={"assets": "used", "policy": "used"},
        generated_by="stub",
        snapshots=snapshots,
    )

    item = parsed.watchlist["priority_1"][0]
    assert item["alert_when"]
    assert item["likely_benign_when"]
    assert {"field": "src_ip", "operator": "not_in_cidr", "value": ["10.42.20.0/24", "10.42.50.0/24"]} in item[
        "detection_hints"
    ]
    assert item["routing_policy"]["action"] == "tier1_llm"
    assert item.get("context_only") is not True
