from soc.context.watchlist import match_watchlist
from soc.models import Flow, SourceActivitySummary


def test_watchlist_matches_target_asset_and_port() -> None:
    flow = Flow(
        flow_id="f1",
        start_ms=None,
        end_ms=None,
        src_ip="18.1.1.1",
        dst_ip="172.31.69.28",
        src_port=12345,
        dst_port=443,
        protocol="6",
    )
    watchlist = {
        "priority_1": [
            {
                "id": "P1",
                "target_assets": [{"ip": "172.31.69.28"}],
                "reason": "sample",
                "detection_hints": [{"field": "dst_port", "operator": "in", "value": [80, 443]}],
                "alert_when": ["repeated failed attempts"],
                "likely_benign_when": ["single approved HTTPS connection"],
            }
        ],
        "priority_2": [],
        "priority_3": [],
    }

    match = match_watchlist(flow, watchlist)

    assert match.matched is True
    assert match.priority == "priority_1"
    assert match.item_id == "P1"
    assert match.match_strength == "asset_service"
    assert match.scope_matched is True
    assert match.trigger_matched is False
    assert match.alert_when == ["repeated failed attempts"]
    assert match.likely_benign_when == ["single approved HTTPS connection"]


def test_watchlist_does_not_match_wrong_port() -> None:
    flow = Flow(
        flow_id="f1",
        start_ms=None,
        end_ms=None,
        src_ip="18.1.1.1",
        dst_ip="172.31.69.28",
        src_port=12345,
        dst_port=22,
        protocol="6",
    )
    watchlist = {
        "priority_1": [
            {
                "id": "P1",
                "target_assets": [{"ip": "172.31.69.28"}],
                "detection_hints": [{"field": "dst_port", "operator": "in", "value": [80, 443]}],
            }
        ],
    }

    match = match_watchlist(flow, watchlist)

    assert match.matched is True
    assert match.match_strength == "asset_only"
    assert match.trigger_matched is False


def test_watchlist_matches_structured_ip_hints() -> None:
    flow = Flow(
        flow_id="f1",
        start_ms=None,
        end_ms=None,
        src_ip="18.221.219.4",
        dst_ip="172.31.69.25",
        src_port=12345,
        dst_port=22,
        protocol="6",
    )
    watchlist = {
        "priority_1": [
            {
                "id": "P1",
                "target_assets": [{"ip": "172.31.69.25"}],
                "detection_hints": [
                    {"field": "src_ip", "operator": "in", "value": ["18.221.219.4"]},
                    {"field": "dst_ip", "operator": "eq", "value": "172.31.69.25"},
                ],
            }
        ],
    }

    match = match_watchlist(flow, watchlist)

    assert match.matched is True
    assert match.match_strength == "threat_source"
    assert match.trigger_matched is True
    assert "src_ip in ['18.221.219.4']" in match.matched_conditions
    assert "dst_ip == 172.31.69.25" in match.matched_conditions


def test_watchlist_linter_marks_p1_without_strong_trigger_context_only() -> None:
    flow = Flow(
        flow_id="f1",
        start_ms=None,
        end_ms=None,
        src_ip="18.1.1.1",
        dst_ip="172.31.69.28",
        src_port=12345,
        dst_port=443,
        protocol="6",
    )
    watchlist = {
        "priority_1": [
            {
                "id": "P1",
                "target_assets": [{"ip": "172.31.69.28"}],
                "detection_hints": [{"field": "dst_port", "operator": "in", "value": [443]}],
            }
        ],
        "priority_2": [],
        "priority_3": [],
    }

    from soc.context.watchlist import lint_watchlist

    linted = lint_watchlist(watchlist)
    match = match_watchlist(flow, linted)

    assert linted["priority_1"][0]["context_only"] is True
    assert linted["linter_warnings"]
    assert match.context_only is True


def test_watchlist_matches_recent_source_activity_hint() -> None:
    flow = Flow(
        flow_id="f1",
        start_ms=None,
        end_ms=None,
        src_ip="198.51.100.77",
        dst_ip="203.0.113.20",
        src_port=12345,
        dst_port=443,
        protocol="6",
    )
    watchlist = {
        "priority_1": [
            {
                "id": "P1-vpn",
                "target_assets": [{"ip": "203.0.113.20"}],
                "detection_hints": [
                    {"field": "recent_source_same_dst_port_count", "operator": "gte", "value": 2}
                ],
            }
        ],
    }
    activity = SourceActivitySummary(
        window_minutes=10,
        flow_count=3,
        distinct_dst_count=1,
        top_dst_ports=[443],
        recent_verdicts=[],
        summary_ko="recent repeated source activity",
        same_src_same_dst_count=3,
        same_src_same_dst_port_count=2,
    )

    match = match_watchlist(flow, watchlist, source_activity=activity)

    assert match.matched is True
    assert match.match_strength == "behavior"
    assert match.trigger_matched is True


def test_watchlist_matches_policy_style_source_cidr_hint() -> None:
    flow = Flow(
        flow_id="f1",
        start_ms=None,
        end_ms=None,
        src_ip="198.51.100.90",
        dst_ip="10.42.30.25",
        src_port=12345,
        dst_port=5432,
        protocol="6",
    )
    watchlist = {
        "priority_1": [
            {
                "id": "P1-db",
                "target_assets": [{"ip": "10.42.30.25"}],
                "detection_hints": [
                    {"field": "dst_port", "operator": "eq", "value": 5432},
                    {
                        "field": "src_ip",
                        "operator": "not_in_cidr",
                        "value": ["10.42.20.0/24", "10.42.50.0/24"],
                    },
                ],
            }
        ],
    }

    match = match_watchlist(flow, watchlist)

    assert match.matched is True
    assert match.match_strength == "policy_violation"
    assert match.trigger_matched is True


def test_watchlist_promotes_sensitive_source_external_egress_to_behavioral_review() -> None:
    flow = Flow(
        flow_id="f1",
        start_ms=None,
        end_ms=None,
        src_ip="10.42.40.12",
        dst_ip="198.51.100.123",
        src_port=50000,
        dst_port=443,
        protocol="6",
    )
    watchlist = {
        "priority_1": [
            {
                "id": "P1-egress",
                "target_assets": [{"ip": "10.42.40.12", "match": "src"}],
                "detection_hints": [
                    {"field": "dst_port", "operator": "eq", "value": 443},
                    {"field": "dst_ip", "operator": "not_in_cidr", "value": ["10.42.0.0/16"]},
                ],
            }
        ],
    }

    match = match_watchlist(flow, watchlist)

    assert match.matched is True
    assert match.match_strength == "behavioral_review"
    assert match.trigger_matched is True


def test_watchlist_supports_source_cidr_scope_for_dns_review() -> None:
    flow = Flow(
        flow_id="f1",
        start_ms=None,
        end_ms=None,
        src_ip="10.42.100.55",
        dst_ip="8.8.8.8",
        src_port=53000,
        dst_port=53,
        protocol="17",
    )
    watchlist = {
        "priority_1": [
            {
                "id": "P1-dns",
                "target_assets": [{"cidr": "10.42.100.0/24", "role": "workstations", "match": "src"}],
                "detection_hints": [
                    {"field": "dst_port", "operator": "eq", "value": 53},
                    {"field": "dst_ip", "operator": "not_in_cidr", "value": ["10.42.0.0/16"]},
                ],
            }
        ],
    }

    match = match_watchlist(flow, watchlist)

    assert match.matched is True
    assert match.scope_matched is True
    assert match.match_strength == "behavioral_review"
    assert "target_assets.cidr 10.42.100.0/24 contains flow.src_ip" in match.matched_conditions


def test_watchlist_does_not_treat_source_cidr_scope_as_dns_trigger() -> None:
    flow = Flow(
        flow_id="f1",
        start_ms=None,
        end_ms=None,
        src_ip="10.42.100.55",
        dst_ip="10.42.60.5",
        src_port=53000,
        dst_port=53,
        protocol="17",
    )
    watchlist = {
        "priority_1": [
            {
                "id": "P1-dns",
                "target_assets": [{"cidr": "10.42.100.0/24", "role": "workstations", "match": "src"}],
                "detection_hints": [
                    {"field": "dst_port", "operator": "eq", "value": 53},
                    {"field": "protocol", "operator": "eq", "value": 17},
                    {"field": "src_ip", "operator": "in_cidr", "value": ["10.42.100.0/24"]},
                    {"field": "dst_ip", "operator": "not_in_cidr", "value": ["10.42.0.0/16"]},
                    {"field": "recent_source_same_dst_port_count", "operator": "gte", "value": 2},
                ],
                "trigger_groups": [
                    {
                        "name": "external_dns_tunnel",
                        "required": [
                            {"field": "dst_port", "operator": "eq", "value": 53},
                            {"field": "protocol", "operator": "eq", "value": 17},
                            {"field": "dst_ip", "operator": "not_in_cidr", "value": ["10.42.0.0/16"]},
                        ],
                        "supporting": [
                            {"field": "recent_source_same_dst_port_count", "operator": "gte", "value": 2}
                        ],
                        "min_supporting": 0,
                    }
                ],
                "benign_hints": [{"field": "dst_ip", "operator": "eq", "value": "10.42.60.5"}],
            }
        ],
    }

    match = match_watchlist(flow, watchlist)

    assert match.matched is True
    assert match.match_strength == "asset_service"
    assert match.trigger_matched is False
    assert match.trigger_completeness == "partial"
    assert "src_ip in ['10.42.100.0/24']" not in match.matched_trigger_hints
    assert "dst_ip not in ['10.42.0.0/16']" in match.unmatched_trigger_hints
    assert "dst_ip == 10.42.60.5" in match.matched_benign_hints


def test_watchlist_routes_external_dns_when_required_group_matches() -> None:
    flow = Flow(
        flow_id="f1",
        start_ms=None,
        end_ms=None,
        src_ip="10.42.100.55",
        dst_ip="8.8.8.8",
        src_port=53000,
        dst_port=53,
        protocol="17",
    )
    watchlist = {
        "priority_1": [
            {
                "id": "P1-dns",
                "target_assets": [{"cidr": "10.42.100.0/24", "role": "workstations", "match": "src"}],
                "detection_hints": [
                    {"field": "dst_port", "operator": "eq", "value": 53},
                    {"field": "protocol", "operator": "eq", "value": 17},
                    {"field": "src_ip", "operator": "in_cidr", "value": ["10.42.100.0/24"]},
                    {"field": "dst_ip", "operator": "not_in_cidr", "value": ["10.42.0.0/16"]},
                ],
                "trigger_groups": [
                    {
                        "name": "external_dns_tunnel",
                        "required": [
                            {"field": "dst_port", "operator": "eq", "value": 53},
                            {"field": "protocol", "operator": "eq", "value": 17},
                            {"field": "dst_ip", "operator": "not_in_cidr", "value": ["10.42.0.0/16"]},
                        ],
                    }
                ],
                "benign_hints": [{"field": "dst_ip", "operator": "eq", "value": "10.42.60.5"}],
            }
        ],
    }

    match = match_watchlist(flow, watchlist)

    assert match.matched is True
    assert match.match_strength == "behavioral_review"
    assert match.trigger_matched is True
    assert match.trigger_completeness == "required_met"
    assert "dst_ip not in ['10.42.0.0/16']" in match.matched_trigger_hints
    assert match.matched_benign_hints == []


def test_watchlist_marks_metadata_service_as_critical_forbidden() -> None:
    flow = Flow(
        flow_id="f1",
        start_ms=None,
        end_ms=None,
        src_ip="10.42.20.15",
        dst_ip="169.254.169.254",
        src_port=50000,
        dst_port=80,
        protocol="6",
    )
    watchlist = {
        "priority_1": [
            {
                "id": "P1-metadata",
                "target_assets": [{"ip": "169.254.169.254", "match": "dst"}],
                "detection_hints": [
                    {"field": "dst_ip", "operator": "eq", "value": "169.254.169.254"},
                    {"field": "dst_port", "operator": "eq", "value": 80},
                    {"field": "src_ip", "operator": "in_cidr", "value": ["10.42.0.0/16"]},
                ],
            }
        ],
    }

    match = match_watchlist(flow, watchlist)

    assert match.matched is True
    assert match.match_strength == "critical_forbidden"
    assert match.trigger_matched is True


def test_watchlist_preserves_valid_routing_policy_for_strong_trigger() -> None:
    flow = Flow(
        flow_id="f1",
        start_ms=None,
        end_ms=None,
        src_ip="198.51.100.90",
        dst_ip="10.42.30.25",
        src_port=12345,
        dst_port=5432,
        protocol="6",
    )
    watchlist = {
        "priority_1": [
            {
                "id": "P1-db",
                "target_assets": [{"ip": "10.42.30.25"}],
                "detection_hints": [
                    {"field": "src_ip", "operator": "in", "value": ["198.51.100.90"]},
                ],
                "routing_policy": {
                    "review_threshold": 0.10,
                    "max_threshold_drop": 0.20,
                    "action": "tier1_llm",
                    "reason": "source-backed low-score review",
                },
            }
        ],
        "priority_2": [],
        "priority_3": [],
    }

    from soc.context.watchlist import lint_watchlist

    match = match_watchlist(flow, lint_watchlist(watchlist))

    assert match.routing_policy == {
        "review_threshold": 0.10,
        "max_threshold_drop": 0.20,
        "action": "tier1_llm",
        "reason": "source-backed low-score review",
    }


def test_watchlist_ignores_routing_policy_for_context_only_item() -> None:
    watchlist = {
        "priority_1": [
            {
                "id": "P1-context",
                "target_assets": [{"ip": "10.42.30.25"}],
                "detection_hints": [{"field": "dst_port", "operator": "eq", "value": 5432}],
                "routing_policy": {"review_threshold": 0.10, "action": "tier1_llm"},
            }
        ],
        "priority_2": [],
        "priority_3": [],
    }

    from soc.context.watchlist import lint_watchlist

    linted = lint_watchlist(watchlist)

    assert "routing_policy" not in linted["priority_1"][0]
    assert any("routing_policy ignored" in warning for warning in linted["priority_1"][0]["linter_warnings"])


def test_watchlist_ignores_invalid_routing_policy_with_warning() -> None:
    watchlist = {
        "priority_1": [
            {
                "id": "P1-bad-policy",
                "target_assets": [{"ip": "10.42.30.25"}],
                "detection_hints": [{"field": "src_ip", "operator": "in", "value": ["198.51.100.90"]}],
                "routing_policy": {"review_threshold": 0.01, "action": "tier1_llm"},
            }
        ],
        "priority_2": [],
        "priority_3": [],
    }

    from soc.context.watchlist import lint_watchlist

    linted = lint_watchlist(watchlist)

    assert "routing_policy" not in linted["priority_1"][0]
    assert any("review_threshold below" in warning for warning in linted["priority_1"][0]["linter_warnings"])
