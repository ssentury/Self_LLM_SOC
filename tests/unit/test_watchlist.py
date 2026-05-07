from soc.context.watchlist import match_watchlist
from soc.models import Flow


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
