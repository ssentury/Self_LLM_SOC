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
            }
        ],
        "priority_2": [],
        "priority_3": [],
    }

    match = match_watchlist(flow, watchlist)

    assert match.matched is True
    assert match.priority == "priority_1"
    assert match.item_id == "P1"


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

    assert match_watchlist(flow, watchlist).matched is False
