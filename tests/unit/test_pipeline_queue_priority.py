from soc.cli.pipeline import _queue_priority
from soc.models import WatchlistMatch


def test_queue_priority_promotes_middle_strength_watchlist_review() -> None:
    priority = _queue_priority(
        3,
        0.13,
        WatchlistMatch(
            matched=True,
            priority="priority_1",
            match_strength="behavioral_review",
            trigger_matched=True,
        ),
        "watchlist_first",
    )

    assert priority == (0.0, -0.13, 3)


def test_queue_priority_promotes_critical_forbidden_watchlist_review() -> None:
    priority = _queue_priority(
        4,
        0.05,
        WatchlistMatch(
            matched=True,
            priority="priority_1",
            match_strength="critical_forbidden",
            trigger_matched=True,
        ),
        "watchlist_first",
    )

    assert priority == (0.0, -0.05, 4)


def test_queue_priority_does_not_promote_context_only_match() -> None:
    priority = _queue_priority(
        5,
        0.22,
        WatchlistMatch(
            matched=True,
            priority="priority_1",
            match_strength="behavioral_review",
            trigger_matched=True,
            context_only=True,
        ),
        "watchlist_first",
    )

    assert priority == (1.0, -0.22, 5)


def test_queue_priority_does_not_promote_scope_only_match() -> None:
    priority = _queue_priority(
        6,
        0.25,
        WatchlistMatch(
            matched=True,
            priority="priority_1",
            match_strength="asset_service",
            trigger_matched=False,
        ),
        "watchlist_first",
    )

    assert priority == (1.0, -0.25, 6)
