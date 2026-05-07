import sqlite3
import subprocess
import sys
from pathlib import Path


def test_slow_loop_asset_only_watchlist_does_not_lower_realtime_threshold(tmp_path: Path) -> None:
    tier2_output = tmp_path / "tier2"
    reports = tmp_path / "reports"
    db_path = tmp_path / "soc_events.sqlite"

    tier2_result = subprocess.run(
        [
            sys.executable,
            "scripts/tier2_batch.py",
            "--config",
            "config/settings.example.yaml",
            "--output",
            str(tier2_output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "runner=deterministic" in tier2_result.stdout
    watchlist = tier2_output / "watchlists" / "latest.yaml"
    brief = tier2_output / "briefs" / "latest.md"
    assert watchlist.exists()
    assert brief.exists()

    pipeline_result = subprocess.run(
        [
            sys.executable,
            "scripts/pipeline_run.py",
            "--input",
            "data/sample/flows.csv",
            "--output",
            str(reports),
            "--sqlite",
            str(db_path),
            "--detector",
            "dummy",
            "--llm",
            "fake",
            "--tier1-mode",
            "sequential",
            "--watchlist",
            str(watchlist),
            "--brief",
            str(brief),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "processed=3" in pipeline_result.stdout
    with sqlite3.connect(db_path) as conn:
        p1_route = conn.execute(
            """
            SELECT route, adjusted_by_watchlist, ml_prob
            FROM route_decisions
            WHERE flow_id = 'sample-p1-web'
            """
        ).fetchone()
        p1_verdict = conn.execute(
            "SELECT watchlist_matched FROM verdicts WHERE flow_id = 'sample-p1-web'"
        ).fetchone()
        benign_route = conn.execute(
            "SELECT route, adjusted_by_watchlist FROM route_decisions WHERE flow_id = 'sample-benign'"
        ).fetchone()
        tier1_calls = conn.execute("SELECT COUNT(*) FROM tier1_calls").fetchone()[0]

    assert p1_route == ("auto_dismiss", 0, 0.25)
    assert p1_verdict[0].startswith("P1-")
    assert benign_route == ("auto_dismiss", 0)
    assert tier1_calls == 0

    p1_report = (reports / "sample-p1-web.html").read_text(encoding="utf-8")
    assert "Adjusted by watchlist:</strong> False" in p1_report
    assert "Watchlist priority:</strong> priority_1" in p1_report
    assert "Watchlist match strength:</strong> asset_service" in p1_report
    assert "Watchlist context only:</strong> True" in p1_report
