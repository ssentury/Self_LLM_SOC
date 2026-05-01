import sqlite3
import subprocess
import sys
from pathlib import Path


def test_pipeline_persists_events_to_sqlite(tmp_path: Path) -> None:
    input_csv = tmp_path / "flows.csv"
    input_csv.write_text(
        "\n".join(
            [
                "flow_id,FLOW_START_MILLISECONDS,FLOW_END_MILLISECONDS,IPV4_SRC_ADDR,L4_SRC_PORT,IPV4_DST_ADDR,L4_DST_PORT,PROTOCOL,IN_BYTES,IN_PKTS,OUT_BYTES,OUT_PKTS,mock_prob,Label,Attack",
                "dismiss-1,1,2,10.0.0.1,40000,172.31.69.28,443,6,100,1,100,1,0.10,0,Benign",
                "tier1-1,3,4,10.0.0.1,40001,172.31.69.29,8080,6,100,1,100,1,0.50,1,Review",
                "alert-1,5,6,10.0.0.2,40002,172.31.69.30,22,6,100,1,100,1,0.99,1,Alert",
            ]
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "reports"
    db_path = tmp_path / "soc_events.sqlite"

    result = subprocess.run(
        [
            sys.executable,
            "scripts/pipeline_run.py",
            "--input",
            str(input_csv),
            "--output",
            str(output_dir),
            "--sqlite",
            str(db_path),
            "--detector",
            "dummy",
            "--llm",
            "fake",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "processed=3" in result.stdout
    with sqlite3.connect(db_path) as conn:
        counts = {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("flows", "ml_results", "route_decisions", "verdicts")
        }
        tier1_calls = conn.execute("SELECT COUNT(*) FROM tier1_calls").fetchone()[0]
        tier1_call = conn.execute(
            "SELECT model_name, latency_ms, tokens_used FROM tier1_calls"
        ).fetchone()
        routes = {
            row[0]
            for row in conn.execute("SELECT route FROM route_decisions").fetchall()
        }

    assert counts == {
        "flows": 3,
        "ml_results": 3,
        "route_decisions": 3,
        "verdicts": 3,
    }
    assert tier1_calls == 1
    assert tier1_call[0] == "fake-llm"
    assert tier1_call[1] is not None
    assert tier1_call[2] is not None
    assert routes == {"auto_dismiss", "tier1_llm", "auto_alert"}


def test_pipeline_no_storage_keeps_smoke_path(tmp_path: Path) -> None:
    output_dir = tmp_path / "reports"
    db_path = tmp_path / "disabled.sqlite"

    result = subprocess.run(
        [
            sys.executable,
            "scripts/pipeline_run.py",
            "--input",
            "data/sample/flows.csv",
            "--output",
            str(output_dir),
            "--sqlite",
            str(db_path),
            "--no-storage",
            "--detector",
            "dummy",
            "--llm",
            "fake",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "processed=3" in result.stdout
    assert (output_dir / "summary.html").exists()
    assert not db_path.exists()
