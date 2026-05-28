import sqlite3
import subprocess
import sys
from pathlib import Path


def test_pipeline_queue_mode_records_call_limit_fallback(tmp_path: Path) -> None:
    input_csv = tmp_path / "flows.csv"
    input_csv.write_text(
        "\n".join(
            [
                "flow_id,FLOW_START_MILLISECONDS,FLOW_END_MILLISECONDS,IPV4_SRC_ADDR,L4_SRC_PORT,IPV4_DST_ADDR,L4_DST_PORT,PROTOCOL,IN_BYTES,IN_PKTS,OUT_BYTES,OUT_PKTS,mock_prob,Label,Attack",
                "queue-1,1,2,10.0.0.1,40000,172.31.69.28,443,6,100,1,100,1,0.50,1,Test",
                "queue-2,3,4,10.0.0.2,40001,172.31.69.28,443,6,100,1,100,1,0.50,1,Test",
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
            "--tier1-mode",
            "queue",
            "--tier1-workers",
            "1",
            "--tier1-max-calls-per-run",
            "1",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "processed=2" in result.stdout
    assert not output_dir.exists()
    with sqlite3.connect(db_path) as conn:
        tier1_call_stats = conn.execute(
            "SELECT COUNT(*), SUM(success) FROM tier1_calls"
        ).fetchone()
        fallback_sources = {
            row[0]
            for row in conn.execute(
                "SELECT fallback_source FROM verdicts WHERE fallback_source IS NOT NULL"
            ).fetchall()
        }
    assert tier1_call_stats == (2, 1)
    assert fallback_sources == {"queue"}


def test_pipeline_queue_mode_records_llm_fallback(tmp_path: Path) -> None:
    input_csv = tmp_path / "flows.csv"
    input_csv.write_text(
        "\n".join(
            [
                "flow_id,FLOW_START_MILLISECONDS,FLOW_END_MILLISECONDS,IPV4_SRC_ADDR,L4_SRC_PORT,IPV4_DST_ADDR,L4_DST_PORT,PROTOCOL,IN_BYTES,IN_PKTS,OUT_BYTES,OUT_PKTS,mock_prob,Label,Attack",
                "llm-fail-1,1,2,10.0.0.1,40000,172.31.69.28,443,6,100,1,100,1,0.50,1,Test",
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
            "ollama",
            "--ollama-url",
            "http://127.0.0.1:9",
            "--ollama-timeout",
            "0.5",
            "--tier1-mode",
            "queue",
            "--tier1-workers",
            "1",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "processed=1" in result.stdout
    assert not output_dir.exists()
    with sqlite3.connect(db_path) as conn:
        tier1_calls = conn.execute("SELECT COUNT(*) FROM tier1_calls").fetchone()[0]
        fallback_source = conn.execute(
            "SELECT fallback_source FROM verdicts WHERE flow_id = 'llm-fail-1'"
        ).fetchone()[0]
    assert tier1_calls == 1
    assert fallback_source == "llm"
