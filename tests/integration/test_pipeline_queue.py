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

    result = subprocess.run(
        [
            sys.executable,
            "scripts/pipeline_run.py",
            "--input",
            str(input_csv),
            "--output",
            str(output_dir),
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
    summary = (output_dir / "summary.html").read_text(encoding="utf-8")
    assert "tier1_mode: queue" in summary
    assert "tier1_queued: 2" in summary
    assert "tier1_calls: 1" in summary
    assert "tier1_fallbacks: 1" in summary
    assert "tier1_queue_fallbacks: 1" in summary
    assert "tier1_llm_fallbacks: 0" in summary
    assert "tier1_skipped_by_call_limit: 1" in summary


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

    result = subprocess.run(
        [
            sys.executable,
            "scripts/pipeline_run.py",
            "--input",
            str(input_csv),
            "--output",
            str(output_dir),
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
    summary = (output_dir / "summary.html").read_text(encoding="utf-8")
    assert "tier1_calls: 1" in summary
    assert "tier1_fallbacks: 1" in summary
    assert "tier1_queue_fallbacks: 0" in summary
    assert "tier1_llm_fallbacks: 1" in summary
