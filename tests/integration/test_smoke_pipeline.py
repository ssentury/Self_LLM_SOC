import subprocess
import sys
from pathlib import Path


def test_pipeline_script_runs(tmp_path: Path) -> None:
    output_dir = tmp_path / "reports"
    result = subprocess.run(
        [
            sys.executable,
            "scripts/pipeline_run.py",
            "--input",
            "data/sample/flows.csv",
            "--output",
            str(output_dir),
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
    assert (output_dir / "sample-p1-web.html").exists()
