from pathlib import Path

from soc.tier2.batch import FakeTier2Runner


def test_fake_tier2_batch_writes_latest_files(tmp_path: Path) -> None:
    config = tmp_path / "config" / "settings.example.yaml"
    config.parent.mkdir()
    config.write_text("tier2:\n  provider: fake\n", encoding="utf-8")

    FakeTier2Runner().run(config, tmp_path / "output")

    assert (tmp_path / "output" / "watchlists" / "latest.yaml").exists()
    assert (tmp_path / "output" / "briefs" / "latest.md").exists()
    assert (tmp_path / "output" / "memory" / "latest.md").exists()
