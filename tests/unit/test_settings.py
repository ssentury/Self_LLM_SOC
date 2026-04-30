from pathlib import Path

import pytest

from soc.config.settings import (
    apply_pipeline_overrides,
    load_pipeline_settings,
    validate_pipeline_settings,
)


def test_load_pipeline_settings_from_yaml(tmp_path: Path) -> None:
    config = tmp_path / "settings.yaml"
    config.write_text(
        """
schema_version: 1
runtime:
  input: data/sample/xgb_route_sample.csv
  output: output/custom
storage:
  enabled: false
  sqlite_path: output/custom.sqlite
detector:
  provider: xgboost
tier1:
  llm:
    provider: ollama
    model: gemma4:e4b
    ollama_url: http://host.docker.internal:11434
  queue:
    mode: queue
    workers: 2
    max_size: 50
""",
        encoding="utf-8",
    )

    settings = load_pipeline_settings(config)
    validate_pipeline_settings(settings)

    assert settings.runtime.input == "data/sample/xgb_route_sample.csv"
    assert settings.runtime.output == "output/custom"
    assert settings.storage.enabled is False
    assert settings.storage.sqlite_path == "output/custom.sqlite"
    assert settings.detector.provider == "xgboost"
    assert settings.tier1.llm.provider == "ollama"
    assert settings.tier1.llm.model == "gemma4:e4b"
    assert settings.tier1.queue.mode == "queue"
    assert settings.tier1.queue.workers == 2
    assert settings.tier1.queue.max_size == 50


def test_cli_overrides_settings_file_values(tmp_path: Path) -> None:
    config = tmp_path / "settings.yaml"
    config.write_text(
        """
runtime:
  input: old.csv
detector:
  provider: dummy
tier1:
  queue:
    mode: sequential
""",
        encoding="utf-8",
    )

    settings = load_pipeline_settings(config)
    settings = apply_pipeline_overrides(
        settings,
        {
            "input": "new.csv",
            "detector": "xgboost",
            "tier1_mode": "queue",
            "tier1_workers": 3,
            "storage_enabled": False,
            "sqlite_path": "output/override.sqlite",
        },
    )

    assert settings.runtime.input == "new.csv"
    assert settings.detector.provider == "xgboost"
    assert settings.tier1.queue.mode == "queue"
    assert settings.tier1.queue.workers == 3
    assert settings.storage.enabled is False
    assert settings.storage.sqlite_path == "output/override.sqlite"


def test_validate_pipeline_settings_rejects_bad_choice(tmp_path: Path) -> None:
    config = tmp_path / "settings.yaml"
    config.write_text("detector:\n  provider: nope\n", encoding="utf-8")

    settings = load_pipeline_settings(config)
    with pytest.raises(ValueError, match="detector.provider"):
        validate_pipeline_settings(settings)
