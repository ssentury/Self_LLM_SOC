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
  category_model: output/models/custom_hint.json
  category_metadata: output/models/custom_hint_metadata.json
realtime:
  activity_window_minutes: 240
tier1:
  llm:
    provider: gemini
    model: gemma-4-26b-a4b-it
    ollama_url: http://host.docker.internal:11434
    max_tokens: 8192
    retry_attempts: 2
    retry_backoff_seconds: 1.5
  queue:
    mode: queue
    workers: 2
    max_size: 50
tier2:
  provider: gemini
  model: gemini-3.5-flash
  ollama_url: http://host.docker.internal:11434
  gemini_api_key_env: 26_AISecApp_Project_GEMINI_API_KEY
  gemini_api_base_url: https://generativelanguage.googleapis.com/v1beta
  timeout_seconds: 600
  max_tokens: 16384
  attack_surface_memory_max_chars: 3000
  temperature: 1.0
  response_format: json
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
    assert settings.detector.category_model == "output/models/custom_hint.json"
    assert settings.detector.category_metadata == "output/models/custom_hint_metadata.json"
    assert settings.realtime.activity_window_minutes == 240
    assert settings.tier1.llm.provider == "gemini"
    assert settings.tier1.llm.model == "gemma-4-26b-a4b-it"
    assert settings.tier1.llm.max_tokens == 8192
    assert settings.tier1.llm.retry_attempts == 2
    assert settings.tier1.llm.retry_backoff_seconds == 1.5
    assert settings.tier1.queue.mode == "queue"
    assert settings.tier1.queue.workers == 2
    assert settings.tier1.queue.max_size == 50
    assert settings.tier2.provider == "gemini"
    assert settings.tier2.model == "gemini-3.5-flash"
    assert settings.tier2.ollama_url == "http://host.docker.internal:11434"
    assert settings.tier2.gemini_api_key_env == "26_AISecApp_Project_GEMINI_API_KEY"
    assert (
        settings.tier2.gemini_api_base_url
        == "https://generativelanguage.googleapis.com/v1beta"
    )
    assert settings.tier2.timeout_seconds == 600
    assert settings.tier2.max_tokens == 16384
    assert settings.tier2.attack_surface_memory_max_chars == 3000
    assert settings.tier2.temperature == 1.0
    assert settings.tier2.response_format == "json"


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
            "tier1_max_tokens": 6144,
            "tier1_retry_attempts": 0,
            "tier1_retry_backoff_seconds": 0.5,
            "tier1_workers": 3,
            "activity_window_minutes": 120,
            "storage_enabled": False,
            "sqlite_path": "output/override.sqlite",
            "category_model": "output/models/override_hint.json",
        },
    )

    assert settings.runtime.input == "new.csv"
    assert settings.detector.provider == "xgboost"
    assert settings.tier1.llm.max_tokens == 6144
    assert settings.tier1.llm.retry_attempts == 0
    assert settings.tier1.llm.retry_backoff_seconds == 0.5
    assert settings.tier1.queue.mode == "queue"
    assert settings.tier1.queue.workers == 3
    assert settings.realtime.activity_window_minutes == 120
    assert settings.storage.enabled is False
    assert settings.storage.sqlite_path == "output/override.sqlite"
    assert settings.detector.category_model == "output/models/override_hint.json"


def test_validate_pipeline_settings_rejects_bad_choice(tmp_path: Path) -> None:
    config = tmp_path / "settings.yaml"
    config.write_text("detector:\n  provider: nope\n", encoding="utf-8")

    settings = load_pipeline_settings(config)
    with pytest.raises(ValueError, match="detector.provider"):
        validate_pipeline_settings(settings)
