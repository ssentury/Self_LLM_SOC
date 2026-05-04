from pathlib import Path
import json

from soc.context.watchlist import match_watchlist
from soc.llm.provider import LLMProvider, LLMResponse
from soc.models import Flow
from soc.tier2.batch import DeterministicTier2Runner, LLMTier2Runner, run_tier2_from_config


def test_deterministic_tier2_batch_writes_latest_files(tmp_path: Path) -> None:
    config = tmp_path / "config" / "settings.example.yaml"
    config.parent.mkdir()
    config.write_text("tier2:\n  provider: fake\n", encoding="utf-8")

    DeterministicTier2Runner().run(config, tmp_path / "output")

    assert (tmp_path / "output" / "watchlists" / "latest.yaml").exists()
    assert (tmp_path / "output" / "briefs" / "latest.md").exists()
    assert (tmp_path / "output" / "memory" / "latest.md").exists()


def test_run_tier2_from_config_uses_deterministic_provider(tmp_path: Path) -> None:
    config = tmp_path / "config" / "settings.example.yaml"
    config.parent.mkdir()
    config.write_text("tier2:\n  provider: deterministic\n", encoding="utf-8")

    output = run_tier2_from_config(config, tmp_path / "output")

    assert output.metadata["runner"] == "deterministic"
    assert (tmp_path / "output" / "watchlists" / "latest.yaml").exists()


def test_run_tier2_from_config_uses_gemini_fallback_without_api_key(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.delenv("26_AISecApp_Project_GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    config = tmp_path / "config" / "settings.example.yaml"
    config.parent.mkdir()
    config.write_text(
        """
storage:
  enabled: false
tier2:
  provider: gemini
  model: gemini-3-flash-preview
  response_format: json
""".lstrip(),
        encoding="utf-8",
    )

    output = run_tier2_from_config(config, tmp_path / "output")

    assert output.metadata["runner"] == "gemini"
    assert output.metadata["fallback"] is True
    assert "Gemini API key is not set" in output.metadata["fallback_reason"]
    assert (tmp_path / "output" / "watchlists" / "latest.yaml").exists()


def test_deterministic_tier2_watchlist_uses_asset_service_ports(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    assets = config_dir / "assets.yaml"
    assets.write_text(
        """
assets:
  - ip: "172.31.69.25"
    role: "multi-service-server"
    services: ["ssh", "ftp", "http"]
    criticality: "high"
""".lstrip(),
        encoding="utf-8",
    )
    config = config_dir / "settings.example.yaml"
    config.write_text(
        f"""
tier2:
  provider: fake
  sources:
    assets:
      enabled: true
      path: {assets.as_posix()}
""".lstrip(),
        encoding="utf-8",
    )

    output = DeterministicTier2Runner().run(config, tmp_path / "output")
    item = output.watchlist["priority_1"][0]

    assert item["detection_hints"] == [
        {"field": "dst_port", "operator": "in", "value": [21, 22, 80]}
    ]
    assert match_watchlist(
        Flow(
            flow_id="ssh-flow",
            start_ms=None,
            end_ms=None,
            src_ip="18.1.1.1",
            dst_ip="172.31.69.25",
            src_port=12345,
            dst_port=22,
            protocol="6",
        ),
        output.watchlist,
    ).matched is True


class StubTier2Provider(LLMProvider):
    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 2048,
        temperature: float = 0.3,
        response_format: str = "text",
    ) -> LLMResponse:
        content = json.dumps(
            {
                "watchlist": {
                    "priority_1": [
                        {
                            "target_assets": [{"ip": "172.31.69.28", "role": "web"}],
                            "reason": "LLM curated public web risk",
                            "detection_hints": [
                                {"field": "dst_port", "operator": "in", "value": [80, 443]}
                            ],
                        }
                    ],
                    "priority_2": [],
                    "priority_3": [],
                },
                "brief_context": "# Brief\n\nLLM curated brief.",
                "attack_surface_memory": "# Memory\n\nLLM curated memory.",
            },
            ensure_ascii=False,
        )
        return LLMResponse(content=content, tokens_used=42, model_name="stub-tier2", latency_ms=3.0)


def test_llm_tier2_runner_writes_validated_artifacts(tmp_path: Path) -> None:
    config = tmp_path / "config" / "settings.example.yaml"
    config.parent.mkdir()
    config.write_text(
        """
storage:
  enabled: false
tier2:
  provider: ollama
  model: stub-tier2
""".lstrip(),
        encoding="utf-8",
    )

    output = LLMTier2Runner(StubTier2Provider(), runner_name="test-llm").run(
        config,
        tmp_path / "output",
    )

    assert output.metadata["runner"] == "test-llm"
    assert output.metadata["tokens_used"] == 42
    assert output.watchlist["generated_by"] == "stub-tier2"
    assert output.watchlist["priority_1"][0]["target_assets"][0]["ip"] == "172.31.69.28"
    assert (tmp_path / "output" / "briefs" / "latest.md").exists()
