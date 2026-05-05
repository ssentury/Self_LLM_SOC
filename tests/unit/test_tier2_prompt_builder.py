from pathlib import Path

from soc.models import SourceSnapshot
from soc.tier2.prompt_builder import build_tier2_system_prompt
from soc.tier2.prompt_builder import build_tier2_user_prompt


def test_build_tier2_system_prompt_reads_markdown_file(tmp_path: Path) -> None:
    prompt = tmp_path / "tier2_system.md"
    prompt.write_text("custom Tier 2 prompt\n", encoding="utf-8")

    assert build_tier2_system_prompt(prompt) == "custom Tier 2 prompt"


def test_build_tier2_system_prompt_default_uses_repo_prompt_file() -> None:
    system_prompt = build_tier2_system_prompt()

    assert "Tier 2 System Prompt" in system_prompt
    assert "attack_surface_memory" in system_prompt


def test_build_tier2_user_prompt_includes_configurable_memory_limit() -> None:
    prompt = build_tier2_user_prompt(
        cycle_id="20260502T000000+0000",
        snapshots=[
            SourceSnapshot(
                name="assets",
                status="used",
                source_type="yaml",
                path_or_uri="config/assets.example.yaml",
                item_count=1,
                content="assets: []",
            )
        ],
        attack_surface_memory_max_chars=3000,
    )

    assert "Keep attack_surface_memory under 3000 Korean characters." in prompt
