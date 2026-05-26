from pathlib import Path

import pytest

from soc.demo.gui_server import _day_dir_name, _scenario_source_paths


def test_day_dir_name_normalizes_day_tokens() -> None:
    assert _day_dir_name("5") == "day05"
    assert _day_dir_name("day03") == "day03"


def test_scenario_source_paths_use_generated_regional_day() -> None:
    paths = _scenario_source_paths("regional_care_dynamic_cve", "day05")

    assert paths["organization"] == str(
        Path("config/scenarios/regional_care_dynamic_cve/generated/day05/organization.yaml")
    )
    assert paths["assets"].endswith("generated/day05/assets.yaml")


def test_scenario_source_paths_reject_unknown_scenario() -> None:
    with pytest.raises(ValueError):
        _scenario_source_paths("unknown")
