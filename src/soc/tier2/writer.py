from __future__ import annotations

import shutil
import yaml
from pathlib import Path

from soc.models import Tier2Output


def write_tier2_output(output: Tier2Output, output_dir: str | Path = "output") -> None:
    base = Path(output_dir)
    watchlists = base / "watchlists"
    briefs = base / "briefs"
    memory = base / "memory"
    for directory in (watchlists, briefs, memory):
        directory.mkdir(parents=True, exist_ok=True)

    watchlist_path = watchlists / f"watchlist_{output.cycle_id}.yaml"
    brief_path = briefs / f"brief_context_{output.cycle_id}.md"
    memory_path = memory / f"attack_surface_memory_{output.cycle_id}.md"

    watchlist_path.write_text(yaml.safe_dump(output.watchlist, allow_unicode=True, sort_keys=False), encoding="utf-8")
    brief_path.write_text(output.brief_context, encoding="utf-8")
    memory_path.write_text(output.attack_surface_memory, encoding="utf-8")

    shutil.copyfile(watchlist_path, watchlists / "latest.yaml")
    shutil.copyfile(brief_path, briefs / "latest.md")
    shutil.copyfile(memory_path, memory / "latest.md")
