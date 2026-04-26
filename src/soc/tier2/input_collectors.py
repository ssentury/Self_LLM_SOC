from __future__ import annotations

from pathlib import Path


def collect_source_status(config_dir: str | Path = "config") -> dict[str, str]:
    base = Path(config_dir)
    return {
        "assets": "used" if (base / "assets.example.yaml").exists() else "missing",
        "cve_feed": "used" if (base / "cve_feed.example.yaml").exists() else "missing",
        "threat_feed": "used" if (base / "threat_feed.example.yaml").exists() else "missing",
        "policy": "used" if (base / "policy.example.yaml").exists() else "missing",
        "tier1_db": "missing",
        "watchlist_feedback": "missing",
    }
