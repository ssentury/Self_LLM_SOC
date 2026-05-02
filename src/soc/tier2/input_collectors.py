from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from soc.models import SourceSnapshot
from soc.storage.sqlite import SQLiteEventStore
from soc.tier2.source_providers import (
    YamlAssetInfoProvider,
    YamlCveInfoProvider,
    YamlPolicyInfoProvider,
    YamlThreatInfoProvider,
)

KST = timezone(timedelta(hours=9))


class Tier2InputCollector:
    """Collects inputs for the Tier 2 Slow Loop from configured sources and DB."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        
    def collect(self) -> list[SourceSnapshot]:
        snapshots: list[SourceSnapshot] = []
        tier2_config = self.config.get("tier2", {})
        sources_config = tier2_config.get("sources", {})

        # YAML Providers
        providers = [
            YamlAssetInfoProvider(sources_config.get("assets", {})),
            YamlPolicyInfoProvider(sources_config.get("policy", {})),
            YamlCveInfoProvider(sources_config.get("cve_feed", {})),
            YamlThreatInfoProvider(sources_config.get("threat_feed", {})),
        ]

        for provider in providers:
            snapshots.append(provider.get_snapshot())

        # DB Stats Provider (Tier1 stats for the last 7 days)
        storage_config = self.config.get("storage", {})
        if storage_config.get("enabled", False) and storage_config.get("sqlite_path"):
            db_path = Path(storage_config["sqlite_path"])
            if db_path.exists():
                try:
                    stats_snapshot = self._collect_tier1_stats(db_path)
                    snapshots.append(stats_snapshot)
                except Exception as e:
                    snapshots.append(
                        SourceSnapshot(
                            name="tier1_db",
                            status="error",
                            source_type="db",
                            path_or_uri=str(db_path),
                            item_count=0,
                            content="",
                            error=f"Failed to collect stats: {e}",
                        )
                    )
            else:
                snapshots.append(
                    SourceSnapshot(
                        name="tier1_db",
                        status="missing",
                        source_type="db",
                        path_or_uri=str(db_path),
                        item_count=0,
                        content="",
                    )
                )
        else:
            snapshots.append(
                SourceSnapshot(
                    name="tier1_db",
                    status="disabled",
                    source_type="db",
                    path_or_uri=None,
                    item_count=0,
                    content="",
                )
            )

        return snapshots

    def _collect_tier1_stats(self, db_path: Path) -> SourceSnapshot:
        store = SQLiteEventStore(db_path)
        stats = store.get_tier1_stats_snapshot(days=7)
        content = json.dumps(stats, ensure_ascii=False, indent=2)
        
        # Item count could be the total number of flow evaluations or just 1 as it's a single snapshot
        item_count = stats.get("total_verdicts", 0)
        
        return SourceSnapshot(
            name="tier1_db",
            status="used",
            source_type="db",
            path_or_uri=str(db_path),
            item_count=item_count,
            content=content,
        )
