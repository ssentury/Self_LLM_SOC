from pathlib import Path

from soc.context.watchlist import match_watchlist
from soc.models import Flow
from soc.tier2.batch import DeterministicTier2Runner


def test_deterministic_tier2_batch_writes_latest_files(tmp_path: Path) -> None:
    config = tmp_path / "config" / "settings.example.yaml"
    config.parent.mkdir()
    config.write_text("tier2:\n  provider: fake\n", encoding="utf-8")

    DeterministicTier2Runner().run(config, tmp_path / "output")

    assert (tmp_path / "output" / "watchlists" / "latest.yaml").exists()
    assert (tmp_path / "output" / "briefs" / "latest.md").exists()
    assert (tmp_path / "output" / "memory" / "latest.md").exists()


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
