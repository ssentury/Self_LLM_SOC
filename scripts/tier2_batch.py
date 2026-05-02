from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc.tier2.batch import DeterministicTier2Runner


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the mini LLM SOC slow-loop runner.")
    parser.add_argument("--config", default="config/settings.example.yaml")
    parser.add_argument("--output", default="output")
    args = parser.parse_args()
    result = DeterministicTier2Runner().run(config_path=args.config, output_dir=args.output)
    print(f"week_id={result.week_id} watchlist={Path(args.output) / 'watchlists' / 'latest.yaml'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
