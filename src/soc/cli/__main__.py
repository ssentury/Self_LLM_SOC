from __future__ import annotations

import argparse

from soc.cli import pipeline


def main() -> int:
    parser = argparse.ArgumentParser(description="Mini LLM SOC command group.")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("pipeline", help="Run the real-time loop scaffold.")
    args, rest = parser.parse_known_args()
    if args.command == "pipeline":
        return pipeline.main(rest)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
