from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc.summary.daily import run_daily_summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate the day-end easy summary from stored realtime SOC results."
    )
    parser.add_argument("--sqlite", default="output/soc_events.sqlite")
    parser.add_argument("--date", dest="summary_date", help="Local summary date in YYYY-MM-DD form.")
    parser.add_argument("--timezone", default="Asia/Seoul")
    parser.add_argument("--output", default="output/daily_summaries")
    parser.add_argument("--max-alerts", type=int, default=5)
    args = parser.parse_args()

    summary = run_daily_summary(
        args.sqlite,
        args.output,
        summary_date=args.summary_date,
        timezone_name=args.timezone,
        max_alerts=args.max_alerts,
    )
    print(
        f"date={summary['date']} flows={summary['flow_count']} "
        f"risk={summary['risk_level']} latest={Path(args.output) / 'latest.md'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

