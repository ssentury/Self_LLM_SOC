from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc.tier2.batch import run_tier2_from_config


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the mini LLM SOC slow-loop runner.")
    parser.add_argument("--config", default="config/settings.example.yaml")
    parser.add_argument("--output", default="output")
    parser.add_argument("--provider", choices=["deterministic", "fake", "ollama", "gemini"])
    parser.add_argument("--model")
    parser.add_argument("--ollama-url")
    parser.add_argument("--gemini-api-key-env")
    parser.add_argument("--gemini-api-base-url")
    parser.add_argument("--timeout-seconds", type=float)
    parser.add_argument("--max-tokens", type=int)
    parser.add_argument("--temperature", type=float)
    parser.add_argument("--response-format", choices=["text", "json"])
    args = parser.parse_args()
    result = run_tier2_from_config(
        config_path=args.config,
        output_dir=args.output,
        overrides={
            "provider": args.provider,
            "model": args.model,
            "ollama_url": args.ollama_url,
            "gemini_api_key_env": args.gemini_api_key_env,
            "gemini_api_base_url": args.gemini_api_base_url,
            "timeout_seconds": args.timeout_seconds,
            "max_tokens": args.max_tokens,
            "temperature": args.temperature,
            "response_format": args.response_format,
        },
    )
    fallback = result.metadata.get("fallback_reason")
    print(
        f"week_id={result.week_id} "
        f"runner={result.metadata.get('runner')} "
        f"model={result.metadata.get('model')} "
        f"watchlist={Path(args.output) / 'watchlists' / 'latest.yaml'}"
    )
    if fallback:
        print(f"fallback_reason={fallback}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
