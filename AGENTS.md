# AGENTS.md

## Project Context

This repository is for **mini LLM SOC**, a Python-based network security triage pipeline for small organizations.

The main architecture is:
- XGBoost/ML handles cheap first-pass flow routing.
- Tier 2 LLM periodically creates **Watchlist & Contexts** files from currently enabled organization/security inputs.
- Tier 1 LLM uses flow/ML evidence plus the Tier 2-generated files to make real-time verdicts.

Implementation source of truth:
- `Knowledge/IMPLEMENTATION_SPEC.md`

Presentation alignment rule:
- The presentation has higher priority than the proposal markdown.
- Do not design Tier 1 as a raw multi-layer context dump. Tier 2 should curate the watchlist/context files that Tier 1 consumes.

