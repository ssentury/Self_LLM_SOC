# AGENTS.md

## Project Context

This repository is for **mini LLM SOC**, a Python-based network security triage pipeline for small organizations.

The main architecture is:
- XGBoost/ML handles cheap first-pass flow routing.
- Tier 2 LLM runs on important asset/threat updates or scheduled cycles and creates **Watchlist & Contexts** files from currently enabled organization/security inputs.
- Tier 1 LLM uses flow/ML evidence plus the Tier 2-generated files to make real-time verdicts.

Implementation source of truth:
- `Knowledge/IMPLEMENTATION_SPEC.md`

Presentation alignment rule:
- The presentation has higher priority than the proposal markdown.
- Do not design Tier 1 as a raw multi-layer context dump. Tier 2 should curate the watchlist/context files that Tier 1 consumes.

## Always Remember

The user understands this project mainly through the presentation deck, not through a full engineering plan. Keep the implementation aligned with the deck's story and explain changes in plain language.

Presentation-first architecture:
- Batch Loop: Tier 2 LLM reads organization/security inputs and prior feedback, then creates Watchlist & Contexts, Attack Surface Memory, and a human-readable summary.
- Real Time Loop: NetFlow/flow logs go through cheap ML routing first. Only selected flows go to Tier 1 LLM with flow context, ML/SHAP evidence, recent source activity, and the Tier 2-generated Watchlist & Contexts.
- Tier 1 must not receive a raw dump of all assets, CVEs, policies, and threat feeds. Tier 2 curates those into files that Tier 1 can consume.

Documentation rule:
- Keep `Knowledge/PROJECT_STRUCTURE.md` updated whenever folders, files, or pipeline responsibilities change.
- That document must stay easy to understand and include an ASCII structure/flow diagram.
- If code behavior and documentation diverge, update the documentation in the same task.

Batch Loop source boundary decision:
- Do not reopen the raw-context question in future sessions.
- Tier 2 is the only layer that reads organization/security source inputs such as assets, policy, CVE feeds, and threat feeds.
- Tier 1 must consume only Tier 2-curated artifacts plus realtime flow/ML/activity evidence.
- MVP source implementations should be YAML-backed providers for the existing `config/*.example.yaml` files.
- The provider boundary should be future-compatible with DB-backed and API-backed sources.
- Each provider should return a source snapshot with status metadata: `used`, `missing`, `disabled`, or `error`, plus source type, path/URI, item count, content, and optional error text.
- Tier 2 prompt builders may include content from `used` snapshots and should include source status summaries. Tier 2 outputs should preserve source status metadata, especially in watchlist files.
- `tier2_runs` persistence and Tier 2 DB summary contracts belong to the future Batch Loop implementation work, not the Real Time Loop completion cleanup.

Environment rule:
- Prefer Docker for repeatable execution, especially when moving between this desktop and the user's laptop.
- Use `docker compose run --rm app python -m pytest` for tests.
- Use Docker commands in README as the canonical setup path. Local `.venv` is optional only.

Windows PowerShell path rule:
- The repository path contains square brackets (`[인공지능보안응용]`), which PowerShell can treat as wildcard syntax.
- When running PowerShell commands in this repo, always enter the workspace with `Set-Location -LiteralPath '<absolute repo path>'`.
- Prefer `-LiteralPath` for file and directory operations. If relative paths behave oddly, resolve files with `Get-ChildItem` and pipe the file objects directly instead of retrying plain relative paths.
- Do not treat these path issues as a broken user environment; they are expected for this Windows path.

Failure handling rule:
- If environment/tooling cleanup fails because of permissions, missing runtimes, or unclear system state, stop and explain the problem before trying stronger workarounds such as ownership changes, permission resets, or repeated alternate deletion methods.
