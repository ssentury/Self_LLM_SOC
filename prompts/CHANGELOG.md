# Prompt Changelog

## v1

- Added presentation-aligned Tier 1 and Tier 2 prompt skeletons.
- Tier 1 consumes curated Watchlist & Contexts, not raw source files.

## v2

- Clarified that watchlist matches are inspection guidance, not attack evidence.
- Added Tier 1 guardrails for benign explanations and weak-evidence uncertain
  verdicts.
- Extended Tier 2 watchlist guidance with alert_when and likely_benign_when so
  Tier 1 can separate "watch carefully" from "alert."

## v3

- Reframed watchlist items as scope plus trigger contracts.
- Required priority_1 items to include observable machine-readable trigger
  conditions beyond target asset importance.
- Clarified that asset-only and asset-service matches are context, not alert
  evidence.
