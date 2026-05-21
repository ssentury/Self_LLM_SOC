# Productization Roadmap

This document records the remaining productization work after the realtime
pipeline performance pass and the separate day-end summary loop.

The project is presentation-first, but the product shape should stay honest:
the GUI should observe and control a realtime SOC product, while demo input
tools stay outside the product boundary.

## Product Shape

```text
Organization/security inputs
  organization, assets, policy, CVE feed, threat feed, feedback
                         |
                         v
             Tier 2 Context Refresh
        watchlist + brief + attack-surface memory
                         |
                         v
Flow input boundary ---> Realtime Loop ---> SQLite event/report history
 real adapter later        ML first
 manual one-flow input     Tier 1 only when selected
 demo injector
                         |
                         v
                       GUI
```

## Decisions

1. The product needs a flow-level input boundary.
   - A single flow entering that boundary must immediately enter the Realtime
     Loop.
   - The current CSV pipeline should become a caller of the same per-flow core,
     not the only product-shaped entrypoint.
   - A future NetFlow/log adapter can replace the source side without changing
     routing, Tier 1, storage, or GUI contracts.

2. The demo flow sender is separate from the GUI.
   - It may read scenario CSV rows and send them one by one to the product input
     boundary.
   - Speed controls and scenario replay belong to this sender, not to the main
     monitoring UI.
   - This keeps the product UI credible even when a live laptop demo is skipped
     because Tier 1 latency is too high for a short presentation slot.

3. Tier 2 remains a context refresh loop.
   - It reads organization/security source inputs and prior feedback.
   - It can be started manually from the GUI after assets, policy, CVEs, or
     threat inputs change.
   - Tier 1 still receives only realtime flow/ML/activity evidence and Tier
     2-curated artifacts.

4. The GUI should make both loops visible.
   - Realtime Monitoring is the presentation main screen.
   - Tier 2 inputs and curated context need their own visible surfaces so the
     architecture does not look like a raw-context Tier 1 classifier.

## Remaining Work

### P1. Realtime Input Core

- Extract a reusable per-flow realtime service from the current CSV runner.
- Keep ML routing, activity summary, watchlist matching, Tier 1 queueing,
  verdict storage, and event rendering contracts aligned with current behavior.
- Make the existing CSV pipeline call that service so batch-style tests keep
  working.
- Define the ingest result payload the API and GUI will consume.

### P2. Product API

- Add a backend boundary for one-flow ingest.
- Add read endpoints for recent flows, selected flow detail, queue/runtime
  status, latest summary, report archive, source inputs, and Tier 2 artifacts.
- Add a manual Tier 2 context refresh action.
- Keep source-input edits scoped to Tier 2 YAML-backed MVP providers first.

### P3. GUI Shell

- Build a dark SOC dashboard as the home page.
- Home needs:
  - current system situation and alert counters
  - latest summary preview in a scrollable area
  - quick navigation to Inputs, Realtime Monitoring, latest summary, and all
    reports
  - a compact snapshot of current assets/policies/CVEs/threat inputs and active
    Tier 2 context
- Avoid a marketing landing page; the first screen should be the operational
  dashboard.

### P4. Input And Context Pages

- Build the organization/security input page with tabs or sections for:
  - organization profile
  - assets
  - policies
  - CVE feed
  - threat feed
- Show source status and counts.
- Provide the manual Tier 2 refresh action after input changes.
- Build a Tier 2 Context page for:
  - current watchlist
  - brief
  - attack-surface memory
  - refresh timestamp and source status

### P5. Realtime Monitoring Page

- Build the live flow table with flow time, source, destination, protocol/port,
  ML probability, route, verdict, severity, and watchlist hit.
- Show selected-flow detail:
  - flow fields
  - ML evidence and SHAP when present
  - route reason
  - Tier 1 verdict and recommended action
  - watchlist match details
  - fallback state
- Show Tier 1 queue/runtime state and the active Tier 2 context snapshot.

### P6. Organization Topology View

- Generate a small-organization structure view from the asset inputs and zones.
- Show grouped assets such as external/public, DMZ, internal apps, DBs, backup,
  admin, and workstations when the input data supports them.
- Place this graph on the Realtime Monitoring page.
- Highlight the source and destination of the selected flow.
- If time permits, light recent flow edges briefly and keep alert edges visibly
  stronger than normal traffic.
- Treat this as an operator-facing asset relationship view, not a claim of
  fully discovered network topology.

### P7. Reports Experience

- Build the latest-summary page with the easy text, statistics, important
  alerts, and recommended first checks.
- Build the all-reports page with daily summaries and event reports.
- Add filters that matter for presentation and operator review: date, severity,
  verdict, asset, and watchlist hit.

### P8. Demo Flow Injector

- Add a simple tool that reads scenario flow CSV files and calls the product
  flow input boundary one row at a time.
- Support target endpoint, speed/interval, and scenario/day selection where
  practical.
- Keep it useful for recorded demonstrations even when no live LLM demo is
  attempted on the presentation laptop.

## Suggested Build Order

1. Realtime Input Core
2. Product API
3. GUI Shell and Realtime Monitoring skeleton
4. Inputs and Tier 2 Context pages
5. Topology View
6. Reports archive polish
7. Demo Flow Injector

## Presentation Check

The finished product surface should make this explanation easy:

1. Tier 2 prepares context from organization and security inputs.
2. New flows enter a realtime input boundary and ML routes them first.
3. Only selected flows reach Tier 1 with curated context.
4. Operators can inspect flow evidence, current context, topology, and reports
   from one dark SOC UI.

