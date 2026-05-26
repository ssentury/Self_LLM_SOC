# Project Structure

## Day-End Daily Summary Loop

The day-end summary is separate from the Tier 2 context refresh. Tier 2 prepares
curated context for current or upcoming realtime decisions; the Daily Summary
Loop reads stored realtime results after a local operating day ends, then uses
the configured Tier 2 LLM provider to write the operator-facing summary text and
first-check recommendations. Deterministic SQLite aggregation remains the source
of truth for counts and is used as a fallback if no Tier 2 LLM provider is
configured or the LLM call fails. Summary artifacts include generation metadata
such as `mode`, `llm_called`, provider/model, token counts, latency, and fallback
reason when relevant.

```text
SQLite Event Store
 flows + route decisions + verdicts + Tier 1 calls
             |
             v
scripts/daily_summary.py
   - slices one local day by flow start timestamp
   - falls back to stored created_at only when a flow lacks start_ms
   - aggregates routes, verdicts, watchlist hits, fallbacks, and Tier 1 calls
   - Product API passes the configured Tier 2 LLM provider for narrative fields
   - standalone script mode writes deterministic fallback text unless extended
     with a provider
             |
             v
 output/daily_summaries/summary_YYYY-MM-DD.json
 output/daily_summaries/summary_YYYY-MM-DD.md
 output/daily_summaries/latest.json
 output/daily_summaries/latest.md
```

`Knowledge/PRODUCTIZATION_ROADMAP.md` records the remaining GUI, per-flow input
boundary, topology, API, and demo-injector work after this summary loop.

## Product GUI Runtime

The product GUI is the operator-facing demo shell for the same presentation-first
pipeline. It does not give Tier 1 raw organization/security inputs. The GUI
edits and saves those source files for Tier 2, then Tier 2 curates the watchlist,
brief, and memory files that Tier 1 later consumes.

```text
Browser first-run setup
  choose Tier 1/Tier 2 LLM provider and model
  optional Gemini API key entry
  Ollama/Gemini preflight through Product API
             |
             v
Product API runtime settings
             |
             +--> starts/checks Ollama when an Ollama provider is selected
             +--> checks Gemini API key/connectivity when Gemini is selected
             |
             v
Main GUI
  Inputs page
    - structured add forms for organization, assets, policy, CVE, and threat feed
    - raw YAML editor for exact source-file edits
    - source metadata kept in the side panel
  Tier 2 Context page
    - Refresh Tier 2 runs the Batch Loop and shows a status message
    - source status is below Watchlist And Context Files
  Realtime page
    - live table shows at most the latest 100 visible flows
    - full flow modal pages through recent stored events
    - optional Hide benign filter
    - topology aggregates inter-zone flow lines through group gateways
    - Tier 1 LLM work is scheduled by the Product API queue using settings
      worker/max-size/timeout values, so live POST bursts do not bypass queue
      backpressure
```

## Current Curated-Trigger Flow

The current implementation keeps the presentation-first boundary intact:
Tier 2 is the only layer that reads organization/security source inputs, and
Tier 1 consumes only Tier 2 artifacts plus realtime flow, ML, and activity
evidence.

```text
                 [ Batch Loop: Tier 2 only ]

 YAML-backed source providers
 organization/assets/policy/CVE/threat feed + SQLite feedback
             |
             v
       SourceSnapshot list
             |
             v
 Tier 2 LLM or deterministic runner
             |
             v
 parse_tier2_response()
             |
             v
enhance_watchlist_quality()
  - preserves alert_when / likely_benign_when
  - adds missing observable hints when source-backed
  - adds routing_policy from source-backed review-worthy conditions
  - can synthesize source-CIDR scoped patterns from threat feed inputs
  - adds trigger_groups for source-wide patterns so Tier 1 can see which
    attack conditions did and did not match
  - adds benign_hints for approved infrastructure flows such as internal DNS/NTP
  - leaves weak P1 items context_only through the linter
             |
             v
 output/watchlists/latest.yaml
 output/briefs/latest.md
 output/memory/latest.md


                [ Real Time Loop: Tier 1 ]

 product input boundary: one Flow
             |
             v
 RealtimeIngestService.prepare_flow()
   - builds ML features
   - reads recent source activity from SQLite or same-run memory
   - matches Tier 2 watchlist
   - routes the flow before any Tier 1 call
             |
             v
match_watchlist()
   - target_assets are scope only
   - scope conditions are separated from trigger evidence
   - trigger_groups can require AND-style conditions before a review trigger is complete
   - unmatched trigger hints and matched benign hints are preserved for Tier 1
   - asset_only / asset_service are context only
   - review_candidate / behavioral_review are middle-strength review triggers
   - behavior / threat_source / policy_violation / critical_forbidden are strong review triggers
             |
             v
route_flow()
  - applies dynamic review threshold for review-worthy priority_1 matches
  - does not apply watchlist threshold drops to scope-only or partial trigger evidence
  - never turns routing_policy into auto_alert
             |
             v
 auto verdict or Product API / CLI Tier 1 worker queue
             |
             v
 Tier 1 prompt payload
   flow + ML/SHAP + structured SourceActivitySummary
   + matched Tier 2 watchlist fields + brief excerpt
   + flow_context, matched/unmatched trigger hints, and benign hints
   + no raw source YAML
```

이 문서는 폴더와 파일의 역할을 쉽게 설명하는 안내서입니다. 작업을 하면서 구조나 책임이 바뀌면 이 문서도 같이 갱신합니다.

## 한 줄 요약

이 프로젝트는 발표자료의 구조를 따라갑니다.

- Batch Loop: Tier 2가 조직 지식과 보안 입력을 정리해서 Watchlist & Contexts를 만듭니다.
- Real Time Loop: NetFlow/flow가 ML을 먼저 지나고, 필요한 경우 Tier 1이 Watchlist & Contexts를 참고해 판정합니다.

## 전체 그림

```text
                         [ Batch Loop ]

  config/organization.example.yaml
  config/assets.example.yaml
  config/policy.example.yaml
  config/cve_feed.example.yaml
  config/threat_feed.example.yaml
  SQLite Event Store + previous feedback
             |
             v
      Tier 2 strategy layer
             |
             +--> output/watchlists/latest.yaml
             +--> output/briefs/latest.md
             +--> output/memory/latest.md
             +--> Tier 1 consumes latest curated files


                      [ Real Time Loop ]

  Demo Flow Injector / NetFlow adapter
  data/sample scenario CSV rows
             |
             v
  Product API one-flow ingest
             |
             v
     RealtimeIngestService
             |
             v
       ML Binary Router
             |
             v
       Route Decision
      /      |       \
 dismiss   alert    Tier 1 queue
             |       |
             v       v
       optional Multiclass Hint
       (explanation only; never routing)
             |
             v
       Tier 1 LLM worker(s)
     \       |       /
      \      |      /
       v     v     v
          SQLite Event Store
             |                 \
             v                  v
      output/reports/*.html   Product API read endpoints
```

## Scenario Design Notes

`Knowledge/DYNAMIC_CVE_SCENARIO_DESIGN.md` defines the next evaluation scenario
contract: a 5-day, 1000-flow regional-care scenario with staged CVE feed changes
on day 3 and day 5. It records the presentation-aligned data generation rules
for feature preservation, source-backed benign windows, attack-label feature
mapping, daily source snapshots, and CVE-focused evaluation slices.

`config/scenarios/regional_care_dynamic_cve/` contains the concrete source
inputs for that scenario. `base/` holds the day-1/day-2 organization, asset,
policy, CVE, and threat-feed YAML. `overlays/` holds the day-3 Tomcat CVE
addition, the day-4 small inventory/IOC drift with no new CVE, and the day-5
FortiManager CVE addition. `flow_plan.yaml` fixes the 5-day, 1000-flow design:
180 benign and 20 malicious flows per day, explicit attack slots, benign
profile counts, attack-family mappings, and source-state expectations.

`config/settings.regional_care_dynamic_cve_xgb.yaml` is the runtime settings
entry point for the model-backed dynamic-CVE evaluation. It points at the base
source state; `scripts/evaluate_dynamic_cve_memory_cycle.py` replaces those
source paths with `generated/day01..day05` snapshots before each Tier 2 Batch
Loop run.

`scripts/generate_regional_care_dynamic_cve_xgb_flows.py` generates the actual
model-backed dynamic-CVE CSV from `Dataset/NF-CICIDS2018-v3.csv`. It writes
`data/sample/regional_care_dynamic_cve_flows_xgb.csv`, the matching manifest,
and `config/scenarios/regional_care_dynamic_cve/generated/day01..day05/`
source snapshots. `tests/integration/test_dynamic_cve_scenario_inputs.py`
checks the generated 1000-flow shape, XGBoost feature contract, CVE timeline,
Tier 2 source-provider connectivity, and the runner's day-specific source
selection.

`Knowledge/DYNAMIC_CVE_SCENARIO_KO.md` is a short Korean explanation of the same
scenario for presentation preparation and teammate handoff.

## ML Runtime Addendum

The CICIDS2018 binary XGBoost v1 router has been trained on the GPU workstation
and copied into this repository as a small committed runtime artifact. The goal
of the current ML layer is cheap routing, not final SOC judgment.

```text
src/soc/ml/features.py
  Defines the binary ML feature contract:
  - fixed feature order
  - excluded leak-prone fields
  - categorical feature list
  - attack hint label mapping for the later multiclass helper model
  It also builds the detector input dict from a Flow so core fields such as
  L4_DST_PORT and PROTOCOL are present during inference.

scripts/ml_train.py
  GPU-workstation training entrypoint for the CICIDS2018 binary XGBoost router.
  It uses stratified train/validation/test as the primary split, records
  time-split diagnostics, selects routing thresholds on validation, and writes
  model, metadata, metrics, and thresholds under output/models/.
  The default auto-dismiss attack leak target is 1.0%, with 0.5% recorded as
  the ideal best-effort target.

scripts/ml_train_multiclass.py
  GPU-workstation training entrypoint for the optional attack-family hint model.
  It uses the same CICIDS2018 feature contract as the binary router, filters to
  attack rows only, maps the raw Attack column through ATTACK_HINT_LABEL_MAP, and
  writes xgb_attack_hint_v1 model, metadata, and metrics artifacts under
  output/models/. This model is explanation evidence only, not route selection.

output/models/xgb_binary_v1*.json
  Trained XGBoost model artifacts copied from the GPU workstation. These
  small v1 artifacts are kept in Git so the project can move cleanly between
  development machines without retraining.
  The runtime routing default uses:
    low_threshold = 0.30
    high_threshold = 0.95

src/soc/ml/detector.py
  DummyDetector remains the offline smoke-test detector.
  XGBoostDetector now loads the trained model and metadata, validates the
  feature contract, applies categorical encoders, and returns MLResult.prob.
  XGBoostDetector can also load the optional xgb_attack_hint_v1 multiclass model.
  The pipeline calls it only after binary routing for auto_alert and tier1_llm
  events. auto_dismiss records category_hint=not_evaluated. SHAP top5 is still
  computed only for the tier1_llm route, so auto_dismiss and auto_alert stay
  cheap.

src/soc/cli/pipeline.py
  Supports:
    --config config/settings.example.yaml
    --detector dummy
    --detector xgboost --model ... --metadata ... --thresholds ...
    --category-model ... --category-metadata ...
    --llm fake
    --llm ollama --llm-model gemma4:e4b --ollama-url ...
    --sqlite output/soc_events.sqlite
    --no-storage
    --tier1-mode sequential
    --tier1-mode queue --tier1-workers ... --tier1-queue-max-size ...
  The pipeline passes L4_DST_PORT and PROTOCOL back into the detector feature
  surface so training and inference use the same feature order.
  It also keeps SHAP evidence limited to tier1_llm events before report/LLM
  rendering. Category hints are route-after evidence only and never change
  binary route decisions.
  Queue mode runs as a producer-consumer bounded queue. The producer routes each
  flow through cheap ML, completes auto_dismiss and auto_alert immediately, and
  enqueues only tier1_llm events. Worker tasks consume the queue concurrently.
  When storage is enabled, every flow writes flow, ML result, route decision,
  verdict, and Tier 1 call/fallback metadata to SQLite before HTML rendering.
  Queue overflow, timeout, or call-limit cases produce uncertain/medium fallback
  verdicts instead of silently dropping events.
  CLI options override config file values. This keeps the YAML file as the
  dashboard-friendly source of runtime settings while preserving quick one-off
  experiments from the terminal.

data/sample/xgb_route_sample.csv
  Small tracked sample generated from CICIDS2018 for model-backed route smoke
  testing. It contains examples for auto_dismiss, tier1_llm, and auto_alert.
  The XGBoost integration test uses it to verify SHAP evidence appears in the
  tier1_llm HTML report.

data/sample/clinic_telehealth_flows_xgb.csv
  Model-backed clinic scenario sample generated separately from the older
  prompt-control CSV. It has 300 rows across 2026-05-02 through 2026-05-04,
  preserves the NF-CICIDS2018-v3 model feature contract, and intentionally has
  no mock_prob column. Benign rows are selected from source-order benign
  NF-CICIDS2018 traffic by service port, while attack rows use real attack-label
  feature vectors projected into the clinic asset/IP/time context.

data/sample/clinic_telehealth_flows_xgb_manifest.json
  Generation manifest for the model-backed clinic sample. It records the source
  dataset, scanned row count, label/attack/scenario counts, feature order, and
  per-flow source trace. Any organization-driven feature projection, such as
  mapping a SQL_Injection profile onto the clinic postgres port 5432, is listed
  here for auditability.

config/settings.clinic_scenario_xgb.yaml
  Runtime config for the model-backed clinic scenario. It points at
  clinic_telehealth_flows_xgb.csv and uses the trained XGBoost binary router,
  optional attack-family hint model, and SHAP evidence path instead of
  DummyDetector/mock_prob.

output/reports_xgb_sample/
  Local generated HTML sample from the XGBoost route smoke path. It is useful
  for manual inspection but remains an output artifact.
  It also has a --preflight-only mode for new machines. That mode loads and
  validates the dataset, prints distribution counts, and stops before training.
  Full training prints timestamped progress logs and periodic XGBoost evaluation
  output so long GPU runs are observable.

evaluation_artifacts/clinic_memory_cycle_eval_prompt_v1/
  Tracked evaluation artifact for one full clinic telehealth prompt-v1 run.
  Generated output/ paths remain ignored; this copied result lives outside
  output/ so shared experiment records are separated from normal runtime
  scratch files. It contains the three-day flow set, per-day settings and
  metrics, Tier 2 watchlist/brief/memory artifacts, HTML reports, the full
  SQLite event store, and `평가_결과_해석.md` explaining the run identity,
  result interpretation, and scenario limits. Add future shared test results
  as explicit named folders under evaluation_artifacts/.

evaluation_artifacts/clinic_memory_cycle_eval_current_full_guardrails_v3/
  Tracked evaluation artifact for the full clinic telehealth run after the
  watchlist trigger guardrail changes. It preserves the Gemini Tier 2 and local
  Ollama Tier 1 outputs, comparison notes against prompt v1, and a scenario
  reliability assessment in `평가_결과_해석.md` that explains what the synthetic
  case can and cannot prove.

evaluation_artifacts/eval_clinic_v6_review_strength_sync_8192/
  2026-05-19 full clinic telehealth rerun after syncing reviewable watchlist
  strengths across the router and Tier 1 queue priority. It uses Gemini Tier 2
  with `tier2-max-tokens=8192` and local Ollama Tier 1. The earlier 4096-token
  retry attempt is preserved separately in
  `evaluation_artifacts/eval_clinic_v6_review_strength_sync/` because Gemini
  returned truncated JSON on day 2 and the evaluator refused deterministic
  fallback.

evaluation_artifacts/eval_dynamic_cve_v2_review_strength_sync_8192/
  2026-05-19 full regional-care dynamic CVE rerun after the same watchlist
  review-strength sync. It preserves all five day-specific source snapshots,
  Gemini Tier 2 outputs, realtime reports, SQLite events, and aggregate metrics.

evaluation_artifacts/review_strength_sync_comparison_20260519/
  Comparison bundle for the 2026-05-19 reruns. `comparison_metrics.json`
  contains structured old-vs-new metrics against
  `eval_clinic_v5_dynamic_threshold` and
  `eval_dynamic_cve_v1_dynamic_threshold`; `analysis.md` explains the expected
  recall gains and the dynamic-CVE DNS false-positive regression.
  `dynamic_fp_root_cause_deep_dive.md`, `dynamic_fp_detail.json`, and
  `dynamic_fp_detail.csv` break down the 153 dynamic-CVE false positives by
  day, flow family, watchlist item, match strength, ML probability band,
  matched condition, and route reason.

evaluation_artifacts/eval_clinic_v7_gemini35_flash_20260521/
  2026-05-21 partial clinic telehealth run with Gemini 3.5 Flash and
  `tier2-max-tokens=8192`. It is preserved as a failed compatibility artifact
  because Gemini returned truncated JSON and the evaluator refused deterministic
  fallback.

evaluation_artifacts/eval_clinic_v7_gemini35_flash_16384_20260521/
  2026-05-21 completed clinic telehealth rerun with Gemini 3.5 Flash,
  `tier2-max-tokens=16384`, and local Ollama Tier 1. It preserves the three
  day-specific settings, Tier 2 outputs, realtime reports, SQLite events, and
  aggregate metrics.

evaluation_artifacts/eval_dynamic_cve_v3_gemini35_flash_16384_20260521/
  2026-05-21 completed regional-care dynamic CVE rerun with Gemini 3.5 Flash,
  `tier2-max-tokens=16384`, and local Ollama Tier 1. It preserves all five
  day-specific source snapshots, Tier 2 outputs, realtime reports, SQLite
  events, and aggregate metrics.

evaluation_artifacts/gemini35_flash_comparison_20260521/
  Comparison bundle for the 2026-05-21 Gemini 3.5 Flash reruns.
  `comparison_metrics.json` contains structured metrics against the 2026-05-19
  `gemini-3-flash-preview` runs; `analysis.md` explains the clinic regression,
  dynamic-CVE precision recovery, token/cost changes, and the 8192-token
  truncation finding.

requirements-ml.txt
  ML runtime and training dependencies. Docker installs this file so the
  XGBoost detector path is reproducible across both development machines.

Knowledge/GPU_TRAINING_HANDOFF.md
  Exact handoff instructions for the GPU Codex session. It explains the fixed
  feature contract, split policy, threshold policy, SHAP policy, and which
  output files must be copied back.

Knowledge/PROMPT_ENGINEERING_AND_SIMULATION_GUIDE.md
  기준 문서입니다. Tier 2/Tier 1 프롬프트, Batch Loop 산출물 형식,
  Attack Surface Memory, 평가 지표, 시연용 시뮬레이션 케이스를 설계할 때
  사용자의 최신 의도를 반복 설명 없이 이어가기 위해 둡니다.
```

## 2026-05-01 Real Time Loop Hardening

The Real Time Loop is now treated as model-backed by default while staying
repeatable without a live local LLM.

```text
config/settings.example.yaml
  runtime.input: data/sample/xgb_route_sample.csv
  detector.provider: xgboost
  tier1.queue.mode: queue
  tier1.llm.provider: fake
  tier1.llm.max_tokens: 4096
  tier1.llm.retry_attempts: 1
  tier1.llm.retry_backoff_seconds: 2
```

Use `--llm ollama --llm-model gemma4:e4b --ollama-url ...` when validating the
real local Tier 1 model. The fake provider remains the default because it keeps
Docker tests and laptop handoff runs deterministic.

Tier 1 LLM response handling:

```text
soc.llm.tier1.judge_flow
  -> calls provider with tier1.llm.max_tokens, default 4096
  -> retries transient provider/API failures once by default
     (timeouts, connection resets, 429, and 5xx)
  -> does not retry MAX_TOKENS; raise tier1.llm.max_tokens instead
  -> parses JSON
  -> accepts only verdict in benign/alert/uncertain
  -> accepts only severity in low/medium/high/critical
  -> invalid JSON or invalid schema becomes uncertain/medium fallback
  -> preserves provider model, token count, and latency metadata

SQLiteEventStore.tier1_calls
  -> records provider, model_name, latency_ms, tokens_used, success,
     fallback_reason for every Tier 1 path event when storage is enabled
```

Multiclass attack-family hint boundary:

```text
XGBoostDetector.predict()
  -> binary probability only; this decides routing thresholds

XGBoostDetector.predict_category_hint()
  -> optional attack-family hint model
  -> evaluated only after binary routing
  -> used for auto_alert and tier1_llm evidence
  -> never changes auto_dismiss / tier1_llm / auto_alert route selection

XGBoostDetector.explain()
  -> SHAP top5 evidence
  -> computed only for tier1_llm to keep cheap paths cheap
```

Batch Loop work should build on this boundary. Tier 2 should consume SQLite
history and enabled organization/security inputs, then curate watchlist,
brief, and memory files. It should not push raw asset/CVE/policy/threat-feed
dumps into Tier 1.

## Watchlist Semantics

Watchlist entries are review guidance, not attack evidence. Tier 2 decides which
assets and flow patterns deserve closer inspection, while Tier 1 decides whether
the current flow shows concrete suspicious behavior.

```text
Tier 2 watchlist item
  -> target_assets + detection_hints: when to route/review more carefully
  -> routing_policy: optional Tier 2 instruction to lower only the Tier 1 review threshold
  -> alert_when: extra behavior needed before Tier 1 should alert
  -> likely_benign_when: normal explanations Tier 1 should check first

Tier 1 verdict
  -> alert only with flow/ML/activity evidence of suspicious behavior
  -> uncertain when watchlist context matters but evidence is weak
  -> benign when normal business traffic explains the flow
```

This prevents "important asset" from becoming "attack" by itself and keeps the
Batch Loop / Real Time Loop split aligned with the presentation.

Implementation boundary:

```text
scope-only match
  -> match_strength=asset_only or asset_service
  -> no watchlist threshold lowering
  -> Tier 1 may receive it only when ML already enters the review band

middle-strength review match
  -> match_strength=review_candidate or behavioral_review
  -> priority_1 may lower the Tier 1 review threshold enough to give Tier 1 a review chance
  -> used for combinations like sensitive asset + unknown external egress,
     source CIDR + risky service, or workstation + non-approved destination

strong review match
  -> match_strength=behavior, threat_source, policy_violation, or critical_forbidden
  -> priority_1 may lower the Tier 1 review threshold further, using routing_policy when present
  -> used for known bad sources, repeated behavior, clear policy violations,
     metadata-service access, or repeated unapproved external DNS
  -> Tier 1 still needs current-flow evidence before alert
```

The watchlist loader/parser lints Tier 2 artifacts. Priority 1 items without a
reviewable machine-readable trigger are marked `context_only` and emit linter
warnings, so future test scenarios do not require case-by-case routing patches.
`routing_policy.review_threshold` is ignored on weak/context-only matches and
never changes the global ML thresholds or the auto-alert path.

`target_assets` may scope either a destination asset or a source CIDR. Concrete
asset IPs remain preferred for destination-focused items. Source-wide behavior
such as workstation DNS tunneling can use a CIDR target with `match: src`, while
the actual risky service and destination direction stay in `detection_hints`.

## Batch Loop Source Boundary Decision

This decision is fixed for future sessions and should not be reopened unless
the user explicitly asks to redesign the architecture.

```text
config/organization.example.yaml
config/assets.example.yaml
config/policy.example.yaml
config/cve_feed.example.yaml
config/threat_feed.example.yaml
        |
        v
YAML-backed InfoProviders for the MVP
        |
        v
SourceSnapshot(name, status, source_type, path_or_uri, item_count, content, error)
        |
        v
      Tier2InputCollector
             |
             v
      Tier 2 LLM prompt builder
             |
             +--> deterministic runner for repeatable smoke tests
             +--> Ollama provider for local Tier 2 experiments
             +--> Gemini provider for API-backed Tier 2 Flash runs
             |
             v
watchlist + brief + memory
        |
        v
Tier 1 consumes curated outputs only
```

The MVP reads the planned YAML files through provider implementations. That is
not a raw Tier 1 context dump. It is the first implementation of a stable
provider boundary that can later support DB-backed or API-backed providers:

```text
YamlOrganizationInfoProvider -> later DbOrganizationInfoProvider
YamlAssetInfoProvider        -> later DbAssetInfoProvider
YamlPolicyInfoProvider       -> later DbPolicyInfoProvider
YamlCveInfoProvider          -> later ApiCveInfoProvider
YamlThreatInfoProvider       -> later ThreatIntelApiProvider
```

## 2026-05-04 Gemini Tier 2 Provider

Gemini is attached only to the Batch Loop. It implements the same
`LLMProvider.generate()` contract as Ollama and is selected with
`tier2.provider: gemini` or `scripts/tier2_batch.py --provider gemini`.
`tier2.attack_surface_memory_max_chars` controls the runtime memory length
limit; the example config currently sets it to 3000 Korean characters.

```text
Tier2InputCollector
        |
        v
prompts/tier2_system.md + build_tier2_user_prompt
        |
        v
GeminiProvider
  model: gemini-3.5-flash by default
  API key env: 26_AISecApp_Project_GEMINI_API_KEY
  endpoint: Gemini generateContent REST API
  response_format=json -> responseMimeType=application/json
  non-STOP finish reasons, including MAX_TOKENS, are reported as provider errors
  so Tier 2 fallback metadata points at truncation instead of a generic parse error
        |
        v
parse_tier2_response
        |
        v
output/watchlists/latest.yaml
output/briefs/latest.md
output/memory/latest.md
```

This does not change the source boundary. Gemini receives the Tier 2 prompt
built from `SourceSnapshot` records and produces curated artifacts. Tier 1 still
receives only realtime flow/ML/activity evidence plus Tier 2-curated files, not
raw organization/security source dumps. The Pro model can be supplied later by
changing `tier2.model`; Flash remains the default because it is the intended
cost-controlled Tier 2 API path.

Each provider returns a source snapshot with:

```text
name: organization | assets | policy | cve_feed | threat_feed | feedback | ...
status: used | missing | disabled | error
source_type: yaml | db | api
path_or_uri: config/assets.example.yaml or API/DB identifier
item_count: number of loaded records or rules
content: normalized provider payload
error: parse/load/fetch error text, or null
```

`status` metadata is required because Tier 2 must distinguish a legitimately
empty source from a missing, disabled, or broken source. Tier 2 prompt builders
should include content only from `used` snapshots, while still including a
compact status summary for all enabled or configured sources. Tier 2 outputs
should preserve this status summary, especially in `watchlists/latest.yaml`.

`tier2_runs` persistence and a formal Tier 2 DB summary contract are Batch Loop
implementation tasks. They are not required to declare the current Real Time
Loop complete.

Current ML boundary:

```text
Repository:
  trained XGBoost v1 model + metadata + thresholds are present
  Docker installs the ML runtime dependencies
  tests cover dummy smoke and XGBoost+SHAP route smoke

GPU workstation:
  used only when retraining xgb_binary_v1 or creating a later model version
```

## 폴더 역할

```text
.
|-- AGENTS.md
|   다음 작업자가 반드시 기억해야 할 프로젝트 규칙입니다.
|
|-- Knowledge/
|   발표자료, 구현 명세, 제안서, 쉬운 구조 설명, 프롬프트/시뮬레이션 설계 지침을 둡니다.
|
|-- config/
|   Batch Loop가 읽을 조직/보안 입력 예시입니다. organization은 짧은 업무 맥락,
|   assets/policy/CVE/threat feed는 보안 판단 원천 입력입니다.
|   settings.clinic_scenario.yaml은 프롬프트 테스트용 가상 의료/예약 서비스
|   시나리오를 한 번에 연결합니다.
|
|-- data/
|   샘플 입력 데이터입니다. 큰 원본 데이터셋은 Dataset/에 있고 Git에는 올리지 않습니다.
|   data/sample/clinic_telehealth_flows.csv는 프롬프트 테스트용 공격/비공격
|   3일치 300개 flow 세트입니다. 하루 100개씩 들어 있고, 악성은 10%입니다.
|   악성 flow는 ML이 바로 auto_alert로 걸러야 하는 명백한 공격과 Tier 1이
|   맥락을 봐야 하는 정교한 공격을 반반 섞습니다.
|
|-- src/soc/
|   실제 Python 패키지입니다.
|
|-- scripts/
|   사람이 직접 실행하는 CLI wrapper입니다.
|
|-- prompts/
|   Tier 1, Tier 2 프롬프트와 변경 이력입니다.
|
|-- tests/
|   단위 테스트와 통합 smoke test입니다.
|
|-- evaluation_artifacts/
|   Slow or device-dependent experiment results intentionally promoted to Git.
|   These are copied out of output/ so only selected analysis artifacts are
|   shared across PCs.
|
|-- output/
|   실행 결과가 생성되는 위치입니다. 최신 watchlist, brief, memory, report가 여기에 생깁니다.
|
|-- Dockerfile
|   Python 3.11 실행 환경을 Docker 이미지로 고정합니다. 테스트와 XGBoost 런타임 의존성을 함께 설치합니다.
|
|-- compose.yaml
|   Docker 명령을 짧게 실행하기 위한 설정입니다.
|
|-- .dockerignore
|   Docker 이미지 빌드에 필요 없는 큰 파일과 로컬 산출물을 제외합니다.
|
|-- .venv/
|   선택 사항인 로컬 Python 가상환경입니다. Git에는 올리지 않고, 노트북 이전 기준 실행은 Docker를 우선합니다.
```

## 핵심 파일 역할

```text
src/soc/models.py
  Flow, MLResult, Verdict 같은 공통 데이터 모양을 정의합니다.

src/soc/io.py
  CSV flow 파일을 읽어 Flow 객체로 바꿉니다.

src/soc/ml/detector.py
  ML 탐지기 인터페이스, DummyDetector, XGBoostDetector가 있습니다.
  XGBoostDetector는 학습된 binary 모델과 metadata를 로드하고, 선택적으로 multiclass
  category hint 모델을 로드합니다. category hint는 auto_alert와 tier1_llm에만
  route 이후 설명용으로 붙고, tier1_llm 경로에만 SHAP top5 근거를 제공합니다.

src/soc/routing/router.py
  ML 확률을 보고 auto_dismiss, auto_alert, tier1_llm 중 하나로 보냅니다.
  Tier 2가 정리한 `routing_policy`가 강한 priority_1 trigger와 함께 맞으면
  auto_alert가 아니라 Tier 1 검토 문턱만 낮추는 동적 임계치 레이어를 적용합니다.

src/soc/context/watchlist.py
  Tier 2가 만든 latest.yaml을 읽고 flow가 watchlist에 걸리는지 확인합니다.
  선택 필드 `routing_policy`를 lint하고 라우터가 해석 가능한 형태로 넘깁니다.

src/soc/context/activity.py
  같은 출발지의 최근 활동을 간단히 요약합니다.

  Storage enabled runs use SQLite history for same-source activity. Storage
  disabled runs keep the previous same-run in-memory fallback.

src/soc/storage/sqlite.py
  SQLiteEventStore owns the MVP operational history for the Real Time Loop:
  flows, ml_results, route_decisions, verdicts, and tier1_calls. It also
  summarizes recent same-source DB history for Tier 1 context.
  The Reports experience reads the same store through list_report_events()
  and get_report_filter_options(), so date/severity/verdict/asset/watchlist
  filters are derived from stored realtime outcomes rather than raw
  organization/security source inputs.
  route_decisions에는 적용된 검토 문턱, 동적 임계치 적용 여부, 적용 이유도 저장합니다.
  clear_all_events() deletes all rows from every event table in FK-safe order
  and returns per-table deleted counts. Used by /api/admin/reset.

src/soc/realtime/service.py
  RealtimeIngestService is the reusable per-flow product input core. It accepts
  one Flow, runs ML feature construction, watchlist matching, routing,
  route-specific ML enrichment, optional Tier 1 judgment, SQLite persistence,
  and event payload creation. The CSV CLI now calls this service for each row;
  a future API or NetFlow/log adapter should call the same boundary instead of
  duplicating realtime-loop logic.

src/soc/api/product.py
  ProductApi is the dependency-free product backend core. It exposes one-flow
  ingest, recent flow reads, selected flow detail, runtime status, source-input
  status/content for the GUI, product-owned runtime source input import,
  Tier 2 artifacts, manual Tier 2 refresh, latest
  summary, filterable report/event listing, and an operator-facing topology payload. It supports
  Fake, Ollama, and Gemini API Tier 1 providers. It
  owns the live Tier 1 worker queue for `/api/flows`: every tier1_llm API
  ingest is enqueued and processed according to `tier1.queue.workers`,
  `max_size`, `timeout_seconds`, and `priority_policy` instead of spawning an
  unbounded background provider call per POST. Queue overflow, timeout, and
  call-limit cases are queue-policy fallbacks; provider/API failures remain LLM
  fallbacks after configured Tier 1 retry attempts. It also
  validates Ollama runtime overrides before applying them, so a disconnected
  Tier 1/Tier 2 local model or a model that cannot load because of host memory
  pressure is rejected at config/pre-injection time instead of producing many
  repeated provider-fallback verdicts during flow ingest. If ProductApi itself
  is running on the same host as a localhost Ollama URL, it first tries to start
  `ollama serve`; otherwise the browser setup log tells the operator what failed.
  For low-memory laptops, Tier 1 can select the Gemini API `gemma-4-26b-a4b-it`
  model and enter the Gemini API key through the browser setup/settings screen. It also
  exposes a dashboard payload that combines recent flow counters, source status,
  Tier 2 artifact status, latest summary, report links, and topology data for
  the GUI home screen. It calls RealtimeIngestService instead of duplicating
  realtime routing or Tier 1 prompt logic.
  `/api/topology` builds the P6 organization topology view from the configured
  asset YAML source, trust zones, and recent stored flow events. The payload is
  an asset relationship view for operators, not a claim of full network
  discovery.
  `/api/flows` runs ML routing synchronously. Auto-dismiss and auto-alert routes
  complete immediately. `tier1_llm` routes are saved as pending with
  `processing_state: tier1_queued`, then the Product-owned Tier 1 worker queue
  writes the final verdict when a configured worker finishes. When the API starts
  from the default product config, an existing
  `output/product_runtime/settings.active.yaml` is resumed so copied scenario
  inputs and Settings-page runtime overrides survive Docker restarts.
  Admin API endpoints:
    POST /api/admin/reset  – clears all SQLite event tables and resets in-memory
                             service state
    POST /api/admin/config – applies and persists runtime overrides for tier1_provider,
                             tier1_model, tier1_ollama_url,
                             tier1_max_tokens, tier1 queue workers,
                             tier2_provider,
                             tier2_model, tier2_ollama_url,
                             tier2_max_tokens
    POST /api/admin/source-inputs
                           - copies organization/assets/policy/CVE/threat YAML
                             into `output/product_runtime/inputs/`, writes
                             `output/product_runtime/settings.active.yaml`, and
                             makes the product read from that copied workspace
    GET  /api/admin/llm-options
                           - returns static Gemini choices, discovered Ollama
                             `/api/tags` model names, and Ollama reachability
                             errors for first-run and Settings UI warnings

src/soc/api/server.py
  Thin stdlib HTTP wrapper around ProductApi. It is intentionally small so the
  API contract can be tested without opening a socket and can later move to a
  richer web framework if the GUI needs it. It also serves the static GUI shell
  at `/` and `/static/*`.

src/soc/api/topology.py
  Builds the Realtime Monitoring topology payload from Tier 2 asset source
  snapshots plus recent SQLite flow events. It groups configured and recently
  observed endpoints into operator-facing buckets such as External/Public, DMZ,
  Internal Apps, Databases, Backup, Admin, Infrastructure, and Workstations,
  then aggregates recent source-to-destination flow edges with alert and
  watchlist counts.

src/soc/gui/static/
  Static first-screen SOC dashboard assets. The GUI is a thin operational view
  over ProductApi: it shows current runtime status, recent realtime flow triage,
  source-input health, active Tier 2 curated artifacts, latest daily summary,
  and compact realtime outcome trends. Reports shows the structured daily summary
  fields directly and does not duplicate the raw markdown artifact in the main
  UI. The sidebar now switches between Dashboard,
  Realtime Monitoring, Inputs, Tier 2 Context, Reports, and Settings views. Inputs
  is the editable source-input surface for Tier 2 YAML files, with structured add
  forms and raw YAML save. Tier 2 Context is the read surface over curated
  artifacts; manual Tier 2 refresh is exposed there as a product action. The
  Dashboard keeps its recent-flow list to the latest 10
  decision-critical rows, uses the recovered space for a dismiss/alert/uncertain
  line chart, and opens flow-detail modals without forcing a view change. Its
  top summary strip now focuses on Active Alerts, Needs Review, and LLM Review
  Queue. Active Alerts and Needs Review open paged operator lists for alert and
  uncertain flows, while LLM Review Queue shows the pending Tier 1 count and
  current Tier 1 model. `processing` and `pending` labels are neutral gray so
  they do not read as warnings. Realtime Monitoring reads stored flow detail
  through ProductApi so the
  UI can show the P6 asset relationship topology before the detailed flow table,
  highlight the selected flow source/destination, strengthen alert/watchlist
  edges, aggregate noisy inter-zone lines through group gateway anchors, and keep
  the topology in a fixed-height draggable 2D workspace. The
  Realtime page puts topology and the live flow table side by side, opens flow
  detail as a modal from table clicks, caps the visible table at 100 recent rows,
  offers a Hide benign filter, and opens a full paged recent-flow modal. It moves
  lower-priority Tier 1 runtime and active-context panels below the main monitoring surface. It does not feed
  raw organization/security YAML into Tier 1 and does not contain the demo flow
  injector. Settings is the product-owned runtime configuration surface for
  Tier 1/Tier 2 provider choices, discovered model choices, routing thresholds,
  Tier 1/Tier 2 output-token budgets, and DB reset. Ollama choices are populated
  from `/api/tags` discovery only, so Gemini/API model names are not advertised
  as local Ollama models. If Ollama is not reachable from Docker, first-run setup
  and Settings show a red warning telling the operator to start `ollama serve`
  and refresh model discovery. While either screen has an Ollama provider
  selected, the browser also retries model discovery every few seconds and when
  the tab regains focus, so newly started Ollama servers appear without a full
  page refresh.

src/soc/demo/flow_injector.py
  Demo Flow Injector for Productization Roadmap P8. It reads a flow CSV from an
  explicit `--input` path or a built-in scenario selector, optionally filters by
  day tokens such as `day05`, and posts each row to the Product API `/api/flows`
  boundary with a configurable interval. It also supports `--dry-run` so the
  dashboard demo input can be checked without calling the API. The injection loop
  accepts an optional `cancel_event` (threading.Event) so the Demo GUI can stop
  a running injection midway.

src/soc/demo/gui_server.py
  Standalone Demo GUI server for Productization Roadmap P8. It runs on a
  separate port (default 8081) and is completely decoupled from the Product API.
  It manages a background injection thread via InjectionRunner, proxies read-only
  product status for operator feedback, can ask ProductApi to copy selected
  scenario source inputs into the product runtime workspace, and serves the
  demo_static/ frontend at /. Scenario selection has two separate actions:
  apply the scenario organization/security input files by copy, then stream the
  scenario CSV rows to the Product API `/api/flows` boundary. It no longer
  points the product directly at scenario config files and still does not own
  LLM settings or DB resets; those belong to the product Settings surface.

src/soc/demo/demo_static/
  Static frontend assets for the Demo GUI (index.html, style.css, app.js).
  The UI has Product status, scenario input apply, Flow injector settings
  (scenario, day, interval, start/stop), and a live log console. It is
  intentionally a scenario replay/input machine; product settings are edited in
  the product dashboard.

src/soc/asset/source.py
  조직 자산 카탈로그를 읽는 AssetSource 인터페이스입니다.
  지금은 껍데기만 있고, 다음 단계에서 YAML 구현체를 채웁니다.

src/soc/threat/source.py
  위협 인텔을 읽는 ThreatSource 인터페이스입니다.
  지금은 껍데기만 있고, 다음 단계에서 YAML 구현체를 채웁니다.

src/soc/llm/provider.py
  LLMProvider 인터페이스, FakeLLMProvider, OllamaProvider가 있습니다.
  OllamaProvider는 /api/generate를 stream=false로 호출하고 JSON 응답 모드에서
  Tier 1 verdict를 받습니다. Docker에서 Windows host의 Ollama를 사용할 때는
  --ollama-url http://host.docker.internal:11434 를 사용합니다.

src/soc/llm/tier1.py
  Tier 1 입력을 조립하고 LLM 판정 결과를 Verdict로 바꿉니다.
  prompts/tier1_system.md를 system prompt로 읽고, provider 실패나 JSON 파싱 실패는
  uncertain/medium fallback verdict로 안전하게 처리합니다.
  Tier 1 provider 호출은 설정 가능한 max_tokens를 사용하며 기본값은 4096입니다.

  Gemma-style responses may include explanation text plus fenced JSON, so Tier 1
  now scans embedded JSON objects and uses the last object that matches the
  verdict/severity schema.

src/soc/config/settings.py
  Typed runtime settings loader for the Real Time Loop. It reads YAML settings,
  validates detector / LLM / queue choices, and applies CLI overrides. The same
  loader can later be reused by a dashboard or API layer.
  StorageSettings controls whether SQLite persistence is enabled and where the
  event database is written.

src/soc/tier2/batch.py
  Batch Loop runner 진입점입니다.
  DeterministicTier2Runner는 YAML provider와 SQLite 통계를 수집해 결정론적(rules-based)으로 산출물을 만듭니다.
  LLMTier2Runner/OllamaTier2Runner는 같은 SourceSnapshot 입력을 prompt로 조립해 로컬 Tier 2 LLM을 호출한 뒤
  검증된 watchlist, brief, memory 파일을 저장합니다. LLM 호출 또는 출력 파싱 실패 시 결정론적 fallback 산출물을 씁니다.

  It maps asset service names such as ssh, ftp, http, and https into watchlist
  destination-port hints so Real Time routing can match the curated services.

src/soc/tier2/prompt_builder.py
  prompts/tier2_system.md를 Tier 2 LLM system prompt로 읽고,
  SourceSnapshot 목록을 Tier 2 LLM user prompt로 조립합니다.
  LLM에는 먼저 attack_surface_memory를 도출하고, 그 결과를 반영해
  watchlist와 brief_context를 만들도록 지시합니다.
  watchlist는 예상 위험 flow 조건과 짧은 이유를 담는 결정적 산출물이고,
  brief_context는 Tier 1이 읽는 자연어 조직/자산 현황 및 공격 맥락 요약입니다.
  config의 attack_surface_memory_max_chars 값을 user prompt에 반영해
  Gemini/Ollama 실험별 memory 길이 제한을 조정할 수 있게 합니다.
  used snapshot content만 포함하고 missing/disabled/error source는 status summary로만 전달합니다.

src/soc/tier2/parser.py
  Tier 2 LLM 응답을 JSON/YAML object로 파싱하고 watchlist schema를 방어적으로 정규화합니다.
  malformed output은 empty/fallback artifact로 바뀌며 Real Time Loop가 깨지지 않게 합니다.
  `routing_policy`는 선택 필드로 보존하고, 엄격한 허용 범위 검사는 watchlist linter와 router가 담당합니다.

src/soc/tier2/watchlist_quality.py
  Tier 2 parsing after the LLM response and before writing artifacts.
  It preserves `alert_when` and `likely_benign_when`, enriches weak source-backed
  P1 items with observable hints, and then lets the watchlist linter mark any
  still-weak P1 item as `context_only`.
  CVE, policy, threat feed에서 온 일반 조건은 `detection_hints`와 `routing_policy`로 보강하되,
  특정 clinic IP나 특정 공격명에 맞춘 라우팅 규칙은 만들지 않습니다.

src/soc/tier2/writer.py
  watchlist, brief, memory를 실행 주기별 파일과 latest 파일로 저장합니다.

src/soc/report/renderer.py
  각 flow 결과를 HTML 리포트로 저장합니다.
  Summary HTML also includes Tier 1 queue statistics: mode, worker count,
  queued calls, actual LLM calls, total fallbacks, queue fallbacks, LLM/provider
  fallbacks, timeouts, overflow count, call-limit skips, and wait-time metrics.

src/soc/cli/pipeline.py
  Real Time Loop CSV runner. It loads settings, dependencies, and flow rows,
  then calls RealtimeIngestService for each row. Queue mode still owns Tier 1
  scheduling/backpressure, but the per-flow ML/watchlist/routing/storage/event
  behavior lives in the realtime service so product API ingest can reuse it.

  Persists operational records to SQLite when storage is enabled, then renders
  the same HTML reports as before.
  Event reports now show route reason, whether routing was adjusted by a
  watchlist match, dynamic threshold details, watchlist priority, and matched
  watchlist conditions.

scripts/tier2_batch.py
  Batch Loop runner를 실행합니다. 기본값은 deterministic이고, `--provider ollama --model gemma4:26b`로 로컬 Tier 2 LLM을 호출할 수 있습니다.

scripts/pipeline_run.py
  Real Time Loop 껍데기를 실행합니다.

scripts/product_api.py
  Product API HTTP server entrypoint. Example:
  `python scripts/product_api.py --config config/settings.example.yaml --host 127.0.0.1 --port 8080`.

scripts/demo_flow_injector.py
  Product demo entrypoint for streaming scenario CSV rows into a running
  Product API. Example:
  `python scripts/demo_flow_injector.py --target http://127.0.0.1:8080 --scenario regional_care_dynamic_cve --day day05 --limit 25 --interval 0.3`.

scripts/demo_gui_server.py
  Demo GUI server entrypoint. Runs the demo controller web UI on port 8081.
  Example:
  `python scripts/demo_gui_server.py --port 8081 --product-url http://127.0.0.1:8080`.

toggle_demo_servers.cmd
  Windows cmd helper for the final demo. It starts fixed-name Docker
  containers for the Product API on port 8080 and Demo GUI on port 8081,
  then leaves LLM provider choice, Gemini API key entry, and Ollama/Gemini
  preflight to the browser first-run setup. Pressing any key at the pause stops
  both containers.

scripts/generate_clinic_telehealth_flows.py
  clinic_telehealth 프롬프트 테스트용 flow CSV를 재생성합니다.
  2026-05-02부터 2026-05-04까지 각 날짜 100개, 전체 300개 flow를 만들고
  악성 30개 중 15개는 mock_prob > 0.95로 ML 자동 경보 경로를 검증하며
  15개는 review band 확률로 Tier 1 맥락 판단 경로를 검증합니다.

scripts/generate_clinic_telehealth_xgb_flows.py
  Regenerates data/sample/clinic_telehealth_flows_xgb.csv and its manifest from
  Dataset/NF-CICIDS2018-v3.csv. It keeps model features source-backed where
  possible, avoids mock_prob entirely, and records source indices plus explicit
  projection overrides in the manifest.

scripts/evaluate_clinic_memory_cycle.py
  Runs the three-day clinic Batch Loop/Real Time Loop evaluation and writes
  per-day reports, metrics, Tier 2 artifacts, and a shared SQLite store under
  the selected output directory. It follows the detector configured in the
  supplied settings file, so the older prompt-control run uses DummyDetector
  while config/settings.clinic_scenario_xgb.yaml uses the trained XGBoost
  router and attack-family hint model. ML-only baseline metrics are calculated
  from the stored runtime ML probability rather than from a mock-only CSV
  column.
  Metrics also include dynamic threshold application count, dynamic threshold
  false positives, and malicious flows recovered from auto-dismiss by the
  dynamic threshold layer.

scripts/evaluate_dynamic_cve_memory_cycle.py
  Runs the five-day regional-care dynamic CVE Batch Loop/Real Time Loop
  evaluation. It splits `data/sample/regional_care_dynamic_cve_flows_xgb.csv`
  into five KST days, points Tier 2 at the matching generated source snapshot
  for each day, reuses one SQLite store across the run, and writes per-day
  reports, Tier 2 artifacts, metrics, and aggregate summary files under the
  selected output directory.
  Dynamic-CVE metrics include day 1-2 vs day 3-5 windows, CVE-2025-24813 and
  CVE-2024-47575 attack recall plus benign-control false-positive rates,
  low-ML contextual attack recall, Infilteration-family recall, Tier 1 call
  counts, watchlist routing counts, and dynamic threshold recovery/FP counts.

requirements-dev.txt
  테스트 실행에 필요한 개발용 패키지 목록입니다. 현재는 pytest가 들어 있습니다.

requirements-ml.txt
  XGBoost 런타임과 학습에 필요한 패키지 목록입니다. Docker 이미지에도 설치됩니다.

tests/integration/test_xgboost_pipeline.py
  학습 완료 XGBoost 모델로 샘플 flow를 라우팅하고 tier1_llm HTML에 SHAP 근거가 포함되는지 확인합니다.

tests/integration/test_batch_loop_realtime_integration.py
  Batch Loop가 생성한 watchlist/brief를 Real Time Loop에 연결합니다.
  sample-p1-web flow가 ML 확률 0.25임에도 priority_1 watchlist match 때문에
  auto_dismiss가 아니라 tier1_llm으로 들어가고 SQLite/HTML에 근거가 남는지 확인합니다.

tests/integration/test_clinic_scenario_inputs.py
  프롬프트 테스트용 clinic_telehealth 시나리오의 YAML source와 3일치 300개 flow
  세트가 설정 파일에 제대로 연결되어 있는지 확인합니다. 또한 악성 비율 10%와
  명백한 ML 경보형 공격 / Tier 1 맥락형 공격 분리가 유지되는지 확인합니다.
  It also validates that the separate XGBoost-backed clinic CSV has no
  mock_prob column and satisfies the full binary model feature contract.
```

## 지금 상태

현재 구현은 XGBoost 기반 cheap routing, Ollama 기반 로컬 Tier 1 LLM 호출, Deterministic Tier 2 Runner, 그리고 Ollama 기반 Tier 2 LLM runner까지 들어온 상태입니다. FakeLLMProvider는 오프라인 smoke test용으로 유지합니다.

```text
DeterministicTier2Runner
  -> SourceSnapshots (YAML sources + SQLite DB stats) 수집
  -> 규칙 기반 처리 후 output/watchlists/latest.yaml 생성
  -> output/briefs/latest.md 생성
  -> output/memory/latest.md 생성

Batch -> Real Time integration test
  -> scripts/tier2_batch.py creates latest watchlist/brief
  -> scripts/pipeline_run.py consumes those artifacts
  -> sample-p1-web, prob=0.25, dst=172.31.69.28:443
  -> priority_1 watchlist match lowers review threshold
  -> route_decisions.adjusted_by_watchlist=1 and verdicts.watchlist_matched=P1...

OllamaTier2Runner
  -> SourceSnapshots 수집
  -> prompt_builder가 Tier 2 prompt 조립
  -> local Ollama model, for example gemma4:26b
  -> parser가 watchlist/brief/memory 검증 및 fallback 처리
  -> output/watchlists/latest.yaml, output/briefs/latest.md, output/memory/latest.md 생성

DummyDetector + FakeLLMProvider
  -> data/sample/flows.csv 처리
  -> output/reports/*.html 생성

XGBoostDetector + FakeLLMProvider
  -> data/sample/xgb_route_sample.csv 처리
  -> auto_dismiss / tier1_llm / auto_alert 라우팅 확인
  -> auto_alert / tier1_llm 리포트에 category hint 표시
  -> tier1_llm HTML 리포트에만 SHAP top5 근거 표시

XGBoostDetector + OllamaProvider
  -> Docker 컨테이너에서 host.docker.internal:11434의 Ollama API 호출
  -> gemma4:e4b 같은 로컬 모델로 Tier 1 verdict JSON 생성
  -> provider 실패 또는 JSON 파싱 실패 시 uncertain/medium fallback

Tier 1 queue mode
  -> ML/router가 모든 flow를 먼저 빠르게 분류
  -> auto_dismiss / auto_alert는 LLM queue를 기다리지 않고 verdict 생성
  -> tier1_llm만 producer-consumer bounded queue에 넣고 worker가 동시에 처리
  -> priority_1 watchlist match는 watchlist_first 정책에서 queued backlog 안에서 먼저 처리
  -> queue full / timeout / max calls 제한은 queue fallback으로 기록
  -> Ollama/API 실패와 JSON 파싱 실패는 LLM fallback으로 따로 기록
  -> summary.html에 tier1_calls, tier1_queued, queue/LLM fallback, wait time 기록
```

## 현재 PC에서 실행하는 법

이 컴퓨터에는 Docker Desktop과 WSL2가 준비되어 있으므로 Docker 실행을 우선 사용합니다.

```powershell
docker compose run --rm app python -m pytest
docker compose run --rm app python scripts/tier2_batch.py --config config/settings.example.yaml
docker compose run --rm app python scripts/pipeline_run.py --config config/settings.example.yaml
docker compose run --rm app python scripts/pipeline_run.py --config config/settings.example.yaml --input data/sample/xgb_route_sample.csv --output output/reports_ollama_queue --detector xgboost --llm ollama --llm-model gemma4:e4b --ollama-url http://host.docker.internal:11434 --tier1-mode queue --tier1-workers 1 --tier1-queue-max-size 50 --tier1-queue-timeout 300 --tier1-overflow-policy fallback --tier1-priority-policy watchlist_first
```

로컬 Python을 쓰는 경우에는 프로젝트 루트의 `.venv`를 사용합니다.

```powershell
.\.venv\Scripts\python.exe scripts\tier2_batch.py --config config\settings.example.yaml
.\.venv\Scripts\python.exe scripts\pipeline_run.py --input data\sample\flows.csv --output output\reports --detector dummy --llm fake
.\.venv\Scripts\python.exe scripts\pipeline_run.py --input data\sample\xgb_route_sample.csv --output output\reports_xgb_sample --detector xgboost --llm fake
.\.venv\Scripts\python.exe scripts\pipeline_run.py --input data\sample\xgb_route_sample.csv --output output\reports_ollama --detector xgboost --llm ollama --llm-model gemma4:e4b --ollama-url http://localhost:11434
.\.venv\Scripts\python.exe scripts\pipeline_run.py --input data\sample\xgb_route_sample.csv --output output\reports_ollama_queue --detector xgboost --llm ollama --llm-model gemma4:e4b --ollama-url http://localhost:11434 --tier1-mode queue --tier1-workers 1
.\.venv\Scripts\python.exe -m pytest
```

## 다음 작업: Tier 1 처리 운영화

Real Time Loop는 이제 FakeLLMProvider, OllamaProvider, bounded Tier 1 queue를
지원합니다. 다음 목표는 queue 옵션을 설정 파일로 옮기고, 실제 품질 평가와 저장소
연동을 붙이는 것입니다.

```text
Need:
  실제 로컬 LLM 품질 평가
  queue policy evaluation: sequential vs queue, call-limit fallback, timeout behavior
  Tier 2 reads SQLite event history for feedback-aware batch loop summaries

Not yet:
  Tier 2 실제 LLM 배치
```

## 추가 평가 작업: 토큰 비용 검증

교수 피드백에 따라 Tier 1/2 분리 구조가 실제로 비용 효율적인지 정량 검증해야 합니다.

비교 대상은 두 가지입니다.

```text
Current architecture
  Tier 2 batch
    -> assets / policy / CVE / threat feed / feedback을 주기적으로 압축
    -> watchlist + brief + memory 생성
  Tier 1 realtime
    -> flow + ML/SHAP + activity + watchlist/brief excerpt로 판정

Baseline for experiment only
  Tier 1 only raw context
    -> flow마다 assets / policy / CVE / threat feed를 직접 포함
    -> Tier 2 없이 한 번에 판정
```

측정해야 할 값:
- 토큰/비용: prompt tokens, completion tokens, total tokens, estimated cost, latency.
- 총비용 공식: Tier 1/2 구조는 `Tier 2 배치 1회 + Tier 1 N건`, baseline은 `raw context Tier 1 N건`.
- break-even point: flow 수 N이 커질수록 Tier 2 배치 비용이 언제 상쇄되는지 확인.
- 성능: verdict 일치율, severity 일치율, high/critical recall, false positive 수, JSON 파싱 실패율.

## 다음에 바꿀 가짜 부품

```text
DummyDetector     -> XGBoostDetector for model-backed runs
FakeLLMProvider   -> OllamaProvider first, API providers later
FakeTier2Runner   -> 실제 Tier 2 LLM 배치
StaticYAMLAssetSource / StaticYAMLThreatSource -> 실제 YAML 로더
HTMLRenderer      -> 더 읽기 좋은 한국어 리포트
SQLiteEventStore  -> Tier 2 feedback queries and richer SOC operations
```
