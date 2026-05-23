# Productization Roadmap

## Final Demo Day Notice

안녕하세요, 송현민 교수입니다.

최종 발표회(Demo Day) 일정을 다음과 같이 안내합니다.

이번 발표회는 여러분이 설계하고 개발한 AI 보안 에이전트/시스템의 최종 산출물을 공유하고, 실제 작동하는 Live Demo를 선보이는 자리입니다.

본 발표회를 끝으로 이번 학기 수업은 종강하게 됩니다.

마지막까지 유종의 미를 거둘 수 있도록 준비에 만전을 기해 주시기 바랍니다.

 
1. 최종 발표회 일정 및 장소

    일시: 2026년 5월 30일(토) 오후 1:00 ~ 오후 4:00 (약 3시간)

    장소: SWICT관 406호 (예정)

    발표 시간: 인당 10분 내외 (발표 및 Live Demo)

 
2. 발표 자료 및 최종 산출물 제출 안내

    제출 마감: 5월 29일(금) 23:59:59 (시간 엄수)

    제출 방법: [강의 시스템/LMS] 업로드

    제출 항목:

        최종 발표 자료

        GitHub Repository 링크: README.md가 완비된 최종 코드 저장소 URL (발표 자료 내 표기 및 LMS 제출란에 첨부)

        ※ README.md 필수 포함 사항: 프로젝트 개요, 시스템 아키텍처, AI 도구 활용 전략(Prompting Log), 실행 방법(How to run)

3. 최종 발표 필수 포함 내용

발표 자료는 다음 흐름을 포함하여 핵심 위주로 축약하여 구성해 주세요. (이전 발표 내용 중복 최소화)

    최종 시스템 아키텍처 및 구현체 소개: 최종 완성된 시스템의 구조와 핵심 알고리즘

    Live Demonstration (시연): 구현된 기능이 실제로 동작하는 모습을 현장에서 라이브 데모로 증명 (영상을 녹화해 오는 것도 가능하나 가급적 라이브 시연 권장)

    AI 및 Git 협업 성과: AI 코딩 도구를 디렉팅하여 거둔 정량적·정성적 성과 및 최종 Git 커밋 히스토리 요약

    한계점 및 향후 과제: 프로젝트를 진행하며 느낀 한계점, 보안 관점에서의 개선 방향, 이번 프로젝트를 통해 얻은 인사이트

 
4. 최종 발표 상호 평가 안내

Term Project 평가는 여러분의 상호 평가(70%)와 교수자 평가(30%)로 합산됩니다.

현장에서 모바일 구글 폼을 통해 발표가 끝날 때마다 실시간으로 평가를 진행할 예정입니다.

 

[최종 평가 기준]

    주제의 독창성 및 보안 혁신성 (Creativity): 기존 보안 문제를 AI를 활용해 얼마나 참신하고 효과적인 방식으로 해결하려 했는가?

    기술적 완성도 및 구현체 성숙도 (Completeness): 설계한 아키텍처가 실제로 완성도 높게 구현되었으며, Live Demo가 안정적으로 동작하는가?

    AI 디렉팅 능력 및 프로세스 (AI-Collaboration): AI IDE를 단순 코드 생성을 넘어 주도적으로 매니징하고, Git을 통해 개발 이력을 투명하게 증명했는가?

    발표 및 질의응답 대응 역량 (Professionalism): Senior-level 엔지니어로서 자신의 산출물을 명확하게 피칭했는가?

 

팀원 없이 기획부터 최종 데모까지 홀로 완수해 낸 이번 경험은, 앞으로 여러분이 마주할 AI 에이전트 시대에 그 무엇과도 바꿀 수 없는 경험이 될 것입니다.

토요일 발표회인 만큼 집중도 높은 행사가 될 수 있도록 서로를 위해 최고의 결과물을 준비해주시기 바랍니다.

## Updated Deadline Strategy

Submission deadline: 2026-05-29 23:59:59.
Demo Day: 2026-05-30 13:00-16:00, about 10 minutes per presenter.

The roadmap still targets a credible product-shaped SOC demo, but the final
notice changes the scheduling priority: packaging, README completeness, demo
stability, and AI/Git collaboration evidence are now P0 work. GUI polish that
does not directly support the 10-minute live demo should be treated as optional.

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

### P0. Submission Package And Demo Stability

- Finalize the GitHub repository state before the LMS deadline.
- Update `README.md` so it explicitly includes:
  - project overview
  - final system architecture
  - AI tool usage strategy / Prompting Log
  - Docker-first How to run instructions
- Add or link a concise AI/Git collaboration record for the final presentation:
  - how AI coding tools were directed
  - which architecture decisions were human-directed
  - final Git commit history summary
  - quantitative and qualitative results from AI-assisted development
- Prepare a 10-minute demo path:
  - start product backend and GUI
  - run Tier 2 context refresh or show latest curated artifacts
  - inject scenario flows through the product input boundary
  - inspect ML route, watchlist match, Tier 1 verdict, and stored report
  - show daily/report archive evidence
- Keep a fallback demo package ready:
  - recorded demo or screenshots
  - generated reports
  - SQLite event database from a known-good run
  - exact Docker commands used to reproduce it
- Run final verification through Docker:
  - `docker compose run --rm app python -m pytest`
  - one deterministic fake-LLM demo run
  - one model-backed XGBoost route smoke run

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
- This is optional if P0-P5 and P8 are not yet stable.

### P7. Reports Experience

- Build the latest-summary page with the easy text, statistics, important
  alerts, and recommended first checks.
- Build the all-reports page with daily summaries and event reports.
- Add filters that matter for presentation and operator review: date, severity,
  verdict, asset, and watchlist hit.
- The latest-summary view is higher priority than advanced archive filters.

### P8. Demo Flow Injector

- Add a simple tool that reads scenario flow CSV files and calls the product
  flow input boundary one row at a time.
- Support target endpoint, speed/interval, and scenario/day selection where
  practical.
- Keep it useful for recorded demonstrations even when no live LLM demo is
  attempted on the presentation laptop.

## Suggested Build Order

1. P0 submission checklist draft: README gaps, AI/Git evidence outline, demo
   script, and fallback artifact list.
2. Realtime Input Core.
3. Product API.
4. GUI Shell and Realtime Monitoring skeleton.
5. Demo Flow Injector.
6. Inputs and Tier 2 Context pages.
7. Latest summary/report view.
8. Final README, presentation, and Git history summary.
9. Topology View, only if the core demo is already stable.
10. Reports archive polish and filters, only after the presentation path works.

## Final Presentation Checklist

- Final system architecture and implementation:
  - show Batch Loop / Real Time Loop separation
  - emphasize ML-first routing and Tier 2-curated context
  - explain that Tier 1 does not receive raw asset, CVE, policy, or threat-feed
    dumps
- Live Demonstration:
  - use the dashboard as the first screen
  - show Tier 2 context artifacts before or during realtime flow triage
  - inject flows and inspect one selected flow end to end
  - keep a recorded fallback ready
- AI and Git collaboration:
  - summarize AI direction strategy from prompt/design/review cycles
  - show meaningful commit history groups rather than every commit
  - connect AI usage to concrete outcomes: faster iteration, tests, evaluation
    artifacts, documentation, and guardrail improvements
- Limits and future work:
  - local LLM latency and hardware constraints
  - synthetic scenario limits
  - future DB/API-backed source providers
  - future NetFlow/log adapter
  - stronger evaluation on real organization traffic

## Presentation Check

The finished product surface should make this explanation easy:

1. Tier 2 prepares context from organization and security inputs.
2. New flows enter a realtime input boundary and ML routes them first.
3. Only selected flows reach Tier 1 with curated context.
4. Operators can inspect flow evidence, current context, topology, and reports
   from one dark SOC UI.

