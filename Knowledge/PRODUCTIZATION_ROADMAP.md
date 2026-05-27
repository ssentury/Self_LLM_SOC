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

## Final Notice Work Breakdown

The final notice creates work beyond product implementation. Treat the remaining
week as two parallel tracks:

```text
Product readiness
  P8 dashboard/realtime polish
  Docker verification
  deterministic demo run

Submission and presentation readiness
  final deck
  README and repository package
  AI/Git collaboration evidence
  live demo script and fallback assets
  Q&A / limits / future-work talking points
```

Non-product work is P0 because it is explicitly graded and due before Demo Day.
Do not let optional GUI polish displace the following deliverables:

1. LMS submission package.
   - final presentation deck
   - GitHub repository link
   - complete `README.md`
   - any required fallback demo artifacts or links

2. README completion.
   - project overview in plain language
   - final Batch Loop / Real Time Loop architecture
   - Docker-first run instructions
   - AI tool usage strategy / Prompting Log
   - demo reproduction commands

3. Presentation deck refresh.
   - final architecture and implemented components
   - live demo path, not only design slides
   - AI/Git collaboration results
   - limitations, lessons learned, and future work
   - minimal repetition from the proposal deck

4. Demo operations package.
   - 10-minute live script
   - known-good scenario flows
   - known-good SQLite/report artifacts
   - recorded or screenshot fallback
   - exact commands for backend, GUI, Tier 2 refresh, and demo injection

5. AI/Git evidence package.
   - concise human-directed architecture decisions
   - prompt/design/review cycles that shaped the implementation
   - commit history grouped by product milestone
   - concrete outcomes from AI collaboration: tests, docs, guardrails,
     scenario data, evaluation artifacts, and UI iteration

6. Q&A readiness.
   - why the architecture is creative for small-organization SOC triage
   - what is actually complete and demoable
   - why Tier 2 curates context instead of dumping raw sources into Tier 1
   - where synthetic scenarios and local LLM latency limit the MVP
   - what would move next to DB/API providers and real NetFlow/log adapters

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

Completed implementation baseline:

- P1-P5 are treated as complete and are no longer listed as remaining work.
- The Demo Flow Injector is also complete as `scripts/demo_flow_injector.py`
  and `src/soc/demo/flow_injector.py`, so it stays outside the remaining
  implementation list.

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

### P6. Organization Topology View

Status: implemented.

- `src/soc/api/topology.py` generates a small-organization asset relationship
  view from the configured asset input, trust zones, and recent stored flows.
- `GET /api/topology` and the dashboard payload expose grouped assets/endpoints
  for external/public, DMZ, internal apps, DBs, backup, admin, infrastructure,
  workstations, and other assets when the input data supports them.
- Realtime Monitoring now places the topology graph above the detailed flow
  table, highlights the selected flow source and destination, briefly pulses the
  newest flow edge, and renders alert/watchlist edges stronger than normal
  recent traffic. The graph is fixed-height and draggable like a small 2D
  workspace; flow edges are bundled at the asset-group level so 50 recent flows
  do not become unreadable per-IP line clutter.
- This remains an operator-facing asset relationship view, not a claim of fully
  discovered network topology.
- P7 is now the remaining core implementation item. After P7 is complete, the
  implementation should be considered feature-complete for the final demo,
  subject to the polish items below.

### P7. Reports Experience

Status: implemented.

- The Reports page now renders the latest daily summary as operator-facing
  sections for easy text, statistics, important alerts, and recommended first
  checks, with the raw markdown summary kept as an expandable reference.
- The archive separates daily summaries from stored realtime event reports.
- Event report filters cover the presentation/operator review set: date,
  severity, verdict, asset, and watchlist hit.
- The implementation uses SQLite realtime outcomes and daily summary artifacts;
  it does not reopen the raw-context boundary or make Tier 1 read source inputs.

### P8. Dashboard And Realtime UI Polish

- Simplify the Dashboard recent-flow list:
  - show only the latest 10 flows
  - keep only decision-critical fields and make each row smaller
  - keep the detailed flow view in Realtime Monitoring, not on the Dashboard
  - give the Dashboard list a fixed height so the page does not keep growing as
    new flows arrive
- Use the recovered Dashboard space for a realtime line chart.
  - The chart should show incoming flow counts over time.
  - Series should be `dismiss`, `alert` for both auto-alert and LLM alert
    outcomes, and `uncertain`.
  - The visual target is a compact operational line chart similar to the
    provided reference image, not a large analytics page.
- Change `processing` state labels to gray. They currently read too much like a
  warning because they are yellow.
- Add the same new-flow animation to Dashboard and Realtime Monitoring:
  - the newest item appears at the top
  - existing items shift down smoothly
  - the animation should be subtle and should not interfere with fast triage
- Park the Dashboard top metric-card redesign.
  - The current four cards, `Alerts`, `Tier1 Reviews`, `Watchlist Hits`, and
    `Recent Flows`, will be replaced later.
  - Do not redesign these cards until detailed instructions are provided.

## Suggested Build Order

1. Finish P8 only to the level needed for the 10-minute demo.
   - Dashboard recent-flow compaction and fixed-height layout.
   - Dashboard realtime line chart for dismiss, alert, and uncertain flow
     counts.
   - Shared new-flow insertion animation for Dashboard and Realtime Monitoring.
   - Processing label color correction.

2. Freeze a known-good demo path.
   - Run Tier 2 context refresh or select the latest valid curated artifacts.
   - Inject scenario flows through the product input boundary.
   - Confirm ML route, watchlist match, Tier 1 verdict, topology highlight,
     stored report, and daily/archive evidence.
   - Save fallback screenshots, reports, database, and commands.

3. Prepare the submission package.
   - Complete `README.md`.
   - Add or link the AI/Git collaboration record.
   - Confirm repository URL and final code state for LMS.
   - Run Docker verification.

4. Refresh the final presentation.
   - Lead with the final product architecture, not the old proposal.
   - Keep the live demo path visible and short.
   - Add AI/Git collaboration evidence and future-work talking points.

5. Rehearse once against the actual 10-minute slot.
   - Use the live path first.
   - Keep the fallback path ready if model latency or laptop state becomes a
     problem.

6. Dashboard top-card redesign remains parked until detailed instructions are
   provided.

## Final Presentation Checklist

- Final system architecture and implementation:
  - show Batch Loop / Real Time Loop separation
  - emphasize ML-first routing and Tier 2-curated context
  - explain that Tier 1 does not receive raw asset, CVE, policy, or threat-feed
    dumps
- Live Demonstration:
  - use the dashboard as the first screen
  - show the realtime flow-count chart and compact latest flow list
  - show Tier 2 context artifacts before or during realtime flow triage
  - inject flows, then inspect topology and one selected flow end to end
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
4. Operators can monitor current flow volume by outcome, inspect compact recent
   results, then open Realtime Monitoring for topology, full flow evidence,
   current context, and reports from one dark SOC UI.

