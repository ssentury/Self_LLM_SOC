# Project Structure

이 문서는 폴더와 파일의 역할을 쉽게 설명하는 안내서입니다. 작업을 하면서 구조나 책임이 바뀌면 이 문서도 같이 갱신합니다.

## 한 줄 요약

이 프로젝트는 발표자료의 구조를 따라갑니다.

- Slow Loop: Tier 2가 조직 지식과 보안 입력을 정리해서 Watchlist & Contexts를 만듭니다.
- Real Time Loop: NetFlow/flow가 ML을 먼저 지나고, 필요한 경우 Tier 1이 Watchlist & Contexts를 참고해 판정합니다.

## 전체 그림

```text
                         [ Slow Loop ]

  config/assets.example.yaml
  config/policy.example.yaml
  config/cve_feed.example.yaml
  config/threat_feed.example.yaml
  previous Tier 1 results
             |
             v
      Tier 2 strategy layer
             |
             +--> output/watchlists/latest.yaml
             +--> output/briefs/latest.md
             +--> output/memory/latest.md


                      [ Real Time Loop ]

  data/sample/flows.csv or NetFlow logs
             |
             v
       Dummy/XGBoost ML detector
             |
             v
          Router
      /      |       \
 dismiss   alert    Tier 1 LLM
                      |
                      v
          Watchlist & Brief Context
                      |
                      v
              output/reports/*.html
```

## ML Training Prep Addendum

The CICIDS2018 training work is prepared, but the production model is not
trained on this laptop.

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

requirements-ml.txt
  Optional ML training dependencies for the GPU workstation.
  The normal Docker smoke-test path still uses requirements-dev.txt.

Knowledge/GPU_TRAINING_HANDOFF.md
  Exact handoff instructions for the GPU Codex session. It explains the fixed
  feature contract, split policy, threshold policy, SHAP policy, and which
  output files must be copied back.
```

Current training boundary:

```text
Laptop repo:
  feature contract + training script + handoff instructions are ready

GPU workstation:
  run scripts/ml_train.py against Dataset/NF-CICIDS2018-v3.csv
  copy back:
    output/models/xgb_binary_v1.json
    output/models/xgb_binary_v1_metadata.json
    output/models/xgb_binary_v1_metrics.json
    output/models/xgb_binary_v1_thresholds.json
```

## 폴더 역할

```text
.
|-- AGENTS.md
|   다음 작업자가 반드시 기억해야 할 프로젝트 규칙입니다.
|
|-- Knowledge/
|   발표자료, 구현 명세, 제안서, 쉬운 구조 설명을 둡니다.
|
|-- config/
|   Slow Loop가 읽을 조직/보안 입력 예시입니다.
|
|-- data/
|   샘플 입력 데이터입니다. 큰 원본 데이터셋은 Dataset/에 있고 Git에는 올리지 않습니다.
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
|-- output/
|   실행 결과가 생성되는 위치입니다. 최신 watchlist, brief, memory, report가 여기에 생깁니다.
|
|-- Dockerfile
|   Python 3.11 실행 환경을 Docker 이미지로 고정합니다.
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
  ML 탐지기 인터페이스와 DummyDetector가 있습니다.
  지금은 mock_prob 값으로 테스트용 확률을 만듭니다.

src/soc/routing/router.py
  ML 확률을 보고 auto_dismiss, auto_alert, tier1_llm 중 하나로 보냅니다.

src/soc/context/watchlist.py
  Tier 2가 만든 latest.yaml을 읽고 flow가 watchlist에 걸리는지 확인합니다.

src/soc/context/activity.py
  같은 출발지의 최근 활동을 간단히 요약합니다.

src/soc/asset/source.py
  조직 자산 카탈로그를 읽는 AssetSource 인터페이스입니다.
  지금은 껍데기만 있고, 다음 단계에서 YAML 구현체를 채웁니다.

src/soc/threat/source.py
  위협 인텔을 읽는 ThreatSource 인터페이스입니다.
  지금은 껍데기만 있고, 다음 단계에서 YAML 구현체를 채웁니다.

src/soc/llm/provider.py
  LLMProvider 인터페이스와 FakeLLMProvider가 있습니다.

src/soc/llm/tier1.py
  Tier 1 입력을 조립하고 LLM 판정 결과를 Verdict로 바꿉니다.

src/soc/tier2/batch.py
  FakeTier2Runner가 Slow Loop 산출물을 만듭니다.

src/soc/tier2/writer.py
  watchlist, brief, memory를 주차별 파일과 latest 파일로 저장합니다.

src/soc/report/renderer.py
  각 flow 결과를 HTML 리포트로 저장합니다.

src/soc/cli/pipeline.py
  Real Time Loop를 CLI에서 실행합니다.

scripts/tier2_batch.py
  Slow Loop 껍데기를 실행합니다.

scripts/pipeline_run.py
  Real Time Loop 껍데기를 실행합니다.

requirements-dev.txt
  테스트 실행에 필요한 개발용 패키지 목록입니다. 현재는 pytest가 들어 있습니다.
```

## 지금 상태

현재 구현은 진짜 AI/ML 성능 검증 단계가 아닙니다. 목표는 두 루프가 같은 파일 계약으로 연결되는지 확인하는 것입니다.

```text
FakeTier2Runner
  -> output/watchlists/latest.yaml 생성
  -> output/briefs/latest.md 생성
  -> output/memory/latest.md 생성

DummyDetector + FakeLLMProvider
  -> data/sample/flows.csv 처리
  -> output/reports/*.html 생성
```

## 현재 PC에서 실행하는 법

이 컴퓨터에는 Docker Desktop과 WSL2가 준비되어 있으므로 Docker 실행을 우선 사용합니다.

```powershell
docker compose run --rm app python -m pytest
docker compose run --rm app python scripts/tier2_batch.py --config config/settings.example.yaml
docker compose run --rm app python scripts/pipeline_run.py --input data/sample/flows.csv --output output/reports --detector dummy --llm fake
```

로컬 Python을 쓰는 경우에는 프로젝트 루트의 `.venv`를 사용합니다.

```powershell
.\.venv\Scripts\python.exe scripts\tier2_batch.py --config config\settings.example.yaml
.\.venv\Scripts\python.exe scripts\pipeline_run.py --input data\sample\flows.csv --output output\reports --detector dummy --llm fake
.\.venv\Scripts\python.exe -m pytest
```

## 다음에 바꿀 가짜 부품

```text
DummyDetector     -> XGBoostDetector
FakeLLMProvider   -> OllamaProvider / ClaudeAPIProvider / OpenAIProvider
FakeTier2Runner   -> 실제 Tier 2 LLM 배치
StaticYAMLAssetSource / StaticYAMLThreatSource -> 실제 YAML 로더
HTMLRenderer      -> 더 읽기 좋은 한국어 리포트
in-memory history -> SQLite 판정 DB
```
