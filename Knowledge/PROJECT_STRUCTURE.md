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
  SHAP top5 is computed only for the tier1_llm route, so auto_dismiss and
  auto_alert stay cheap.

src/soc/cli/pipeline.py
  Supports:
    --detector dummy
    --detector xgboost --model ... --metadata ... --thresholds ...
  The pipeline passes L4_DST_PORT and PROTOCOL back into the detector feature
  surface so training and inference use the same feature order.
  It also keeps SHAP evidence limited to tier1_llm events before report/LLM
  rendering.

data/sample/xgb_route_sample.csv
  Small tracked sample generated from CICIDS2018 for model-backed route smoke
  testing. It contains examples for auto_dismiss, tier1_llm, and auto_alert.
  The XGBoost integration test uses it to verify SHAP evidence appears in the
  tier1_llm HTML report.

output/reports_xgb_sample/
  Local generated HTML sample from the XGBoost route smoke path. It is useful
  for manual inspection but remains an output artifact.
  It also has a --preflight-only mode for new machines. That mode loads and
  validates the dataset, prints distribution counts, and stops before training.
  Full training prints timestamped progress logs and periodic XGBoost evaluation
  output so long GPU runs are observable.

requirements-ml.txt
  ML runtime and training dependencies. Docker installs this file so the
  XGBoost detector path is reproducible across both development machines.

Knowledge/GPU_TRAINING_HANDOFF.md
  Exact handoff instructions for the GPU Codex session. It explains the fixed
  feature contract, split policy, threshold policy, SHAP policy, and which
  output files must be copied back.
```

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
  XGBoostDetector는 학습된 모델과 metadata를 로드하고 tier1_llm 경로에 SHAP top5 근거를 제공합니다.

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

requirements-ml.txt
  XGBoost 런타임과 학습에 필요한 패키지 목록입니다. Docker 이미지에도 설치됩니다.

tests/integration/test_xgboost_pipeline.py
  학습 완료 XGBoost 모델로 샘플 flow를 라우팅하고 tier1_llm HTML에 SHAP 근거가 포함되는지 확인합니다.
```

## 지금 상태

현재 구현은 XGBoost 기반 cheap routing까지 들어온 상태입니다. Tier 1 LLM은 아직 FakeLLMProvider라서, 다음 핵심 작업은 로컬 LLM provider를 붙이는 것입니다.

```text
FakeTier2Runner
  -> output/watchlists/latest.yaml 생성
  -> output/briefs/latest.md 생성
  -> output/memory/latest.md 생성

DummyDetector + FakeLLMProvider
  -> data/sample/flows.csv 처리
  -> output/reports/*.html 생성

XGBoostDetector + FakeLLMProvider
  -> data/sample/xgb_route_sample.csv 처리
  -> auto_dismiss / tier1_llm / auto_alert 라우팅 확인
  -> tier1_llm HTML 리포트에 SHAP top5 근거 표시
```

## 현재 PC에서 실행하는 법

이 컴퓨터에는 Docker Desktop과 WSL2가 준비되어 있으므로 Docker 실행을 우선 사용합니다.

```powershell
docker compose run --rm app python -m pytest
docker compose run --rm app python scripts/tier2_batch.py --config config/settings.example.yaml
docker compose run --rm app python scripts/pipeline_run.py --input data/sample/flows.csv --output output/reports --detector dummy --llm fake
docker compose run --rm app python scripts/pipeline_run.py --input data/sample/xgb_route_sample.csv --output output/reports_xgb_sample --detector xgboost --llm fake
```

로컬 Python을 쓰는 경우에는 프로젝트 루트의 `.venv`를 사용합니다.

```powershell
.\.venv\Scripts\python.exe scripts\tier2_batch.py --config config\settings.example.yaml
.\.venv\Scripts\python.exe scripts\pipeline_run.py --input data\sample\flows.csv --output output\reports --detector dummy --llm fake
.\.venv\Scripts\python.exe scripts\pipeline_run.py --input data\sample\xgb_route_sample.csv --output output\reports_xgb_sample --detector xgboost --llm fake
.\.venv\Scripts\python.exe -m pytest
```

## 다음 작업: 로컬 Tier 1 LLM

Real Time Loop의 다음 목표는 FakeLLMProvider를 로컬 LLM provider로 교체하는 것입니다.

```text
Need:
  OllamaProvider 구현
  prompts/tier1_system.md를 실제 provider 호출에 연결
  Tier 1 JSON 응답 파싱 실패 fallback 유지
  XGBoost ML probability + SHAP top5 + watchlist match + brief excerpt를 Tier 1 입력으로 전달
  provider 실패 시 uncertain/medium verdict로 안전하게 fallback

Not yet:
  실제 로컬 LLM 품질 평가
  SQLite 판정 DB 저장
  Tier 2 실제 LLM 배치
```

## 다음에 바꿀 가짜 부품

```text
DummyDetector     -> XGBoostDetector for model-backed runs
FakeLLMProvider   -> OllamaProvider first, API providers later
FakeTier2Runner   -> 실제 Tier 2 LLM 배치
StaticYAMLAssetSource / StaticYAMLThreatSource -> 실제 YAML 로더
HTMLRenderer      -> 더 읽기 좋은 한국어 리포트
in-memory history -> SQLite 판정 DB
```
