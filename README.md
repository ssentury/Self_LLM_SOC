# Mini LLM SOC

소규모 조직을 위한 ML + 2-tier LLM 기반 네트워크 보안 트리아지 파이프라인입니다.

이 저장소의 구현 방향은 `Knowledge/AISecApp Proposal.pptx`의 발표 구조를 우선합니다. 핵심은 두 개의 루프입니다.

```text
Batch Loop
  조직 지식 + 보안 입력 + 이전 판정
        -> Tier 2 LLM
        -> Watchlist & Contexts / Attack Surface Memory / Summary
  중요한 자산/위협 정보가 바뀌거나 운영자가 정한 일정 주기에 실행

Real Time Loop
  Flow Log
        -> ML 라우팅
        -> 필요한 경우 Tier 1 LLM
        -> Verdict / Report / DB 기록
```

## 지금 구현된 것

현재는 테스트 환경에서 전체 루프를 재현할 수 있는 MVP 파이프라인입니다.

- `scripts/tier2_batch.py`: 기본값은 결정론적 Batch Loop runner이며, YAML source와 SQLite 통계를 읽어 watchlist, brief, memory 파일을 생성합니다. `--provider ollama`로 로컬 Tier 2 LLM을 사용할 수 있습니다.
- `scripts/pipeline_run.py`: 샘플 flow CSV를 읽고 XGBoost ML, watchlist 매칭, Fake 또는 Ollama Tier 1 판정, SQLite 저장, HTML 리포트를 실행합니다.
- `Knowledge/PROJECT_STRUCTURE.md`: 폴더와 파일의 역할을 쉬운 설명과 ASCII 구조도로 정리합니다.

## 실행 방법

### Docker 사용 권장

Windows 로컬 Python이나 가상환경이 꼬이면 Docker로 실행하는 편이 가장 재현성이 좋습니다.

테스트:

```powershell
docker compose run --rm app python -m pytest
```

Batch Loop:

```powershell
docker compose run --rm app python scripts/tier2_batch.py --config config/settings.example.yaml
```

Local Ollama Tier 2:

```powershell
docker compose run --rm app python scripts/tier2_batch.py --config config/settings.example.yaml --provider ollama --model gemma4:26b --ollama-url http://host.docker.internal:11434 --timeout-seconds 600 --max-tokens 8192 --response-format text
```

Gemini 3.5 Flash Tier 2:

```powershell
[Environment]::SetEnvironmentVariable('26_AISecApp_Project_GEMINI_API_KEY', '<your Gemini API key>', 'Process')
docker compose run --rm -e 26_AISecApp_Project_GEMINI_API_KEY app python scripts/tier2_batch.py --config config/settings.example.yaml --provider gemini --model gemini-3.5-flash --timeout-seconds 600 --max-tokens 8192 --temperature 1.0 --response-format json
```

Gemini is only wired as a Tier 2 batch-loop provider. Tier 1 still consumes the
curated watchlist, brief, and memory files that Tier 2 writes; it does not read
raw asset, CVE, policy, or threat-feed sources.

Real Time Loop:

```powershell
docker compose run --rm app python scripts/pipeline_run.py --config config/settings.example.yaml
```

Batch Loop -> Real Time Loop integration demo:

```powershell
docker compose run --rm app python scripts/tier2_batch.py --config config/settings.example.yaml --output output/batch_realtime_demo_tier2
docker compose run --rm app python scripts/pipeline_run.py --config config/settings.example.yaml --input data/sample/flows.csv --output output/batch_realtime_demo_reports --sqlite output/batch_realtime_demo.sqlite --detector dummy --llm fake --tier1-mode sequential --watchlist output/batch_realtime_demo_tier2/watchlists/latest.yaml --brief output/batch_realtime_demo_tier2/briefs/latest.md
```

Full dynamic-CVE memory-cycle evaluation:

```powershell
docker compose run --rm -e 26_AISecApp_Project_GEMINI_API_KEY app python scripts/evaluate_dynamic_cve_memory_cycle.py --clean
```

By default the Real Time Loop now writes operational records to SQLite at
`output/soc_events.sqlite` before rendering HTML reports. Override or disable it
per run:

```powershell
docker compose run --rm app python scripts/pipeline_run.py --config config/settings.example.yaml --sqlite output/soc_events.sqlite
docker compose run --rm app python scripts/pipeline_run.py --config config/settings.example.yaml --no-storage
```

CLI options can override config file values:

```powershell
docker compose run --rm app python scripts/pipeline_run.py --config config/settings.example.yaml --input data/sample/xgb_route_sample.csv --output output/reports_ollama --detector xgboost --llm ollama --llm-model gemma4:e4b --ollama-url http://host.docker.internal:11434
```

Tier 1 queue mode can also be configured in the YAML file or overridden at runtime:

```powershell
docker compose run --rm app python scripts/pipeline_run.py --config config/settings.example.yaml --input data/sample/xgb_route_sample.csv --output output/reports_ollama_queue --detector xgboost --llm ollama --llm-model gemma4:e4b --ollama-url http://host.docker.internal:11434 --tier1-mode queue --tier1-workers 1 --tier1-queue-max-size 50 --tier1-queue-timeout 300 --tier1-overflow-policy fallback --tier1-priority-policy watchlist_first
```

For local machine settings, copy `config/settings.example.yaml` to
`config/settings.local.yaml`. Local settings files are ignored by Git.

이미지는 처음 한 번 자동으로 빌드됩니다.

### 로컬 venv 사용

로컬 Python을 쓰고 싶다면 Python 3.11+가 필요합니다. Docker가 더 권장됩니다.

가상환경을 새로 만들 때:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

가상환경이 만들어져 있으면:

```powershell
.\.venv\Scripts\python.exe scripts\tier2_batch.py --config config\settings.example.yaml
.\.venv\Scripts\python.exe scripts\pipeline_run.py --config config\settings.example.yaml
.\.venv\Scripts\python.exe scripts\pipeline_run.py --config config\settings.example.yaml --input data\sample\xgb_route_sample.csv --output output\reports_ollama_queue --detector xgboost --llm ollama --llm-model gemma4:e4b --ollama-url http://localhost:11434 --tier1-mode queue --tier1-workers 1
```

일반적인 shell에서는 아래처럼 실행해도 됩니다.

```bash
python scripts/tier2_batch.py --config config/settings.example.yaml
python scripts/pipeline_run.py --config config/settings.example.yaml
python scripts/pipeline_run.py --config config/settings.example.yaml --input data/sample/xgb_route_sample.csv --output output/reports_ollama_queue --detector xgboost --llm ollama --llm-model gemma4:e4b --ollama-url http://localhost:11434 --tier1-mode queue --tier1-workers 1
```

테스트:

```bash
.\.venv\Scripts\python.exe -m pytest
```

## 중요한 설계 규칙

Tier 1은 원천 자산, CVE, 정책, 위협 인텔을 전부 직접 읽지 않습니다. Tier 2가 먼저 그 정보를 정리해서 `output/watchlists/latest.yaml`과 `output/briefs/latest.md`를 만들고, Tier 1은 그 결과만 참조합니다.

Tier 1 LLM은 느린 로컬 모델일 수 있으므로 `--tier1-mode queue`로 producer-consumer bounded queue를 사용할 수 있습니다. CPU 노트북에서는 `--tier1-workers 1`을 기본으로 두고, 큐가 꽉 차거나 호출 한도에 걸린 이벤트는 `uncertain/medium` fallback으로 남깁니다. summary report에는 Tier 1 호출 수, 큐 대기 시간, queue fallback 수, LLM/provider fallback 수가 따로 기록됩니다.

Runtime options live in `config/settings.example.yaml`. CLI arguments remain available as temporary overrides, but the YAML file is the canonical place for detector, LLM, queue, storage, routing, and Tier 2 artifact paths.

## Real Time Loop status

The default config now exercises the model-backed Real Time Loop shape:

```text
data/sample/xgb_route_sample.csv
  -> XGBoost binary router
  -> auto_dismiss / tier1_llm / auto_alert
  -> optional multiclass attack-family hint for auto_alert and tier1_llm
  -> SHAP top5 only for tier1_llm
  -> Tier 1 queue
  -> SQLite + HTML reports
```

The fake Tier 1 provider remains the default so the sample run is repeatable on
machines without a local Ollama model. For a real local Tier 1 run, override the
provider:

```powershell
docker compose run --rm app python scripts/pipeline_run.py --config config/settings.example.yaml --llm ollama --llm-model gemma4:e4b --ollama-url http://host.docker.internal:11434
```

Tier 1 verdicts are schema-checked before they enter storage or reports.
Invalid `verdict` or `severity` values become `uncertain/medium` LLM fallbacks
instead of being treated as valid SOC decisions. Successful Tier 1 calls also
record model name, latency, and token counts in `tier1_calls` when the provider
returns them.
