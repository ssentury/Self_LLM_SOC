import asyncio
import json
import threading
from dataclasses import replace
from pathlib import Path

from soc.api.product import ProductApi
from soc.llm.provider import LLMResponse


def test_product_api_ingests_flow_and_reads_recent_and_detail(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    api = ProductApi(config_path)

    response = api.handle(
        "POST",
        "/api/flows",
        json.dumps(
            {
                "flow_id": "api-flow-1",
                "start_ms": 10,
                "end_ms": 20,
                "src_ip": "10.0.0.5",
                "dst_ip": "172.31.69.28",
                "src_port": 41000,
                "dst_port": 443,
                "protocol": "6",
                "features": {
                    "IN_BYTES": "100",
                    "IN_PKTS": "1",
                    "OUT_BYTES": "100",
                    "OUT_PKTS": "1",
                    "mock_prob": "0.50",
                },
                "raw_label": "1",
                "raw_attack": "Review",
            }
        ),
    )

    assert response.status == 202
    assert response.body["processing_state"] == "tier1_queued"
    assert response.body["event"]["flow_id"] == "api-flow-1"
    assert response.body["event"]["route"] == "tier1_llm"
    assert response.body["event"]["verdict"] == "processing"

    recent = api.handle("GET", "/api/flows/recent?limit=5")
    assert recent.status == 200
    assert recent.body["events"][0]["flow_id"] == "api-flow-1"

    assert api._tier1_queue is not None
    assert api._tier1_queue.wait_until_idle(1.0)

    detail = api.handle("GET", "/api/flows/api-flow-1")
    assert detail.status == 200
    assert detail.body["event"]["features"]["mock_prob"] == "0.50"
    assert len(detail.body["event"]["tier1_calls"]) == 1
    assert detail.body["event"]["watchlist_detail"]["matched"] is False


def test_product_api_tier1_queue_serializes_api_llm_calls(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _write_config(tmp_path)
    provider = _SlowCountingProvider()
    monkeypatch.setattr("soc.api.product._build_provider", lambda settings: provider)
    api = ProductApi(config_path)

    first = api.handle("POST", "/api/flows", json.dumps(_review_flow_payload("api-q-1")))
    second = api.handle("POST", "/api/flows", json.dumps(_review_flow_payload("api-q-2")))

    assert first.status == 202
    assert second.status == 202
    assert api._tier1_queue is not None
    assert api._tier1_queue.wait_until_idle(2.0)
    assert provider.max_active == 1
    queue_status = api.handle("GET", "/api/status").body["tier1_queue"]
    assert queue_status["tier1_queued"] == 2
    assert queue_status["tier1_calls"] == 2


def test_product_api_refreshes_tier2_and_exposes_artifacts(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    api = ProductApi(config_path)

    refresh = api.handle("POST", "/api/tier2/refresh", "{}")

    assert refresh.status == 200
    assert refresh.body["cycle_id"]
    artifacts = api.handle("GET", "/api/tier2/artifacts")
    assert artifacts.status == 200
    assert artifacts.body["watchlist"]["exists"] is True
    assert artifacts.body["brief"]["exists"] is True
    assert artifacts.body["memory"]["exists"] is True


def test_product_api_reports_source_status(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    api = ProductApi(config_path)

    response = api.handle("GET", "/api/source-inputs/status")

    assert response.status == 200
    statuses = {source["name"]: source["status"] for source in response.body["sources"]}
    assert statuses["organization"] == "used"
    assert statuses["assets"] == "used"
    assert statuses["tier1_db"] == "used"


def test_product_api_exposes_source_input_content_for_gui(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    api = ProductApi(config_path)

    response = api.handle("GET", "/api/source-inputs")

    assert response.status == 200
    organization = next(
        source for source in response.body["sources"] if source["name"] == "organization"
    )
    assert organization["status"] == "used"
    assert "Test Clinic" in organization["content"]
    assert organization["item_count"] == 1


def test_product_api_copies_source_inputs_into_runtime_workspace(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    scenario_dir = tmp_path / "scenario"
    scenario_dir.mkdir()
    scenario_sources = {
        "organization": "name: Scenario Clinic\n",
        "assets": "assets: []\n",
        "policy": "policies: []\n",
        "cve_feed": "cves: []\n",
        "threat_feed": "indicators: []\n",
    }
    for name, content in scenario_sources.items():
        (scenario_dir / f"{name}.yaml").write_text(content, encoding="utf-8")
    runtime_dir = tmp_path / "product_runtime"
    api = ProductApi(config_path)

    response = api.handle(
        "POST",
        "/api/admin/source-inputs",
        json.dumps(
            {
                "scenario": "clinic_telehealth",
                "runtime_dir": str(runtime_dir),
                "sources": {
                    name: str(scenario_dir / f"{name}.yaml")
                    for name in scenario_sources
                },
            }
        ),
    )

    assert response.status == 200
    assert response.body["input_dir"] == str(runtime_dir / "inputs")
    assert api.config_path == runtime_dir / "settings.active.yaml"
    copied_org = runtime_dir / "inputs" / "organization.yaml"
    assert copied_org.read_text(encoding="utf-8") == "name: Scenario Clinic\n"

    source_response = api.handle("GET", "/api/source-inputs")
    organization = next(
        source for source in source_response.body["sources"] if source["name"] == "organization"
    )
    assert organization["path_or_uri"] == str(copied_org)
    assert "Scenario Clinic" in organization["content"]


def test_product_api_resumes_active_runtime_config_on_default_start(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _write_config(tmp_path)
    default_config = tmp_path / "config" / "settings.example.yaml"
    default_config.write_text(config_path.read_text(encoding="utf-8"), encoding="utf-8")
    active_config = tmp_path / "output" / "product_runtime" / "settings.active.yaml"
    active_config.parent.mkdir(parents=True)
    active_config.write_text(
        default_config.read_text(encoding="utf-8").replace("threshold_low: 0.30", "threshold_low: 0.12"),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    api = ProductApi()

    assert api.config_path == Path("output/product_runtime/settings.active.yaml")
    assert api.settings.routing.threshold_low == 0.12


def test_product_api_persists_default_runtime_settings_for_restart(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _write_config(tmp_path)
    default_config = tmp_path / "config" / "settings.example.yaml"
    default_config.write_text(config_path.read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    api = ProductApi()
    response = api.handle(
        "POST",
        "/api/admin/config",
        json.dumps({"threshold_low": "0.21"}),
    )

    assert response.status == 200
    active_config = Path("output/product_runtime/settings.active.yaml")
    assert active_config.exists()
    assert api.config_path == active_config
    assert ProductApi().settings.routing.threshold_low == 0.21


def test_product_api_saves_raw_source_input_content(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    api = ProductApi(config_path)

    response = api.handle(
        "POST",
        "/api/source-inputs/organization",
        json.dumps({"content": "organization:\n  name: Edited Clinic\n"}),
    )

    assert response.status == 200
    assert response.body["source"]["status"] == "used"
    source_response = api.handle("GET", "/api/source-inputs")
    organization = next(
        source for source in source_response.body["sources"] if source["name"] == "organization"
    )
    assert organization["data"]["organization"]["name"] == "Edited Clinic"


def test_product_api_appends_structured_source_input_item(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    api = ProductApi(config_path)

    response = api.handle(
        "POST",
        "/api/source-inputs/assets",
        json.dumps(
            {
                "append": {
                    "id": "db-1",
                    "ip": "10.0.0.20",
                    "role": "database",
                    "services": "postgres, tls",
                    "criticality": "high",
                }
            }
        ),
    )

    assert response.status == 200
    source_response = api.handle("GET", "/api/source-inputs")
    assets = next(source for source in source_response.body["sources"] if source["name"] == "assets")
    assert assets["item_count"] == 2
    assert assets["data"]["assets"][-1]["services"] == ["postgres", "tls"]


def test_product_api_deletes_structured_source_input_item(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    api = ProductApi(config_path)

    response = api.handle(
        "POST",
        "/api/source-inputs/assets",
        json.dumps({"delete": {"list_key": "assets", "index": 0}}),
    )

    assert response.status == 200
    assert response.body["change"] == "item_deleted"
    source_response = api.handle("GET", "/api/source-inputs")
    assets = next(source for source in source_response.body["sources"] if source["name"] == "assets")
    assert assets["item_count"] == 0
    assert assets["data"]["assets"] == []


def test_product_api_applies_llm_runtime_options(tmp_path: Path, monkeypatch) -> None:
    config_path = _write_config(tmp_path)
    api = ProductApi(config_path)
    monkeypatch.setattr(
        "soc.api.product._fetch_ollama_tags_with_timeout",
        lambda base_url, *, timeout_seconds: {
            "reachable": True,
            "url": base_url,
            "models": ["gemma4:e4b", "gemma4:26b"],
        },
    )
    monkeypatch.setattr(
        "soc.api.product._preflight_ollama_generate",
        lambda base_url, model, *, timeout_seconds: {
            "ok": True,
            "url": base_url,
            "model": model,
        },
    )

    response = api.handle(
        "POST",
        "/api/admin/config",
        json.dumps(
            {
                "tier1_provider": "ollama",
                "tier1_model": "gemma4:e4b",
                "tier1_ollama_url": "http://host.docker.internal:11434",
                "tier1_max_tokens": "8192",
                "tier1_retry_attempts": "2",
                "tier1_retry_backoff_seconds": "0.25",
                "tier1_workers": "2",
                "tier2_provider": "ollama",
                "tier2_model": "gemma4:26b",
                "tier2_ollama_url": "http://host.docker.internal:11434",
                "tier2_max_tokens": "32768",
            }
        ),
    )

    assert response.status == 200
    status = response.body["status"]
    assert status["tier1_provider"] == "ollama"
    assert status["tier1_ollama_url"] == "http://host.docker.internal:11434"
    assert status["tier1_max_tokens"] == 8192
    assert status["tier1_retry_attempts"] == 2
    assert status["tier1_retry_backoff_seconds"] == 0.25
    assert status["tier1_queue_workers"] == 2
    assert status["tier2_provider"] == "ollama"
    assert status["tier2_ollama_url"] == "http://host.docker.internal:11434"
    assert status["tier2_max_tokens"] == 32768
    assert status["routing"]["threshold_low"] == 0.30


def test_product_api_tier2_ollama_options_use_discovered_models_only(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _write_config(tmp_path)
    api = ProductApi(config_path)
    monkeypatch.setattr(
        "soc.api.product._ollama_catalog",
        lambda base_url: {"reachable": True, "url": base_url, "models": []},
    )

    response = api.handle("GET", "/api/admin/llm-options")

    assert response.status == 200
    tier2_ollama = [
        choice for choice in response.body["tier2"]["models"]
        if choice["provider"] == "ollama"
    ]
    assert tier2_ollama == []


def test_product_api_tier1_ollama_options_do_not_fallback_to_gemini_model(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _write_config(tmp_path)
    api = ProductApi(config_path)
    api.settings = replace(
        api.settings,
        tier1=replace(
            api.settings.tier1,
            llm=replace(
                api.settings.tier1.llm,
                provider="gemini",
                model="gemma-4-26b-a4b-it",
            ),
        ),
    )
    monkeypatch.setattr(
        "soc.api.product._ollama_catalog",
        lambda base_url: {
            "reachable": False,
            "url": base_url,
            "models": [],
            "error": "connection refused",
        },
    )

    response = api.handle("GET", "/api/admin/llm-options")

    assert response.status == 200
    tier1_ollama = [
        choice for choice in response.body["tier1"]["models"]
        if choice["provider"] == "ollama"
    ]
    assert tier1_ollama == []
    assert response.body["ollama"]["tier1"]["reachable"] is False
    assert response.body["ollama"]["tier1"]["error"] == "connection refused"


def test_product_api_rejects_unreachable_tier1_ollama_runtime(tmp_path: Path, monkeypatch) -> None:
    config_path = _write_config(tmp_path)
    api = ProductApi(config_path)
    monkeypatch.setattr(
        "soc.api.product._fetch_ollama_tags_with_timeout",
        lambda base_url, *, timeout_seconds: {
            "reachable": False,
            "url": base_url,
            "models": [],
            "error": "[Errno 111] Connection refused",
        },
    )

    response = api.handle(
        "POST",
        "/api/admin/config",
        json.dumps(
            {
                "tier1_provider": "ollama",
                "tier1_model": "gemma4:e4b",
                "tier1_ollama_url": "http://host.docker.internal:11434",
            }
        ),
    )

    assert response.status == 400
    assert "Tier 1 Ollama is not reachable" in response.body["error"]
    assert api.settings.tier1.llm.provider == "fake"


def test_product_api_attempts_local_ollama_start_before_rejecting(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _write_config(tmp_path)
    api = ProductApi(config_path)
    attempts = []

    def fake_tags(base_url, *, timeout_seconds):
        attempts.append(base_url)
        if len(attempts) == 1:
            return {
                "reachable": False,
                "url": base_url,
                "models": [],
                "error": "[Errno 111] Connection refused",
            }
        return {
            "reachable": True,
            "url": base_url,
            "models": ["gemma4:e4b"],
        }

    monkeypatch.setattr("soc.api.product._fetch_ollama_tags_with_timeout", fake_tags)
    monkeypatch.setattr("soc.api.product._running_in_container", lambda: False)
    monkeypatch.setattr(
        "soc.api.product._try_start_local_ollama",
        lambda base_url: {"attempted": True, "started": True},
    )
    monkeypatch.setattr(
        "soc.api.product._preflight_ollama_generate",
        lambda base_url, model, *, timeout_seconds: {
            "ok": True,
            "url": base_url,
            "model": model,
        },
    )

    response = api.handle(
        "POST",
        "/api/admin/config",
        json.dumps(
            {
                "tier1_provider": "ollama",
                "tier1_model": "gemma4:e4b",
                "tier1_ollama_url": "http://localhost:11434",
            }
        ),
    )

    assert response.status == 200
    assert attempts == ["http://localhost:11434", "http://localhost:11434"]
    assert api.settings.tier1.llm.provider == "ollama"


def test_product_api_rewrites_local_ollama_url_inside_container(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _write_config(tmp_path)
    api = ProductApi(config_path)
    attempts = []

    def fake_tags(base_url, *, timeout_seconds):
        attempts.append(base_url)
        return {
            "reachable": base_url == "http://host.docker.internal:11434",
            "url": base_url,
            "models": ["gemma4:e4b"] if base_url == "http://host.docker.internal:11434" else [],
            "error": "connection refused",
        }

    monkeypatch.setattr("soc.api.product._running_in_container", lambda: True)
    monkeypatch.setattr("soc.api.product._fetch_ollama_tags_with_timeout", fake_tags)
    monkeypatch.setattr(
        "soc.api.product._preflight_ollama_generate",
        lambda base_url, model, *, timeout_seconds: {
            "ok": True,
            "url": base_url,
            "model": model,
        },
    )

    response = api.handle(
        "POST",
        "/api/admin/config",
        json.dumps(
            {
                "tier1_provider": "ollama",
                "tier1_model": "gemma4:e4b",
                "tier1_ollama_url": "http://localhost:11434",
            }
        ),
    )

    assert response.status == 200
    assert attempts == ["http://host.docker.internal:11434"]
    assert response.body["status"]["tier1_ollama_url"] == "http://host.docker.internal:11434"


def test_product_api_rejects_tier1_ollama_model_that_cannot_load(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _write_config(tmp_path)
    api = ProductApi(config_path)
    monkeypatch.setattr(
        "soc.api.product._fetch_ollama_tags_with_timeout",
        lambda base_url, *, timeout_seconds: {
            "reachable": True,
            "url": base_url,
            "models": ["gemma4:e4b"],
        },
    )
    monkeypatch.setattr(
        "soc.api.product._preflight_ollama_generate",
        lambda base_url, model, *, timeout_seconds: {
            "ok": False,
            "url": base_url,
            "model": model,
            "error": "HTTP 500: model requires more system memory",
        },
    )

    response = api.handle(
        "POST",
        "/api/admin/config",
        json.dumps(
            {
                "tier1_provider": "ollama",
                "tier1_model": "gemma4:e4b",
                "tier1_ollama_url": "http://host.docker.internal:11434",
            }
        ),
    )

    assert response.status == 400
    assert "installed but cannot run" in response.body["error"]
    assert "model requires more system memory" in response.body["error"]
    assert api.settings.tier1.llm.provider == "fake"


def test_product_api_applies_gemini_api_tier1_runtime(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _write_config(tmp_path)
    api = ProductApi(config_path)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(
        "soc.api.product._preflight_gemini_connection",
        lambda base_url, api_key, *, timeout_seconds: {"ok": True},
    )

    response = api.handle(
        "POST",
        "/api/admin/config",
        json.dumps(
            {
                "tier1_provider": "gemini",
                "tier1_model": "gemma-4-26b-a4b-it",
            }
        ),
    )

    assert response.status == 200
    status = response.body["status"]
    assert status["tier1_provider"] == "gemini"
    assert status["tier1_model"] == "gemma-4-26b-a4b-it"
    service = api._service()
    assert service.tier1_runtime.provider == "gemini"
    assert service.tier1_runtime.model_name == "gemma-4-26b-a4b-it"


def test_product_api_rejects_gemini_api_tier1_without_key(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _write_config(tmp_path)
    api = ProductApi(config_path)
    monkeypatch.delenv("26_AISecApp_Project_GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)

    response = api.handle(
        "POST",
        "/api/admin/config",
        json.dumps(
            {
                "tier1_provider": "gemini",
                "tier1_model": "gemma-4-26b-a4b-it",
            }
        ),
    )

    assert response.status == 400
    assert "Gemini API key is not set" in response.body["error"]
    assert api.settings.tier1.llm.provider == "fake"


def test_product_api_accepts_gemini_api_key_from_runtime_settings(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _write_config(tmp_path)
    api = ProductApi(config_path)
    monkeypatch.delenv("26_AISecApp_Project_GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.setattr(
        "soc.api.product._preflight_gemini_connection",
        lambda base_url, api_key, *, timeout_seconds: {
            "ok": api_key == "runtime-key",
        },
    )

    response = api.handle(
        "POST",
        "/api/admin/config",
        json.dumps(
            {
                "tier2_provider": "gemini",
                "tier2_model": "gemini-3.5-flash",
                "gemini_api_key": "runtime-key",
            }
        ),
    )

    assert response.status == 200
    assert response.body["status"]["tier2_provider"] == "gemini"
    assert response.body["status"]["gemini_has_key"] is True


def test_product_api_dashboard_returns_home_payload(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    api = ProductApi(config_path)

    ingest = api.handle(
        "POST",
        "/api/flows",
        json.dumps(
            {
                "flow_id": "dashboard-flow-1",
                "src_ip": "10.0.0.8",
                "dst_ip": "172.31.69.28",
                "src_port": 42000,
                "dst_port": 443,
                "protocol": "6",
                "features": {"mock_prob": "0.98"},
            }
        ),
    )
    assert ingest.status == 200

    response = api.handle("GET", "/api/dashboard")

    assert response.status == 200
    assert response.body["status"]["service"] == "mini-llm-soc-product-api"
    assert response.body["counters"]["total_recent"] == 1
    assert response.body["counters"]["routes"]["auto_alert"] == 1
    assert response.body["recent_flows"][0]["flow_id"] == "dashboard-flow-1"
    assert "source_inputs" in response.body
    assert "tier2_artifacts" in response.body
    assert "latest_summary" in response.body
    assert response.body["topology"]["status"] == "ready"
    assert response.body["topology"]["edges"][0]["alert_count"] == 1


def test_product_api_reports_filter_stored_events(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    api = ProductApi(config_path)

    ingest = api.handle(
        "POST",
        "/api/flows",
        json.dumps(
            {
                "flow_id": "report-flow-1",
                "start_ms": 1_800_000,
                "src_ip": "10.0.0.8",
                "dst_ip": "172.31.69.28",
                "src_port": 42000,
                "dst_port": 443,
                "protocol": "6",
                "features": {"mock_prob": "0.98"},
            }
        ),
    )
    assert ingest.status == 200

    reports = api.handle(
        "GET",
        "/api/reports?date=1970-01-01&verdict=alert&severity=high&asset=172.31.69.28",
    )

    assert reports.status == 200
    assert reports.body["filters"]["date"] == "1970-01-01"
    assert reports.body["event_reports"][0]["flow_id"] == "report-flow-1"
    assert "172.31.69.28" in reports.body["filter_options"]["assets"]

    empty = api.handle("GET", "/api/reports?asset=203.0.113.10")
    assert empty.status == 200
    assert empty.body["event_reports"] == []


def test_product_api_generates_daily_summary(tmp_path: Path, monkeypatch) -> None:
    config_path = _write_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    api = ProductApi(config_path)

    ingest = api.handle(
        "POST",
        "/api/flows",
        json.dumps(
            {
                "flow_id": "summary-flow-1",
                "start_ms": 1_800_000,
                "src_ip": "10.0.0.8",
                "dst_ip": "172.31.69.28",
                "src_port": 42000,
                "dst_port": 443,
                "protocol": "6",
                "features": {"mock_prob": "0.98"},
            }
        ),
    )
    assert ingest.status == 200

    response = api.handle("POST", "/api/summary/generate", "{}")

    assert response.status == 200
    assert response.body["generated"] is True
    assert response.body["generation_mode"] == "deterministic_sqlite"
    assert response.body["llm_called"] is False
    assert response.body["summary"]["flow_count"] == 1
    assert response.body["summary"]["generation"]["llm_called"] is False
    assert response.body["latest_summary"]["json"]["exists"] is True
    assert (tmp_path / "output" / "daily_summaries" / "latest.md").exists()


def test_product_api_generates_daily_summary_with_tier2_llm(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _write_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    provider = _StaticSummaryProvider()
    monkeypatch.setattr(
        "soc.api.product._build_tier2_summary_provider",
        lambda settings: provider,
    )
    api = ProductApi(config_path)
    api.settings = replace(
        api.settings,
        tier2=replace(api.settings.tier2, provider="gemini", model="gemini-summary-test"),
    )

    ingest = api.handle(
        "POST",
        "/api/flows",
        json.dumps(
            {
                "flow_id": "summary-llm-flow-1",
                "start_ms": 1_800_000,
                "src_ip": "10.0.0.8",
                "dst_ip": "172.31.69.28",
                "src_port": 42000,
                "dst_port": 443,
                "protocol": "6",
                "features": {"mock_prob": "0.98"},
            }
        ),
    )
    assert ingest.status == 200

    response = api.handle("POST", "/api/summary/generate", "{}")

    assert response.status == 200
    assert provider.called is True
    assert '"flow_count": 1' in provider.user_prompt
    assert response.body["generation_mode"] == "tier2_llm"
    assert response.body["llm_called"] is True
    assert response.body["summary"]["easy_summary_ko"] == "LLM이 작성한 일일 요약입니다."
    assert response.body["summary"]["first_checks_ko"] == ["LLM이 제안한 첫 점검입니다."]
    assert response.body["summary"]["generation"]["provider"] == "gemini"
    latest_md = tmp_path / "output" / "daily_summaries" / "latest.md"
    assert "Tier 2 LLM summary" in latest_md.read_text(encoding="utf-8")


def test_product_api_exposes_asset_topology(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    api = ProductApi(config_path)

    ingest = api.handle(
        "POST",
        "/api/flows",
        json.dumps(
            {
                "flow_id": "topology-flow-1",
                "src_ip": "10.0.0.8",
                "dst_ip": "172.31.69.28",
                "src_port": 42000,
                "dst_port": 443,
                "protocol": "6",
                "features": {"mock_prob": "0.98"},
            }
        ),
    )
    assert ingest.status == 200

    response = api.handle("GET", "/api/topology")

    assert response.status == 200
    assert response.body["status"] == "ready"
    assert response.body["source"]["status"] == "used"
    groups = {group["id"] for group in response.body["groups"]}
    assert {"dmz", "workstation"}.issubset(groups)
    nodes_by_ip = {node["ip"]: node for node in response.body["nodes"]}
    assert nodes_by_ip["172.31.69.28"]["source"] == "asset_input"
    assert nodes_by_ip["10.0.0.8"]["source"] == "recent_flow"
    edge = response.body["edges"][0]
    assert edge["src_ip"] == "10.0.0.8"
    assert edge["dst_ip"] == "172.31.69.28"
    assert edge["latest_flow_id"] == "topology-flow-1"


def _write_config(tmp_path: Path) -> Path:
    config_dir = tmp_path / "config"
    output_dir = tmp_path / "output"
    config_dir.mkdir()
    (config_dir / "organization.yaml").write_text("name: Test Clinic\n", encoding="utf-8")
    (config_dir / "assets.yaml").write_text(
        "\n".join(
            [
                "assets:",
                "  - id: web-1",
                "    ip: 172.31.69.28",
                "    role: patient-portal-web",
                "    zone: dmz-public",
                "    services: [https]",
                "    criticality: high",
                "trust_zones:",
                "  - cidr: 172.31.0.0/16",
                "    zone: dmz-public",
                "  - cidr: 10.0.0.0/24",
                "    zone: clinic-workstations",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (config_dir / "policy.yaml").write_text("policies: []\n", encoding="utf-8")
    (config_dir / "cve_feed.yaml").write_text("cves: []\n", encoding="utf-8")
    (config_dir / "threat_feed.yaml").write_text("indicators: []\n", encoding="utf-8")
    config_path = tmp_path / "settings.yaml"
    config_path.write_text(
        f"""
schema_version: 1
runtime:
  input: unused.csv
  output: {output_dir / "reports"}
storage:
  enabled: true
  sqlite_path: {output_dir / "events.sqlite"}
detector:
  provider: dummy
tier1:
  llm:
    provider: fake
  queue:
    mode: sequential
tier2:
  provider: deterministic
  watchlist: {output_dir / "watchlists" / "latest.yaml"}
  brief: {output_dir / "briefs" / "latest.md"}
  memory: {output_dir / "memory" / "latest.md"}
  sources:
    organization:
      enabled: true
      path: {config_dir / "organization.yaml"}
    assets:
      enabled: true
      path: {config_dir / "assets.yaml"}
    policy:
      enabled: true
      path: {config_dir / "policy.yaml"}
    cve_feed:
      enabled: true
      path: {config_dir / "cve_feed.yaml"}
    threat_feed:
      enabled: true
      path: {config_dir / "threat_feed.yaml"}
routing:
  threshold_low: 0.30
  threshold_high: 0.95
  priority_1_llm_threshold: 0.20
""".strip(),
        encoding="utf-8",
    )
    return config_path


def _review_flow_payload(flow_id: str) -> dict[str, object]:
    return {
        "flow_id": flow_id,
        "start_ms": 10,
        "end_ms": 20,
        "src_ip": "10.0.0.5",
        "dst_ip": "172.31.69.28",
        "src_port": 41000,
        "dst_port": 443,
        "protocol": "6",
        "features": {
            "IN_BYTES": "100",
            "IN_PKTS": "1",
            "OUT_BYTES": "100",
            "OUT_PKTS": "1",
            "mock_prob": "0.50",
        },
        "raw_label": "1",
        "raw_attack": "Review",
    }


class _SlowCountingProvider:
    def __init__(self) -> None:
        self.active = 0
        self.max_active = 0
        self._lock = threading.Lock()

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.3,
        response_format: str = "text",
    ) -> LLMResponse:
        with self._lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            await asyncio.sleep(0.05)
            return LLMResponse(
                content=json.dumps(
                    {
                        "verdict": "uncertain",
                        "severity": "medium",
                        "rationale_ko": "queued",
                        "recommended_action_ko": "review",
                        "confidence": 0.5,
                    }
                ),
                tokens_used=10,
                model_name="slow-test",
                latency_ms=50.0,
                prompt_tokens=8,
                completion_tokens=2,
            )
        finally:
            with self._lock:
                self.active -= 1


class _StaticSummaryProvider:
    def __init__(self) -> None:
        self.called = False
        self.user_prompt = ""

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.3,
        response_format: str = "text",
    ) -> LLMResponse:
        self.called = True
        self.user_prompt = user_prompt
        return LLMResponse(
            content=json.dumps(
                {
                    "easy_summary_ko": "LLM이 작성한 일일 요약입니다.",
                    "first_checks_ko": ["LLM이 제안한 첫 점검입니다."],
                },
                ensure_ascii=False,
            ),
            tokens_used=42,
            model_name="gemini-summary-test",
            latency_ms=123.0,
            prompt_tokens=30,
            completion_tokens=12,
        )


def test_product_api_dynamic_config_path_reloads_settings(tmp_path: Path) -> None:
    config_path_1 = _write_config(tmp_path)
    config_path_2 = tmp_path / "settings_other.yaml"
    config_path_2.write_text(
        config_path_1.read_text(encoding="utf-8").replace("threshold_low: 0.30", "threshold_low: 0.15"),
        encoding="utf-8"
    )

    api = ProductApi(config_path_1)
    assert api.settings.routing.threshold_low == 0.30

    response = api.handle(
        "POST",
        "/api/admin/config",
        json.dumps({"config_path": str(config_path_2)})
    )
    assert response.status == 200
    assert api.settings.routing.threshold_low == 0.15
    assert response.body["applied"]["config_path"] == str(config_path_2)


def test_product_api_config_path_reload_keeps_runtime_llm_overrides(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path_1 = _write_config(tmp_path)
    config_path_2 = tmp_path / "settings_other.yaml"
    config_path_2.write_text(
        config_path_1.read_text(encoding="utf-8").replace("threshold_low: 0.30", "threshold_low: 0.15"),
        encoding="utf-8"
    )

    api = ProductApi(config_path_1)
    monkeypatch.setattr(
        "soc.api.product._fetch_ollama_tags_with_timeout",
        lambda base_url, *, timeout_seconds: {
            "reachable": True,
            "url": base_url,
            "models": ["gemma4:e4b"],
        },
    )
    monkeypatch.setattr(
        "soc.api.product._preflight_ollama_generate",
        lambda base_url, model, *, timeout_seconds: {
            "ok": True,
            "url": base_url,
            "model": model,
        },
    )

    response = api.handle(
        "POST",
        "/api/admin/config",
        json.dumps(
            {
                "config_path": str(config_path_2),
                "tier1_provider": "ollama",
                "tier1_model": "gemma4:e4b",
                "tier1_ollama_url": "http://host.docker.internal:11434",
            }
        )
    )

    assert response.status == 200
    status = response.body["status"]
    assert api.settings.routing.threshold_low == 0.15
    assert status["tier1_provider"] == "ollama"
    assert status["tier1_model"] == "gemma4:e4b"
    assert status["tier1_ollama_url"] == "http://host.docker.internal:11434"

