import json
from pathlib import Path

from soc.api.product import ProductApi


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
    assert response.body["processing_state"] == "tier1_processing"
    assert response.body["event"]["flow_id"] == "api-flow-1"
    assert response.body["event"]["route"] == "tier1_llm"
    assert response.body["event"]["verdict"] == "processing"

    recent = api.handle("GET", "/api/flows/recent?limit=5")
    assert recent.status == 200
    assert recent.body["events"][0]["flow_id"] == "api-flow-1"

    import time
    time.sleep(0.1)  # wait for background task to complete

    detail = api.handle("GET", "/api/flows/api-flow-1")
    assert detail.status == 200
    assert detail.body["event"]["features"]["mock_prob"] == "0.50"
    assert len(detail.body["event"]["tier1_calls"]) == 1
    assert detail.body["event"]["watchlist_detail"]["matched"] is False


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


def test_product_api_applies_llm_runtime_options(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    api = ProductApi(config_path)

    response = api.handle(
        "POST",
        "/api/admin/config",
        json.dumps(
            {
                "tier1_provider": "ollama",
                "tier1_model": "gemma4:e4b",
                "tier1_ollama_url": "http://host.docker.internal:11434",
                "tier2_provider": "ollama",
                "tier2_model": "gemma4:26b",
                "tier2_ollama_url": "http://host.docker.internal:11434",
            }
        ),
    )

    assert response.status == 200
    status = response.body["status"]
    assert status["tier1_provider"] == "ollama"
    assert status["tier1_ollama_url"] == "http://host.docker.internal:11434"
    assert status["tier2_provider"] == "ollama"
    assert status["tier2_ollama_url"] == "http://host.docker.internal:11434"


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


def _write_config(tmp_path: Path) -> Path:
    config_dir = tmp_path / "config"
    output_dir = tmp_path / "output"
    config_dir.mkdir()
    (config_dir / "organization.yaml").write_text("name: Test Clinic\n", encoding="utf-8")
    (config_dir / "assets.yaml").write_text(
        "assets:\n  - id: web-1\n    ip: 172.31.69.28\n",
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
