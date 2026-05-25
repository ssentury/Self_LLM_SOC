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

