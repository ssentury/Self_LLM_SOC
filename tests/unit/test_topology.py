from soc.api.topology import build_topology_payload
from soc.models import SourceSnapshot


def test_topology_treats_documentation_public_ranges_as_external() -> None:
    payload = build_topology_payload(
        [
            SourceSnapshot(
                name="assets",
                status="used",
                source_type="yaml",
                path_or_uri="assets.yaml",
                item_count=0,
                content="assets: []\ntrust_zones: []\n",
            )
        ],
        [
            {
                "flow_id": "flow-1",
                "src_ip": "198.51.100.10",
                "dst_ip": "10.0.0.5",
                "route": "auto_alert",
                "verdict": "alert",
                "severity": "high",
            }
        ],
    )

    nodes_by_ip = {node["ip"]: node for node in payload["nodes"]}
    assert nodes_by_ip["198.51.100.10"]["group"] == "external"
    assert nodes_by_ip["198.51.100.10"]["zone"] == "external-unknown"
    assert payload["edges"][0]["alert_count"] == 1
