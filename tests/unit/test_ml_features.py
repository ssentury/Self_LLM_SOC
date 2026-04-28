from soc.ml.features import (
    BINARY_FEATURE_ORDER,
    EXCLUDED_FEATURES,
    binary_feature_contract,
    build_ml_feature_dict,
)
from soc.models import Flow


def test_feature_contract_keeps_routing_fields_and_excludes_leaky_fields() -> None:
    contract = binary_feature_contract()

    assert "L4_DST_PORT" in contract.feature_order
    assert "PROTOCOL" in contract.feature_order
    assert "IPV4_SRC_ADDR" in contract.excluded_features
    assert "IPV4_DST_ADDR" in contract.excluded_features
    assert "FLOW_START_MILLISECONDS" in contract.excluded_features
    assert "FLOW_END_MILLISECONDS" in contract.excluded_features
    assert "L4_SRC_PORT" in contract.excluded_features
    assert contract.feature_order == BINARY_FEATURE_ORDER
    assert contract.excluded_features == EXCLUDED_FEATURES


def test_build_ml_feature_dict_adds_allowed_core_fields_only() -> None:
    flow = Flow(
        flow_id="flow-1",
        start_ms=1,
        end_ms=2,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=49152,
        dst_port=443,
        protocol="6",
        features={"IN_BYTES": "100", "mock_prob": "0.25"},
    )

    features = build_ml_feature_dict(flow)

    assert features["L4_DST_PORT"] == 443
    assert features["PROTOCOL"] == "6"
    assert features["IN_BYTES"] == "100"
    assert features["mock_prob"] == "0.25"
    assert "L4_SRC_PORT" not in features
    assert "IPV4_SRC_ADDR" not in features
    assert "IPV4_DST_ADDR" not in features
