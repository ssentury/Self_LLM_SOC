from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from soc.models import Flow


RANDOM_SEED = 42

EXCLUDED_FEATURES = [
    "IPV4_SRC_ADDR",
    "IPV4_DST_ADDR",
    "FLOW_START_MILLISECONDS",
    "FLOW_END_MILLISECONDS",
    "Label",
    "Attack",
    "DNS_QUERY_ID",
    "L4_SRC_PORT",
]

BINARY_FEATURE_ORDER = [
    "L4_DST_PORT",
    "PROTOCOL",
    "L7_PROTO",
    "IN_BYTES",
    "IN_PKTS",
    "OUT_BYTES",
    "OUT_PKTS",
    "TCP_FLAGS",
    "CLIENT_TCP_FLAGS",
    "SERVER_TCP_FLAGS",
    "FLOW_DURATION_MILLISECONDS",
    "DURATION_IN",
    "DURATION_OUT",
    "MIN_TTL",
    "MAX_TTL",
    "LONGEST_FLOW_PKT",
    "SHORTEST_FLOW_PKT",
    "MIN_IP_PKT_LEN",
    "MAX_IP_PKT_LEN",
    "SRC_TO_DST_SECOND_BYTES",
    "DST_TO_SRC_SECOND_BYTES",
    "RETRANSMITTED_IN_BYTES",
    "RETRANSMITTED_IN_PKTS",
    "RETRANSMITTED_OUT_BYTES",
    "RETRANSMITTED_OUT_PKTS",
    "SRC_TO_DST_AVG_THROUGHPUT",
    "DST_TO_SRC_AVG_THROUGHPUT",
    "NUM_PKTS_UP_TO_128_BYTES",
    "NUM_PKTS_128_TO_256_BYTES",
    "NUM_PKTS_256_TO_512_BYTES",
    "NUM_PKTS_512_TO_1024_BYTES",
    "NUM_PKTS_1024_TO_1514_BYTES",
    "TCP_WIN_MAX_IN",
    "TCP_WIN_MAX_OUT",
    "ICMP_TYPE",
    "ICMP_IPV4_TYPE",
    "DNS_QUERY_TYPE",
    "DNS_TTL_ANSWER",
    "FTP_COMMAND_RET_CODE",
    "SRC_TO_DST_IAT_MIN",
    "SRC_TO_DST_IAT_MAX",
    "SRC_TO_DST_IAT_AVG",
    "SRC_TO_DST_IAT_STDDEV",
    "DST_TO_SRC_IAT_MIN",
    "DST_TO_SRC_IAT_MAX",
    "DST_TO_SRC_IAT_AVG",
    "DST_TO_SRC_IAT_STDDEV",
]

CATEGORICAL_FEATURES = [
    "PROTOCOL",
    "L7_PROTO",
    "TCP_FLAGS",
    "CLIENT_TCP_FLAGS",
    "SERVER_TCP_FLAGS",
    "ICMP_TYPE",
    "ICMP_IPV4_TYPE",
    "DNS_QUERY_TYPE",
    "FTP_COMMAND_RET_CODE",
]

ATTACK_HINT_LABEL_MAP = {
    "DDOS_attack-HOIC": "DDoS",
    "DDoS_attacks-LOIC-HTTP": "DDoS",
    "DDOS_attack-LOIC-UDP": "DDoS",
    "DoS_attacks-Hulk": "DoS",
    "DoS_attacks-SlowHTTPTest": "DoS",
    "DoS_attacks-GoldenEye": "DoS",
    "DoS_attacks-Slowloris": "DoS",
    "FTP-BruteForce": "BruteForce",
    "SSH-Bruteforce": "BruteForce",
    "Brute_Force_-Web": "WebAttack",
    "Brute_Force_-XSS": "WebAttack",
    "SQL_Injection": "WebAttack",
    "Bot": "Bot",
    "Infilteration": "Infiltration",
}


@dataclass(frozen=True)
class FeatureContract:
    feature_order: list[str]
    excluded_features: list[str]
    categorical_features: list[str]
    feature_types: dict[str, str]
    random_seed: int
    attack_hint_label_map: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def binary_feature_contract() -> FeatureContract:
    feature_types = {
        feature: (
            "categorical_int" if feature in CATEGORICAL_FEATURES else "numeric"
        )
        for feature in BINARY_FEATURE_ORDER
    }
    feature_types["L4_DST_PORT"] = "service_port_int"
    return FeatureContract(
        feature_order=list(BINARY_FEATURE_ORDER),
        excluded_features=list(EXCLUDED_FEATURES),
        categorical_features=list(CATEGORICAL_FEATURES),
        feature_types=feature_types,
        random_seed=RANDOM_SEED,
        attack_hint_label_map=dict(ATTACK_HINT_LABEL_MAP),
    )


def build_ml_feature_dict(flow: Flow) -> dict[str, Any]:
    """Build the exact feature surface seen by ML detectors.

    read_flows_csv stores some CSV columns as Flow core fields instead of
    flow.features. Add those allowed core fields back here so training and
    inference use the same contract.
    """
    return {
        **flow.features,
        "L4_DST_PORT": flow.dst_port,
        "PROTOCOL": flow.protocol,
    }
