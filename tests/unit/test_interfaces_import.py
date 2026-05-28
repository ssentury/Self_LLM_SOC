from soc.asset.source import AssetInfo, AssetSource
from soc.llm.provider import LLMProvider, LLMResponse
from soc.ml.detector import MLDetector, MLResult
from soc.threat.source import ThreatInfo, ThreatSource


def test_core_interfaces_are_importable() -> None:
    assert AssetInfo
    assert AssetSource
    assert LLMProvider
    assert LLMResponse
    assert MLDetector
    assert MLResult
    assert ThreatInfo
    assert ThreatSource
