from __future__ import annotations

import yaml
from pathlib import Path
from typing import Any

from soc.models import SourceSnapshot


class YamlSourceProvider:
    """Base class for YAML-backed source providers."""

    def __init__(self, name: str, config: dict[str, Any]) -> None:
        self.name = name
        self.config = config
        self.enabled = config.get("enabled", False)
        self.path = config.get("path")

    def get_snapshot(self) -> SourceSnapshot:
        if not self.enabled:
            return SourceSnapshot(
                name=self.name,
                status="disabled",
                source_type="yaml",
                path_or_uri=self.path,
                item_count=0,
                content="",
            )

        if not self.path:
            return SourceSnapshot(
                name=self.name,
                status="error",
                source_type="yaml",
                path_or_uri=None,
                item_count=0,
                content="",
                error="Path is not configured.",
            )

        filepath = Path(self.path)
        if not filepath.exists():
            return SourceSnapshot(
                name=self.name,
                status="missing",
                source_type="yaml",
                path_or_uri=self.path,
                item_count=0,
                content="",
            )

        try:
            content = filepath.read_text(encoding="utf-8")
            data = yaml.safe_load(content)
            
            if data is None:
                data = {}

            if not isinstance(data, dict):
                return SourceSnapshot(
                    name=self.name,
                    status="error",
                    source_type="yaml",
                    path_or_uri=self.path,
                    item_count=0,
                    content="",
                    error="YAML root must be a dictionary.",
                )

            validation_error = self._validate_data(data)
            if validation_error is not None:
                return SourceSnapshot(
                    name=self.name,
                    status="error",
                    source_type="yaml",
                    path_or_uri=self.path,
                    item_count=0,
                    content="",
                    error=validation_error,
                )
                
            item_count = self._count_items(data)
            return SourceSnapshot(
                name=self.name,
                status="used",
                source_type="yaml",
                path_or_uri=self.path,
                item_count=item_count,
                content=content,
            )
        except Exception as e:
            return SourceSnapshot(
                name=self.name,
                status="error",
                source_type="yaml",
                path_or_uri=self.path,
                item_count=0,
                content="",
                error=str(e),
            )

    def _count_items(self, data: Any) -> int:
        """Override in subclasses to specify how to count items."""
        if isinstance(data, dict):
            # Try some common keys or just return 1
            for key in ["assets", "policies", "cves", "threats", "indicators"]:
                if key in data and isinstance(data[key], list):
                    return len(data[key])
            return len(data)
        return 0

    def _validate_data(self, data: dict[str, Any]) -> str | None:
        return None

    def _validate_list_of_mappings(self, data: dict[str, Any], key: str) -> str | None:
        if key not in data:
            return None
        value = data[key]
        if not isinstance(value, list):
            return f"{key} must be a list."
        for index, item in enumerate(value):
            if not isinstance(item, dict):
                return f"{key}[{index}] must be a dictionary."
        return None


class YamlAssetInfoProvider(YamlSourceProvider):
    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__("assets", config)

    def _validate_data(self, data: dict[str, Any]) -> str | None:
        for key in ("assets", "trust_zones"):
            error = self._validate_list_of_mappings(data, key)
            if error is not None:
                return error
        return None

    def _count_items(self, data: Any) -> int:
        if isinstance(data, dict) and "assets" in data:
            return len(data["assets"])
        return super()._count_items(data)


class YamlPolicyInfoProvider(YamlSourceProvider):
    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__("policy", config)

    def _validate_data(self, data: dict[str, Any]) -> str | None:
        for key in ("elevated_risk_rules", "asset_specific_policies", "policies"):
            error = self._validate_list_of_mappings(data, key)
            if error is not None:
                return error
        business_hours = data.get("business_hours")
        if business_hours is not None and not isinstance(business_hours, dict):
            return "business_hours must be a dictionary."
        return None

    def _count_items(self, data: Any) -> int:
        if isinstance(data, dict):
            return sum(
                len(data[key])
                for key in ("elevated_risk_rules", "asset_specific_policies", "policies")
                if isinstance(data.get(key), list)
            )
        return super()._count_items(data)


class YamlCveInfoProvider(YamlSourceProvider):
    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__("cve_feed", config)

    def _validate_data(self, data: dict[str, Any]) -> str | None:
        for key in ("advisories", "cves"):
            error = self._validate_list_of_mappings(data, key)
            if error is not None:
                return error
        return None

    def _count_items(self, data: Any) -> int:
        if isinstance(data, dict):
            return sum(
                len(data[key])
                for key in ("advisories", "cves")
                if isinstance(data.get(key), list)
            )
        return super()._count_items(data)


class YamlThreatInfoProvider(YamlSourceProvider):
    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__("threat_feed", config)

    def _validate_data(self, data: dict[str, Any]) -> str | None:
        for key in ("known_malicious_ips", "custom_threat_context", "suspicious_patterns"):
            error = self._validate_list_of_mappings(data, key)
            if error is not None:
                return error
        return None

    def _count_items(self, data: Any) -> int:
        count = 0
        if isinstance(data, dict):
            if "known_malicious_ips" in data:
                count += len(data["known_malicious_ips"])
            if "custom_threat_context" in data:
                count += len(data["custom_threat_context"])
            if "suspicious_patterns" in data:
                count += len(data["suspicious_patterns"])
        return count if count > 0 else super()._count_items(data)
