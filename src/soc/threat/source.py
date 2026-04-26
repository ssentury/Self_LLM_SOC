from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ThreatInfo:
    is_known_malicious: bool
    tags: list[str]
    advisories: list[dict[str, Any]]


class ThreatSource(ABC):
    @abstractmethod
    def lookup_ip(self, ip: str) -> ThreatInfo:
        raise NotImplementedError

    @abstractmethod
    def get_recent_advisories(self, since_days: int = 7) -> list[dict[str, Any]]:
        raise NotImplementedError


class StaticYAMLThreatSource(ThreatSource):
    """Placeholder for the YAML-backed threat feed implementation."""

    def __init__(self, path: str) -> None:
        self.path = path
        raise NotImplementedError(
            "StaticYAMLThreatSource will be implemented after the scaffold. "
            "Tier 2 currently uses sample config files directly."
        )

    def lookup_ip(self, ip: str) -> ThreatInfo:
        raise NotImplementedError

    def get_recent_advisories(self, since_days: int = 7) -> list[dict[str, Any]]:
        raise NotImplementedError
