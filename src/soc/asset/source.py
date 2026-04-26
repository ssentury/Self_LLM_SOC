from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class AssetInfo:
    ip: str
    role: str
    services: list[str]
    criticality: str
    rationale: str
    found: bool


class AssetSource(ABC):
    @abstractmethod
    def lookup(self, ip: str) -> AssetInfo:
        raise NotImplementedError

    @abstractmethod
    def get_zone(self, ip: str) -> str:
        raise NotImplementedError


class StaticYAMLAssetSource(AssetSource):
    """Placeholder for the YAML-backed asset catalog implementation."""

    def __init__(self, path: str) -> None:
        self.path = path
        raise NotImplementedError(
            "StaticYAMLAssetSource will be implemented after the scaffold. "
            "Tier 2 currently uses sample config files directly."
        )

    def lookup(self, ip: str) -> AssetInfo:
        raise NotImplementedError

    def get_zone(self, ip: str) -> str:
        raise NotImplementedError
