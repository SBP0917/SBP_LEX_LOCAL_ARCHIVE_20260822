from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class OperationalContextSignal:
    environment: dict[str, Any]
    operational_state: dict[str, Any]


@dataclass(frozen=True)
class DependencySignal:
    dependencies: tuple[dict[str, Any], ...]
    satisfied: bool


@dataclass(frozen=True)
class CapabilitySignal:
    capabilities: tuple[dict[str, Any], ...]
    available: bool


@dataclass(frozen=True)
class FeasibilitySignal:
    feasible: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class RiskPotentialSignal:
    score: int
    level: str


@dataclass(frozen=True)
class CascadingImpactSignal:
    score: int
    bounded: bool


@dataclass(frozen=True)
class PathwayContextSignal:
    pathway_id: str
    constraint_valid: bool


@dataclass(frozen=True)
class DTNSignalPackage:
    request_fingerprint: str
    skg_constraint_digest: str
    signals: dict[str, Any]
    digest: str
    signature: str
    timestamp: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

