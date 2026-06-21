from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class AuthorityEntity:
    authority_id: str
    name: str
    jurisdiction: str
    parent_authority_id: str | None = None
    legitimacy_status: str = "declared"
    revoked: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RuleEntity:
    rule_id: str
    authority_id: str
    jurisdiction: str
    effective_at: str
    expires_at: str | None = None
    precedence: int = 0
    revoked: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EvidenceEntity:
    evidence_id: str
    claim: str
    source_records: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AuthorityLinkSignal:
    authority_chain: tuple[str, ...]
    resolved: bool


@dataclass(frozen=True)
class JurisdictionSignal:
    requested_jurisdiction: str
    matched_authority_ids: tuple[str, ...]


@dataclass(frozen=True)
class PrecedenceSignal:
    ordered_rule_ids: tuple[str, ...]
    resolved: bool


@dataclass(frozen=True)
class PolicyConflictSignal:
    conflict_ids: tuple[str, ...]
    resolved: bool


@dataclass(frozen=True)
class SKGSignalPackage:
    request_fingerprint: str
    signals: dict[str, Any]
    digest: str
    signature: str
    timestamp: str

