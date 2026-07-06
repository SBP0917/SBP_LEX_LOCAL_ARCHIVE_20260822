from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sbp_pvpl.status import PVPLStatus


@dataclass(frozen=True)
class PublicationRecord:
    record_type: str
    created_at: str
    publication_active: bool
    external_target: str
    proof_bundle_digest: str
    status: PVPLStatus


def prepare_publication_record(proof_bundle_digest: str) -> PublicationRecord:
    return PublicationRecord(
        record_type="PVPL_LOCAL_PUBLICATION_PREPARATION_RECORD",
        created_at=datetime.now(UTC).isoformat(),
        publication_active=False,
        external_target="NONE",
        proof_bundle_digest=proof_bundle_digest,
        status=PVPLStatus.PROOF_PUBLICATION_PREPARED,
    )
