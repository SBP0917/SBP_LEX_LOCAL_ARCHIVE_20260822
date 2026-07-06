from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sbp_pvpl.status import PVPLStatus


@dataclass(frozen=True)
class ValidatorHandoffRecord:
    record_type: str
    created_at: str
    proof_bundle_digest: str
    instructions: tuple[str, ...]
    status: PVPLStatus


def prepare_validator_handoff(proof_bundle_digest: str) -> ValidatorHandoffRecord:
    return ValidatorHandoffRecord(
        record_type="PVPL_VALIDATOR_HANDOFF_PREPARATION_RECORD",
        created_at=datetime.now(UTC).isoformat(),
        proof_bundle_digest=proof_bundle_digest,
        instructions=(
            "Review proof manifest locally.",
            "Verify artifact hashes against repository evidence.",
            "Do not treat PVPL as runtime authority.",
            "No external publication is performed by this skeleton.",
        ),
        status=PVPLStatus.PROOF_VALIDATOR_HANDOFF_PREPARED,
    )
