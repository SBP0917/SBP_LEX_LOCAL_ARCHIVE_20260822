from __future__ import annotations

from sbp_pvpl.bundle import ProofBundle


def build_private_proof_summary(bundle: ProofBundle) -> dict[str, object]:
    return {
        "proof_bundle_digest": bundle.bundle_digest,
        "artifact_count": bundle.proof_summary["artifact_count"],
        "missing_count": bundle.proof_summary["missing_count"],
        "runtime_authority": bundle.runtime_authority,
        "publication_active": False,
    }
