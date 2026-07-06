from sbp_pvpl.boundary import check_pvpl_boundary
from sbp_pvpl.status import PVPLStatus


def test_boundary_blocks_external_publication() -> None:
    decision = check_pvpl_boundary("bad_publish", ["publish_externally"])

    assert decision.allowed is False
    assert decision.status == PVPLStatus.PROOF_BLOCKED_RUNTIME_BOUNDARY


def test_boundary_allows_local_manifest_build() -> None:
    decision = check_pvpl_boundary("build_manifest", ["build_proof_manifest"])

    assert decision.allowed is True
    assert decision.status == PVPLStatus.PROOF_OK


def test_boundary_blocks_unknown_local_action() -> None:
    decision = check_pvpl_boundary("unknown", ["future_public_validator_sync"])

    assert decision.allowed is False
    assert decision.status == PVPLStatus.PROOF_BLOCKED_RUNTIME_BOUNDARY
    assert decision.blocked_actions == ["future_public_validator_sync"]
