from sbp_pvpl.publication_record import prepare_publication_record
from sbp_pvpl.status import PVPLStatus
from sbp_pvpl.validator_handoff import prepare_validator_handoff


def test_publication_record_is_not_active_publication() -> None:
    record = prepare_publication_record("abc123")

    assert record.publication_active is False
    assert record.external_target == "NONE"
    assert record.status == PVPLStatus.PROOF_PUBLICATION_PREPARED


def test_validator_handoff_warns_no_runtime_authority() -> None:
    record = prepare_validator_handoff("abc123")

    assert record.status == PVPLStatus.PROOF_VALIDATOR_HANDOFF_PREPARED
    assert any("not treat PVPL as runtime authority" in item for item in record.instructions)
