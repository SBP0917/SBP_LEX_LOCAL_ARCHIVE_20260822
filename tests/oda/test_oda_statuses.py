from sbp_oda.status import FORBIDDEN_RUNTIME_AUTHORITY_OUTPUTS, ODAStatus


def test_oda_statuses_are_harness_scoped() -> None:
    assert all(status.value.startswith("HARNESS_") for status in ODAStatus)
    assert {status.value for status in ODAStatus}.isdisjoint(FORBIDDEN_RUNTIME_AUTHORITY_OUTPUTS)
