from sbp_oda.boundary import check_oda_boundary
from sbp_oda.status import ODAStatus


def test_boundary_blocks_pipeline_order_change() -> None:
    decision = check_oda_boundary("bad_action", ["change_pipeline_order"])

    assert decision.allowed is False
    assert decision.status == ODAStatus.HARNESS_BLOCKED_CANONICAL_BOUNDARY


def test_boundary_allows_health_check() -> None:
    decision = check_oda_boundary("health_check", ["repo_health_check"])

    assert decision.allowed is True
    assert decision.status == ODAStatus.HARNESS_OK


def test_boundary_blocks_unknown_operation() -> None:
    decision = check_oda_boundary("unknown", ["future_magic_repair"])

    assert decision.allowed is False
    assert decision.status == ODAStatus.HARNESS_BLOCKED_CANONICAL_BOUNDARY
    assert decision.blocked_keywords == ["future_magic_repair"]
