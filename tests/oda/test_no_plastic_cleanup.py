from sbp_oda.capability_index import FUTURE_CAPABILITY_REGISTER, ODA_TOOLKIT_INDEX
from sbp_oda.remote_support.signed_package_receiver import receive_signed_package
from sbp_oda.repo_control.branch_status import capture_branch_status
from sbp_oda.repo_control.commit_evidence import capture_commit_evidence
from sbp_oda.status import ODAStatus


def test_signed_package_receiver_is_blocked_not_success() -> None:
    result = receive_signed_package("pkg-1")

    assert result["status"] == ODAStatus.HARNESS_BLOCKED_CANONICAL_BOUNDARY
    assert "not implemented" in result["reason"]
    assert result["auto_apply"] == "false"


def test_commit_evidence_capture_returns_structured_result() -> None:
    result = capture_commit_evidence(".")

    assert set(result) == {"commit_hash", "captured", "error"}
    assert isinstance(result["captured"], bool)
    if result["captured"]:
        assert result["commit_hash"]
        assert result["error"] == ""
    else:
        assert result["error"]


def test_branch_status_capture_returns_structured_result() -> None:
    result = capture_branch_status(".")

    assert set(result) == {"branch", "dirty", "status_short", "captured", "error"}
    assert isinstance(result["captured"], bool)
    if result["captured"]:
        assert isinstance(result["dirty"], bool)
        assert result["error"] == ""
    else:
        assert result["error"]


def test_active_capability_names_do_not_contain_placeholder() -> None:
    active_names = {
        capability_name
        for capability_group in ODA_TOOLKIT_INDEX.values()
        for capability_name in capability_group
    }

    assert all("placeholder" not in capability_name for capability_name in active_names)


def test_future_capabilities_are_not_auto_apply() -> None:
    assert FUTURE_CAPABILITY_REGISTER
    assert all(item["status"] == "NOT_IMPLEMENTED" for item in FUTURE_CAPABILITY_REGISTER.values())
    assert all(item["auto_apply_allowed"] is False for item in FUTURE_CAPABILITY_REGISTER.values())
    assert all(item["runtime_authority"] is False for item in FUTURE_CAPABILITY_REGISTER.values())
