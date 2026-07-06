from sbp_oda.capability_index import CapabilityClass, ODA_CAPABILITY_INDEX, ODA_TOOLKIT_INDEX


def test_capability_index_separates_support_from_blocked_canonical() -> None:
    assert ODA_CAPABILITY_INDEX["repo_health_check"].capability_class == CapabilityClass.DIAGNOSTIC
    assert ODA_CAPABILITY_INDEX["runtime_governance_change"].capability_class == CapabilityClass.BLOCKED_CANONICAL
    assert ODA_CAPABILITY_INDEX["runtime_governance_change"].auto_apply_allowed is False
    assert all(capability.runtime_authority is False for capability in ODA_CAPABILITY_INDEX.values())


def test_toolkit_index_contains_required_sections() -> None:
    for section in ("HEALTH_CHECKS", "DIAGNOSTICS", "MAINTENANCE", "REMOTE_SUPPORT", "DOCUMENT_CONTROL", "REPO_CONTROL", "SUPPORT_OUTPUTS"):
        assert section in ODA_TOOLKIT_INDEX
