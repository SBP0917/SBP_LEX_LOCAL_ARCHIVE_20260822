from __future__ import annotations

from pathlib import Path

from sbp_lex.local_trust.evidence_chain import (
    build_local_evidence_chain,
    compare_evidence_chain_to_current_files,
)
from sbp_lex.local_trust.evidence_registry import REQUIRED_EVIDENCE_SPECS


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
OPERATOR_ASSISTANT_REPORT = "outputs/SBP_OPERATOR_ASSISTANT_V1_COMMIT_AND_TEST_REPORT.md"
LOCAL_TRUST_ROOT = REPOSITORY_ROOT / "sbp_lex" / "local_trust"


def test_evidence_registry_includes_operator_assistant_commit_test_report() -> None:
    paths = {spec["path"] for spec in REQUIRED_EVIDENCE_SPECS}

    assert OPERATOR_ASSISTANT_REPORT in paths


def test_operator_assistant_commit_test_report_is_present() -> None:
    report = REPOSITORY_ROOT / OPERATOR_ASSISTANT_REPORT

    assert report.exists()
    assert report.read_text(encoding="utf-8").startswith("# SBP Operator Assistant V1 Commit And Test Report")


def test_evidence_chain_builds_with_zero_missing_items() -> None:
    chain = build_local_evidence_chain(REPOSITORY_ROOT)

    assert chain["evidence_chain_status"] == "EVIDENCE_CHAIN_VALID"
    assert chain["evidence_scope"]["expected_item_count"] == 15
    assert chain["evidence_scope"]["present_item_count"] == 15
    assert chain["evidence_scope"]["missing_item_count"] == 0
    assert chain["missing_evidence_items"] == []


def test_evidence_chain_compare_reports_zero_changed_items() -> None:
    chain = build_local_evidence_chain(REPOSITORY_ROOT)
    comparison = compare_evidence_chain_to_current_files(chain, repository_root=REPOSITORY_ROOT)

    assert comparison["evidence_chain_status"] == "EVIDENCE_CHAIN_VALID"
    assert comparison["changed_evidence_items"] == []


def test_no_runtime_replay_pytest_or_authority_leakage_added_to_evidence_chain_paths() -> None:
    source = "\n".join(
        (LOCAL_TRUST_ROOT / name).read_text(encoding="utf-8")
        for name in (
            "evidence_chain.py",
            "evidence_chain_validator.py",
            "evidence_registry.py",
            "report_attestation.py",
        )
    )

    assert "main.py" not in source
    assert "-m pytest" not in source
    assert "subprocess.run" not in source
    for term in (
        "node_quorum",
        "node_attestation",
        "distributed_consensus",
        "mesh_runtime",
        "cloud_runtime",
        "runtime_activation",
        "external_execution_permission",
        "external_governance_result",
    ):
        assert term not in source
