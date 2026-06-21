from __future__ import annotations

import ast
import json
from copy import deepcopy
from pathlib import Path

from main import sample_request
from sbp_lex.authority_first.root_of_trust_runner import run_root_of_trust
from sbp_lex.classification.ap_acf import run_ap_acf_precheck
from sbp_lex.collective.context_interface import attach_collective_signals, prepare_pre_context_signals
from sbp_lex.governance.procedural_truth_runner import run_procedural_truth_pipeline
from sbp_lex.pipeline.replay_runner import run_replay_check
from sbp_lex.pipeline.runner import run_pipeline
from sbp_lex.security.pqc import generate_digest
from sbp_lex.shared.state_builder import build_state


ROOT = Path(__file__).resolve().parents[1]


def _sources(count: int) -> list[dict[str, object]]:
    return [
        {
            "source": f"phase18_source_{index}",
            "content": f"phase18_evidence_{index}",
            "verified": True,
            "attested": True,
            "freshness_valid": True,
            "consistency_valid": True,
        }
        for index in range(count)
    ]


def _request(tier: str, count: int) -> dict:
    request = sample_request()
    factor = {"LOW": 1, "MEDIUM": 2, "TOP": 3}[tier]
    request["safety_profile"] = {
        "human_safety": factor,
        "irreversibility": 0,
        "cascading_impact": 0,
        "financial_operational": 0,
    }
    request["context"]["financial_amount"] = 0
    request["context"]["evidence"] = _sources(count)
    return request


def _run(tier: str, count: int) -> dict:
    return run_pipeline(_request(tier, count))


def _contains_key(value: object, forbidden: str) -> bool:
    if isinstance(value, dict):
        return forbidden in value or any(_contains_key(item, forbidden) for item in value.values())
    if isinstance(value, list):
        return any(_contains_key(item, forbidden) for item in value)
    return False


def test_valid_top_threshold_passes() -> None:
    assert _run("TOP", 5)["procedural_truth_outcome"] == "PT_PASS"


def test_valid_medium_threshold_passes() -> None:
    assert _run("MEDIUM", 3)["procedural_truth_outcome"] == "PT_PASS"


def test_valid_low_threshold_passes() -> None:
    assert _run("LOW", 2)["procedural_truth_outcome"] == "PT_PASS"


def test_top_with_four_qualifying_sources_escalates() -> None:
    state = _run("TOP", 4)
    assert state["procedural_truth_outcome"] == "PT_ESCALATE"
    assert state["procedural_truth_result"] == "FAIL"


def test_medium_with_two_qualifying_sources_refines() -> None:
    assert _run("MEDIUM", 2)["procedural_truth_outcome"] == "PT_REFINE"


def test_low_with_one_qualifying_source_refines() -> None:
    assert _run("LOW", 1)["procedural_truth_outcome"] == "PT_REFINE"


def test_stale_source_is_excluded() -> None:
    request = _request("LOW", 2)
    request["context"]["evidence"][0]["freshness_valid"] = False
    state = run_pipeline(request)
    assert state["pt_evidence_envelope"]["qualifying_source_count"] == 1
    assert state["procedural_truth_outcome"] == "PT_REFINE"


def test_unattested_source_is_excluded() -> None:
    request = _request("LOW", 2)
    request["context"]["evidence"][0]["attested"] = False
    assert run_pipeline(request)["pt_evidence_envelope"]["qualifying_source_count"] == 1


def test_inconsistent_source_is_excluded() -> None:
    request = _request("LOW", 2)
    request["context"]["evidence"][0]["consistency_valid"] = False
    assert run_pipeline(request)["pt_evidence_envelope"]["qualifying_source_count"] == 1


def test_unverified_source_is_excluded() -> None:
    request = _request("LOW", 2)
    request["context"]["evidence"][0]["verified"] = False
    assert run_pipeline(request)["pt_evidence_envelope"]["qualifying_source_count"] == 1


def test_no_silent_tier_downgrade_or_threshold_relaxation() -> None:
    request = _request("TOP", 2)
    signals = prepare_pre_context_signals(request)
    state = build_state(request, signals)
    state["pt_evidence_envelope"]["threshold_tier"] = "LOW"
    state["pt_evidence_envelope"]["threshold_requirement"] = 2
    state["pt_evidence_envelope_digest"] = generate_digest(state["pt_evidence_envelope"])
    state = attach_collective_signals(state, signals)
    state = run_ap_acf_precheck(state)
    state = run_root_of_trust(state)
    state = run_procedural_truth_pipeline(state)
    assert state["procedural_truth_outcome"] == "PT_FAIL"
    assert "pt_threshold_tier_substitution" in state["procedural_truth_failure_reasons"]


def test_pt_envelope_digest_is_preserved() -> None:
    state = _run("MEDIUM", 3)
    assert state["pt_evidence_envelope_digest"] == generate_digest(state["pt_evidence_envelope"])


def test_root_of_trust_anchors_pt_envelope_and_admitted_digests() -> None:
    state = _run("MEDIUM", 3)
    payload = state["root_of_trust_evidence_anchor"]["payload"]
    envelope = state["pt_evidence_envelope"]
    assert state["root_of_trust_evidence_anchor"]["valid"] is True
    assert payload["request_fingerprint"] == state["request_fingerprint"]
    assert payload["skg_digest"] == envelope["skg_digest"]
    assert payload["dtn_digest"] == envelope["dtn_digest"]
    assert payload["pre_context_digest"] == envelope["pre_context_digest"]
    assert payload["pt_evidence_envelope_digest"] == state["pt_evidence_envelope_digest"]


def test_replay_reproduces_identical_pt_result() -> None:
    replay = run_replay_check(request=_request("TOP", 5), replay_count=2)
    assert replay["matched"] is True
    assert replay["runs"][0]["procedural_truth_outcome"] == "PT_PASS"
    assert replay["runs"][0]["pt_evidence_envelope_digest"] == replay["runs"][1]["pt_evidence_envelope_digest"]


def test_pt_failure_creates_non_executable_state() -> None:
    state = _run("LOW", 1)
    assert state["execution_result"] == "HALT"
    assert state["execution_verified"] is False
    assert state["persistent_inoperability"] is True


def test_pt_reentry_requires_corrected_state_and_full_retraversal() -> None:
    state = _run("MEDIUM", 2)
    reentry = state["governed_reentry"]
    assert reentry["reentry_permitted"] is False
    assert reentry["required_action"] == "full_retraversal_after_correction"
    assert reentry["required_corrections"] == [
        "corrected_evidence",
        "corrected_source_package",
        "corrected_validation_state",
        "full_retraversal",
    ]


def test_skg_remains_external_and_imports_no_canonical_runtime() -> None:
    skg_root = ROOT / "external_substrates" / "skg"
    assert skg_root.is_dir()
    for path in skg_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        assert not any(
            (isinstance(node, ast.ImportFrom) and (node.module or "").startswith("sbp_lex"))
            or (isinstance(node, ast.Import) and any(alias.name.startswith("sbp_lex") for alias in node.names))
            for node in ast.walk(tree)
        )


def test_dtn_remains_external_and_imports_no_canonical_runtime() -> None:
    dtn_root = ROOT / "external_substrates" / "dtn"
    assert dtn_root.is_dir()
    for path in dtn_root.rglob("*.py"):
        assert "sbp_lex" not in path.read_text(encoding="utf-8")


def test_external_packages_emit_no_governance_result() -> None:
    package = json.loads((ROOT / "external_substrates" / "demo" / "sample_pre_context_package.json").read_text(encoding="utf-8"))
    assert not _contains_key(package, "governance_result")


def test_external_packages_emit_no_execution_permission() -> None:
    package = json.loads((ROOT / "external_substrates" / "demo" / "sample_pre_context_package.json").read_text(encoding="utf-8"))
    assert not _contains_key(package, "execution_permission")
