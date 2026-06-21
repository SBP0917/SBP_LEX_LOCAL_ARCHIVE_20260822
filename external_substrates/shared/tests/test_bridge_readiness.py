from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path

from external_substrates.demo.build_demo_pre_context_package import build_demo_chain
from external_substrates.demo.validate_demo_bridge_package import validate_demo_bridge
from external_substrates.shared.bridge_manifest import build_bridge_manifest, validate_bridge_manifest
from external_substrates.shared.bridge_validator import (
    validate_bridge_package_chain,
    validate_dtn_package_for_bridge,
    validate_pre_context_package_for_bridge,
)
from external_substrates.shared.hard_entry_compatibility import build_hard_entry_preview, validate_hard_entry_preview


def chain() -> tuple[dict, dict, dict]:
    return build_demo_chain()


def test_valid_skg_dtn_pre_context_chain_passes_bridge_validation() -> None:
    assert validate_bridge_package_chain(*chain()) == (True, [])


def test_mismatched_skg_dtn_request_fingerprint_fails() -> None:
    skg, dtn, pre = chain()
    dtn["request_fingerprint"] = "different-request"
    valid, failures = validate_bridge_package_chain(skg, dtn, pre)
    assert not valid
    assert "request_fingerprint_mismatch" in failures


def test_mismatched_pre_context_request_fingerprint_fails() -> None:
    skg, dtn, pre = chain()
    pre["request_fingerprint"] = "different-request"
    valid, failures = validate_bridge_package_chain(skg, dtn, pre)
    assert not valid
    assert "request_fingerprint_mismatch" in failures


def test_dtn_without_skg_constraint_digest_fails() -> None:
    skg, dtn, _ = chain()
    dtn.pop("skg_constraint_digest")
    valid, failures = validate_dtn_package_for_bridge(dtn, skg)
    assert not valid
    assert "dtn_missing_skg_constraint_digest" in failures


def test_dtn_skg_constraint_digest_mismatch_fails() -> None:
    skg, dtn, _ = chain()
    dtn["skg_constraint_digest"] = "0" * 64
    valid, failures = validate_dtn_package_for_bridge(dtn, skg)
    assert not valid
    assert "dtn_skg_constraint_digest_mismatch" in failures


def test_pre_context_skg_digest_mismatch_fails() -> None:
    skg, dtn, pre = chain()
    pre["skg_package_digest"] = "0" * 64
    valid, failures = validate_bridge_package_chain(skg, dtn, pre)
    assert not valid
    assert "pre_context_skg_digest_mismatch" in failures


def test_pre_context_dtn_digest_mismatch_fails() -> None:
    skg, dtn, pre = chain()
    pre["dtn_package_digest"] = "0" * 64
    valid, failures = validate_bridge_package_chain(skg, dtn, pre)
    assert not valid
    assert "pre_context_dtn_digest_mismatch" in failures


def test_external_execution_permission_is_rejected() -> None:
    skg, dtn, pre = chain()
    skg["execution_permission"] = "forbidden"
    valid, failures = validate_bridge_package_chain(skg, dtn, pre)
    assert not valid
    assert "external_package_contains_execution_permission" in failures


def test_external_governance_result_is_rejected() -> None:
    skg, dtn, pre = chain()
    dtn["governance_result"] = "forbidden"
    valid, failures = validate_bridge_package_chain(skg, dtn, pre)
    assert not valid
    assert "external_package_contains_governance_result" in failures


def test_invalid_signature_fails() -> None:
    _, _, pre = chain()
    pre["signature"] = "invalid"
    valid, failures = validate_pre_context_package_for_bridge(pre)
    assert not valid
    assert "signature_invalid" in failures


def test_invalid_digest_fails() -> None:
    _, _, pre = chain()
    pre["digest"] = "0" * 64
    valid, failures = validate_pre_context_package_for_bridge(pre)
    assert not valid
    assert "digest_invalid" in failures


def test_stale_package_fails() -> None:
    skg, dtn, pre = chain()
    pre["freshness_valid"] = False
    valid, failures = validate_bridge_package_chain(skg, dtn, pre)
    assert not valid
    assert "stale_package" in failures


def test_inconsistent_package_fails() -> None:
    skg, dtn, pre = chain()
    pre["consistency_valid"] = False
    valid, failures = validate_bridge_package_chain(skg, dtn, pre)
    assert not valid
    assert "inconsistent_package" in failures


def test_bridge_manifest_builds_for_valid_chain() -> None:
    manifest = build_bridge_manifest(*chain())
    assert manifest["bridge_status"] == "VALIDATED"
    assert manifest["validation_failures"] == []
    assert validate_bridge_manifest(manifest) == (True, [])


def test_bridge_manifest_records_rejected_invalid_chain() -> None:
    skg, dtn, pre = chain()
    pre["dtn_package_digest"] = "0" * 64
    manifest = build_bridge_manifest(skg, dtn, pre)
    assert manifest["bridge_status"] == "REJECTED"
    assert "pre_context_dtn_digest_mismatch" in manifest["validation_failures"]
    assert validate_bridge_manifest(manifest) == (True, [])


def test_cli_writes_sample_bridge_manifest(tmp_path: Path) -> None:
    status, manifest = validate_demo_bridge(package_dir=tmp_path)
    assert status == "BRIDGE_READY"
    assert manifest["bridge_status"] == "VALIDATED"
    assert (tmp_path / "sample_bridge_manifest.json").exists()


def test_cli_does_not_mutate_runtime_artifacts(tmp_path: Path) -> None:
    runtime_file = Path("runtime_artifacts/integrity_store.jsonl")
    before = runtime_file.read_bytes() if runtime_file.exists() else None
    validate_demo_bridge(package_dir=tmp_path)
    after = runtime_file.read_bytes() if runtime_file.exists() else None
    assert after == before


def test_hard_entry_preview_contains_no_runtime_authority_result() -> None:
    _, _, pre = chain()
    preview = build_hard_entry_preview(pre)
    assert validate_hard_entry_preview(preview) == (True, [])
    forbidden = {"execution_permission", "execution_result", "governance_result", "final_admissibility"}
    assert forbidden.isdisjoint(preview)


def test_external_substrates_introduce_no_sbp_lex_imports() -> None:
    root = Path("external_substrates")
    imported: list[str] = []
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for item in ast.walk(tree):
            if isinstance(item, ast.Import):
                imported.extend(alias.name for alias in item.names if alias.name.startswith("sbp_lex"))
            elif isinstance(item, ast.ImportFrom) and (item.module or "").startswith("sbp_lex"):
                imported.append(item.module or "")
    assert imported == []


def test_external_executable_source_introduces_no_prohibited_topology_terms() -> None:
    prohibited = (
        "node_quorum",
        "node_attestation",
        "distributed consensus",
        "multi-node execution",
        "distributed mesh",
        "quorum execution",
    )
    matches: list[tuple[str, str]] = []
    for path in Path("external_substrates").rglob("*.py"):
        if "tests" in path.parts:
            continue
        text = path.read_text(encoding="utf-8").lower()
        matches.extend((str(path), term) for term in prohibited if term in text)
    assert matches == []


def test_external_bridge_emits_no_runtime_decision_values() -> None:
    manifest = build_bridge_manifest(*chain())
    rendered = repr(manifest)
    assert "'ALLOW'" not in rendered
    assert "'DENY'" not in rendered
    assert "'ESCALATE'" not in rendered

