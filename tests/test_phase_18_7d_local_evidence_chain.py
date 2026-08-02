from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from sbp_lex.local_trust.evidence_chain import (
    EVIDENCE_CHAIN_SIGNATURE_DOMAIN,
    build_local_evidence_chain,
    chain_digest_for,
    chain_signature_for,
    compare_evidence_chain_to_current_files,
    hash_chain_payload,
    load_local_evidence_chain,
    write_local_evidence_chain,
)
from sbp_lex.local_trust.signing import verify_local_trust_digest
from sbp_lex.local_trust.evidence_chain_validator import (
    EVIDENCE_CHAIN_DIRTY,
    EVIDENCE_CHAIN_INCOMPLETE,
    EVIDENCE_CHAIN_INVALID,
    EVIDENCE_CHAIN_STALE,
    EVIDENCE_CHAIN_VALID,
    validate_local_evidence_chain,
)
from sbp_lex.local_trust.evidence_registry import EXCLUDED_PATHS
from sbp_lex.local_trust.execution_envelope import (
    build_execution_environment_envelope,
    write_execution_envelope,
)
from sbp_lex.local_trust.manifest import build_local_trust_manifest, write_local_trust_manifest
from sbp_lex.local_trust.report_attestation import collect_evidence_items


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
LOCAL_TRUST_ROOT = REPOSITORY_ROOT / "sbp_lex" / "local_trust"


def test_builds_evidence_chain() -> None:
    chain = build_local_evidence_chain(REPOSITORY_ROOT)

    assert chain["chain_type"] == "local_evidence_chain_report_integrity_attestation"
    assert chain["chain_version"] == "18.7D"
    assert chain["evidence_chain_status"] == EVIDENCE_CHAIN_VALID


def test_evidence_chain_includes_repository_provenance() -> None:
    chain = build_local_evidence_chain(REPOSITORY_ROOT)

    assert chain["repository_root"] == str(REPOSITORY_ROOT)
    assert chain["git_branch"] == "main"
    assert isinstance(chain["working_tree_clean"], bool)


def test_evidence_chain_binds_to_local_trust_manifest_digest() -> None:
    chain = build_local_evidence_chain(REPOSITORY_ROOT)

    assert len(chain["bound_local_trust_manifest_digest"]) == 64
    assert chain["bound_local_trust_manifest_status"] == "LOCAL_TRUST_MANIFEST_BOUND"


def test_evidence_chain_binds_to_execution_envelope_digest() -> None:
    chain = build_local_evidence_chain(REPOSITORY_ROOT)

    assert len(chain["bound_execution_envelope_digest"]) == 64
    assert chain["bound_execution_envelope_status"] == "EXECUTION_ENVELOPE_BOUND"


def test_required_evidence_files_are_hashed_when_present() -> None:
    chain = build_local_evidence_chain(REPOSITORY_ROOT)
    records = {item["path"]: item for item in chain["evidence_items"]}

    assert records["outputs/local_trust_root_manifest.json"]["exists"] is True
    assert records["outputs/local_trust_root_manifest.json"]["sha256"]
    assert records["docs/LOCAL_TRUST_ROOT_MANIFEST.md"]["exists"] is True


def test_missing_evidence_files_are_recorded_deterministically(tmp_path: Path) -> None:
    specs = [_spec("missing_report", "reports/missing.md")]
    items = collect_evidence_items(tmp_path, specs)

    assert items == [
        {
            "evidence_id": "missing_report",
            "path": "reports/missing.md",
            "category": "phase_report",
            "required": True,
            "exists": False,
            "size_bytes": None,
            "sha256": None,
            "last_modified_utc": None,
            "content_type": "text/markdown",
            "source_phase": "test",
            "attestation_status": "MISSING",
        }
    ]


def test_excluded_temp_cache_paths_are_not_included() -> None:
    chain = build_local_evidence_chain(REPOSITORY_ROOT)
    paths = {item["path"] for item in chain["evidence_items"]}

    assert ".pytest_cache" in chain["excluded_paths"]
    assert ".pytest_tmp_*" in chain["excluded_paths"]
    assert "outputs/local_trust_temp" in chain["excluded_paths"]
    assert not any(path.startswith("outputs/local_trust_temp") for path in paths)
    assert set(EXCLUDED_PATHS).issubset(set(chain["excluded_paths"]))


def test_chain_digest_validates() -> None:
    chain = build_local_evidence_chain(REPOSITORY_ROOT)
    validation = validate_local_evidence_chain(chain)

    assert validation == {"evidence_chain_status": EVIDENCE_CHAIN_VALID, "validation_failures": []}
    assert chain["chain_payload_digest"] == hash_chain_payload(chain)
    assert verify_local_trust_digest(
        EVIDENCE_CHAIN_SIGNATURE_DOMAIN,
        chain["chain_payload_digest"],
        chain["chain_signature"],
    )
    assert chain["chain_digest"] == chain_digest_for(chain["chain_payload_digest"], chain["chain_signature"])


def test_tampered_chain_digest_is_detected() -> None:
    chain = build_local_evidence_chain(REPOSITORY_ROOT)
    chain["evidence_scope"]["present_item_count"] = -1

    validation = validate_local_evidence_chain(chain)

    assert validation["evidence_chain_status"] == EVIDENCE_CHAIN_INVALID
    assert "chain_payload_digest_mismatch" in validation["validation_failures"]


def test_modified_evidence_file_is_detected_by_compare(tmp_path: Path) -> None:
    manifest_path, envelope_path = _write_bound_manifest_and_envelope(tmp_path)
    evidence_file = tmp_path / "reports" / "evidence.md"
    evidence_file.parent.mkdir(parents=True)
    evidence_file.write_text("original", encoding="utf-8")
    chain = build_local_evidence_chain(
        tmp_path,
        manifest_path=manifest_path,
        envelope_path=envelope_path,
        evidence_specs=[_spec("evidence", "reports/evidence.md")],
    )

    evidence_file.write_text("changed", encoding="utf-8")
    comparison = compare_evidence_chain_to_current_files(chain, repository_root=tmp_path)

    assert comparison["evidence_chain_status"] == EVIDENCE_CHAIN_INVALID
    assert comparison["changed_evidence_items"][0]["change_type"] == "HASH_CHANGED"


def test_missing_bound_manifest_causes_incomplete_status(tmp_path: Path) -> None:
    envelope_path = _write_envelope_only(tmp_path)
    chain = build_local_evidence_chain(tmp_path, manifest_path=tmp_path / "missing.json", envelope_path=envelope_path)

    assert chain["evidence_chain_status"] == EVIDENCE_CHAIN_INCOMPLETE
    assert "local_trust_manifest_not_bound" in chain["validation_failures"]


def test_missing_bound_envelope_causes_incomplete_status(tmp_path: Path) -> None:
    manifest_path = _write_manifest_only(tmp_path)
    chain = build_local_evidence_chain(tmp_path, manifest_path=manifest_path, envelope_path=tmp_path / "missing.json")

    assert chain["evidence_chain_status"] == EVIDENCE_CHAIN_INCOMPLETE
    assert "execution_envelope_not_bound" in chain["validation_failures"]


def test_invalid_bound_manifest_prevents_valid_status(tmp_path: Path) -> None:
    envelope_path = _write_envelope_only(tmp_path)
    invalid_manifest = tmp_path / "manifest.json"
    invalid_manifest.write_text("{not-json", encoding="utf-8")

    chain = build_local_evidence_chain(tmp_path, manifest_path=invalid_manifest, envelope_path=envelope_path)

    assert chain["evidence_chain_status"] == EVIDENCE_CHAIN_INCOMPLETE
    assert chain["bound_local_trust_manifest_digest"] == "LOCAL_TRUST_MANIFEST_INVALID"


def test_invalid_bound_envelope_prevents_valid_status(tmp_path: Path) -> None:
    manifest_path = _write_manifest_only(tmp_path)
    invalid_envelope = tmp_path / "envelope.json"
    invalid_envelope.write_text("{not-json", encoding="utf-8")

    chain = build_local_evidence_chain(tmp_path, manifest_path=manifest_path, envelope_path=invalid_envelope)

    assert chain["evidence_chain_status"] == EVIDENCE_CHAIN_INCOMPLETE
    assert chain["bound_execution_envelope_digest"] == "EXECUTION_ENVELOPE_INVALID"


def test_forbidden_authority_leakage_is_flagged() -> None:
    chain = build_local_evidence_chain(REPOSITORY_ROOT)
    chain["unsafe"] = {"execution_permission": True}
    _refresh_digests(chain)

    validation = validate_local_evidence_chain(chain)

    assert validation["evidence_chain_status"] == EVIDENCE_CHAIN_INVALID
    assert "forbidden_authority_key:$.unsafe.execution_permission" in validation["validation_failures"]


def test_stale_commit_can_produce_stale_status_when_current_validation_requested() -> None:
    chain = build_local_evidence_chain(REPOSITORY_ROOT)
    chain["git_commit"] = "0" * 40
    _refresh_digests(chain)

    validation = validate_local_evidence_chain(
        chain,
        repository_root=REPOSITORY_ROOT,
        current_validation=True,
    )

    assert validation == {"evidence_chain_status": EVIDENCE_CHAIN_STALE, "validation_failures": ["git_commit_stale"]}


def test_dirty_working_tree_can_produce_dirty_status_when_required() -> None:
    chain = build_local_evidence_chain(REPOSITORY_ROOT)
    chain["working_tree_clean"] = False
    _refresh_digests(chain)

    validation = validate_local_evidence_chain(chain, clean_required=True)

    assert validation == {"evidence_chain_status": EVIDENCE_CHAIN_DIRTY, "validation_failures": ["working_tree_dirty"]}


def test_cli_build_creates_output_file(tmp_path: Path) -> None:
    output = tmp_path / "local_evidence_chain.json"
    result = _run_cli("build", "--path", str(output))

    assert result.returncode == 0
    assert output.exists()
    assert "EVIDENCE_CHAIN_VALID" in result.stdout


def test_cli_validate_validates_output_file(tmp_path: Path) -> None:
    output = tmp_path / "local_evidence_chain.json"
    _run_cli("build", "--path", str(output))
    result = _run_cli("validate", "--path", str(output))

    assert result.returncode == 0
    assert result.stdout.strip() == "EVIDENCE_CHAIN_VALID"


def test_cli_show_prints_evidence_status(tmp_path: Path) -> None:
    output = tmp_path / "local_evidence_chain.json"
    _run_cli("build", "--path", str(output))
    result = _run_cli("show", "--path", str(output))

    assert result.returncode == 0
    assert "EVIDENCE_CHAIN_VALID" in result.stdout
    assert "branch=main" in result.stdout


def test_cli_compare_detects_unchanged_evidence(tmp_path: Path) -> None:
    output = tmp_path / "local_evidence_chain.json"
    _run_cli("build", "--path", str(output))
    result = _run_cli("compare", "--path", str(output))

    assert result.returncode == 0
    assert "EVIDENCE_CHAIN_VALID" in result.stdout
    assert "changed_evidence_items=0" in result.stdout


def test_cli_compare_detects_changed_evidence(tmp_path: Path) -> None:
    chain_path = tmp_path / "chain.json"
    chain = build_local_evidence_chain(REPOSITORY_ROOT)
    first_present = next(item for item in chain["evidence_items"] if item["exists"] is True)
    first_present["sha256"] = "0" * 64
    _refresh_digests(chain)
    write_local_evidence_chain(chain, chain_path, repository_root=REPOSITORY_ROOT)

    result = _run_cli("compare", "--path", str(chain_path))

    assert result.returncode == 1
    assert "EVIDENCE_CHAIN_INVALID" in result.stdout


def test_importing_local_trust_modules_does_not_execute_runtime_commands() -> None:
    result = subprocess.run(
        [sys.executable, "-c", "import sbp_lex.local_trust.evidence_chain; print('imported')"],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == "imported"


def test_build_validate_show_compare_do_not_run_runtime_replay_or_pytest() -> None:
    source = _phase_18_7d_source()

    assert "main.py" not in source
    assert "-m pytest" not in source
    assert "subprocess.run" not in source
    assert "run_tests.bat" not in source


def test_no_prohibited_topology_terms_added_to_phase_18_7d_implementation() -> None:
    source = _phase_18_7d_source()

    for term in [
        "node_quorum",
        "node_attestation",
        "distributed_consensus",
        "mesh_runtime",
        "cloud_runtime",
        "runtime_activation",
        "external_execution_permission",
        "external_governance_result",
    ]:
        assert term not in source


def _write_bound_manifest_and_envelope(root: Path) -> tuple[Path, Path]:
    manifest_path = _write_manifest_only(root)
    envelope = build_execution_environment_envelope(root, manifest_path=manifest_path)
    envelope_path = write_execution_envelope(envelope, root / "envelope.json", repository_root=root)
    return manifest_path, envelope_path


def _write_manifest_only(root: Path) -> Path:
    manifest = build_local_trust_manifest(root)
    return write_local_trust_manifest(manifest, root / "manifest.json", repository_root=root)


def _write_envelope_only(root: Path) -> Path:
    manifest_path = _write_manifest_only(root)
    envelope = build_execution_environment_envelope(root, manifest_path=manifest_path)
    return write_execution_envelope(envelope, root / "envelope.json", repository_root=root)


def _spec(evidence_id: str, path: str) -> dict:
    return {
        "evidence_id": evidence_id,
        "path": path,
        "category": "phase_report",
        "required": True,
        "source_phase": "test",
    }


def _refresh_digests(chain: dict) -> None:
    payload_digest = hash_chain_payload(chain)
    chain["chain_payload_digest"] = payload_digest
    chain["chain_signature"] = chain_signature_for(payload_digest)
    chain["chain_digest"] = chain_digest_for(payload_digest, chain["chain_signature"])


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sbp_lex.local_trust.evidence_chain", *args],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _phase_18_7d_source() -> str:
    names = [
        "evidence_chain.py",
        "evidence_chain_validator.py",
        "evidence_registry.py",
        "report_attestation.py",
    ]
    return "\n".join((LOCAL_TRUST_ROOT / name).read_text(encoding="utf-8") for name in names)
