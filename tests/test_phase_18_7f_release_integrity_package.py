from __future__ import annotations

import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

from sbp_lex.local_trust.claims_seed import required_claim_ids, required_command_ids
from sbp_lex.local_trust.release_integrity import (
    build_release_integrity_bundle,
    load_json,
    load_release_manifest,
    validate_release_integrity_bundle,
)
from sbp_lex.local_trust.release_manifest import release_digest_for, release_signature_for, hash_release_payload
from sbp_lex.local_trust.release_validator import (
    RELEASE_INTEGRITY_FAIL,
    RELEASE_INTEGRITY_INCOMPLETE,
    RELEASE_INTEGRITY_PASS,
    validate_release_manifest,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
LOCAL_TRUST_ROOT = REPOSITORY_ROOT / "sbp_lex" / "local_trust"
PROTECTED_RUNTIME_PATHS = {
    "main.py",
    "sbp_lex/execution/execution_gate.py",
    "sbp_lex/governance/procedural_truth_engine.py",
    "sbp_lex/governance/procedural_truth_runner.py",
    "sbp_lex/authority_first/root_of_trust_runner.py",
    "sbp_lex/shared/hash_chain.py",
    "sbp_lex/shared/state_builder.py",
    "sbp_lex/pipeline/dual_runner.py",
}
REQUIRED_BUNDLE_FILES = {
    "RELEASE_MANIFEST.json",
    "ARTIFACT_HASH_INDEX.json",
    "VERIFICATION_COMMANDS.json",
    "CLAIMS_TO_EVIDENCE_SEED.json",
    "BOUNDARY_AND_SCOPE_LOCK.json",
    "RELEASE_README.md",
}


def test_builds_release_integrity_bundle(tmp_path: Path) -> None:
    result = build_release_integrity_bundle(REPOSITORY_ROOT, output_dir=tmp_path / "bundle")

    assert result["release_status"] == RELEASE_INTEGRITY_PASS
    assert {path.name for path in Path(result["bundle_dir"]).iterdir()} == REQUIRED_BUNDLE_FILES


def test_required_bundle_files_exist(tmp_path: Path) -> None:
    bundle = _build_bundle(tmp_path)

    for filename in REQUIRED_BUNDLE_FILES:
        assert (bundle / filename).exists()


def test_release_manifest_binds_manifest_digest(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)

    assert manifest["bound_manifest_digest"] == _load_repo_json("outputs/local_trust_root_manifest.json")["manifest_digest"]


def test_release_manifest_binds_execution_envelope_digest(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)

    assert manifest["bound_execution_envelope_digest"] == _load_repo_json(
        "outputs/local_execution_environment_trust_envelope.json"
    )["envelope_digest"]


def test_release_manifest_binds_evidence_chain_digest(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)

    assert manifest["bound_evidence_chain_digest"] == _load_repo_json("outputs/local_evidence_chain.json")["chain_digest"]


def test_release_manifest_binds_regression_matrix_digest(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)

    assert manifest["bound_regression_matrix_digest"] == _load_repo_json("outputs/local_trust_regression_matrix.json")[
        "matrix_digest"
    ]


def test_release_manifest_binds_constitutional_gates_digest(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)

    assert manifest["bound_constitutional_gates_digest"] == _load_repo_json("outputs/local_constitutional_gates.json")[
        "gate_digest"
    ]


def test_release_manifest_binds_toolchain_guard_digest(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)

    assert manifest["bound_toolchain_guard_digest"] == _load_repo_json("outputs/local_toolchain_guard.json")[
        "toolchain_digest"
    ]


def test_release_manifest_binds_capstone_digest(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)

    assert manifest["bound_capstone_digest"] == _load_repo_json("outputs/local_trust_25_year_capstone.json")[
        "capstone_digest"
    ]


def test_release_digest_validates(tmp_path: Path) -> None:
    bundle = _build_bundle(tmp_path)

    assert validate_release_integrity_bundle(REPOSITORY_ROOT, output_dir=bundle) == {
        "release_status": RELEASE_INTEGRITY_PASS,
        "validation_failures": [],
    }


def test_tampered_release_digest_is_detected(tmp_path: Path) -> None:
    bundle = _build_bundle(tmp_path)
    manifest = load_release_manifest(REPOSITORY_ROOT, output_dir=bundle)
    index, commands, claims, boundary = _bundle_inputs(bundle)
    manifest["release_digest"] = "0" * 64

    validation = validate_release_manifest(
        manifest,
        repository_root=REPOSITORY_ROOT,
        artifact_hash_index=index,
        verification_commands=commands,
        claims_to_evidence_seed=claims,
        boundary_lock=boundary,
    )

    assert validation["release_status"] == RELEASE_INTEGRITY_FAIL
    assert "release_digest_mismatch" in validation["validation_failures"]


def test_required_artifacts_are_present_in_hash_index(tmp_path: Path) -> None:
    bundle = _build_bundle(tmp_path)
    index = load_json(bundle / "ARTIFACT_HASH_INDEX.json")
    paths = {artifact["path"] for artifact in index["artifacts"]}

    assert {
        "outputs/local_trust_root_manifest.json",
        "outputs/local_execution_environment_trust_envelope.json",
        "outputs/local_evidence_chain.json",
        "outputs/local_trust_regression_matrix.json",
        "outputs/local_constitutional_gates.json",
        "outputs/local_toolchain_guard.json",
        "outputs/local_trust_25_year_capstone.json",
    } <= paths


def test_missing_required_artifact_fails_validation(tmp_path: Path) -> None:
    bundle = _build_bundle(tmp_path)
    manifest = load_release_manifest(REPOSITORY_ROOT, output_dir=bundle)
    index, commands, claims, boundary = _bundle_inputs(bundle)
    index = deepcopy(index)
    index["artifacts"][0]["exists"] = False
    index["artifacts"][0]["sha256"] = "MISSING"
    index["artifact_summary"]["missing_artifact_count"] = 1

    validation = validate_release_manifest(
        manifest,
        repository_root=REPOSITORY_ROOT,
        artifact_hash_index=index,
        verification_commands=commands,
        claims_to_evidence_seed=claims,
        boundary_lock=boundary,
    )

    assert validation["release_status"] == RELEASE_INTEGRITY_INCOMPLETE
    assert any(item.startswith("artifact_missing:") for item in validation["validation_failures"])


def test_artifact_hash_mismatch_fails_validation(tmp_path: Path) -> None:
    bundle = _build_bundle(tmp_path)
    manifest = load_release_manifest(REPOSITORY_ROOT, output_dir=bundle)
    index, commands, claims, boundary = _bundle_inputs(bundle)
    index = deepcopy(index)
    index["artifacts"][0]["sha256"] = "0" * 64

    validation = validate_release_manifest(
        manifest,
        repository_root=REPOSITORY_ROOT,
        artifact_hash_index=index,
        verification_commands=commands,
        claims_to_evidence_seed=claims,
        boundary_lock=boundary,
    )

    assert validation["release_status"] == RELEASE_INTEGRITY_FAIL
    assert any(item.startswith("artifact_hash_mismatch:") for item in validation["validation_failures"])


def test_verification_command_index_includes_required_commands(tmp_path: Path) -> None:
    bundle = _build_bundle(tmp_path)
    commands = load_json(bundle / "VERIFICATION_COMMANDS.json")
    command_ids = {command["command_id"] for command in commands["commands"]}

    assert required_command_ids() <= command_ids


def test_claims_to_evidence_seed_includes_required_claim_seeds(tmp_path: Path) -> None:
    bundle = _build_bundle(tmp_path)
    claims = load_json(bundle / "CLAIMS_TO_EVIDENCE_SEED.json")
    claim_ids = {claim["claim_id"] for claim in claims["claim_seeds"]}

    assert required_claim_ids() <= claim_ids


def test_boundary_lock_confirms_phase_19_not_started(tmp_path: Path) -> None:
    boundary = _boundary(tmp_path)

    assert boundary["phase_19_not_started"] is True
    assert boundary["not_phase_19"] is True


def test_boundary_lock_confirms_no_runtime_activation(tmp_path: Path) -> None:
    boundary = _boundary(tmp_path)

    assert boundary["notRuntimeActivation"] is True


def test_boundary_lock_confirms_no_skg_dtn_authority(tmp_path: Path) -> None:
    boundary = _boundary(tmp_path)

    assert boundary["skg_dtn_external_non_authoritative"] is True
    assert boundary["not_skg_dtn_implementation"] is True


def test_boundary_lock_confirms_no_future_runtime_surfaces(tmp_path: Path) -> None:
    boundary = _boundary(tmp_path)

    assert boundary["not_future_distributed_or_mobile_runtime_implementation"] is True


def test_next_phase_18_7g_marker_only(tmp_path: Path) -> None:
    boundary = _boundary(tmp_path)

    assert boundary["next_phase"]["phase_id"] == "18.7G"
    assert boundary["next_phase"]["readiness_marker_only"] is True
    assert boundary["next_phase"]["implemented_in_this_phase"] is False


def test_cli_build_creates_bundle(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    result = _run_cli("build", "--path", str(bundle))

    assert result.returncode == 0
    assert "RELEASE_INTEGRITY_PASS" in result.stdout
    assert (bundle / "RELEASE_MANIFEST.json").exists()


def test_cli_validate_validates_bundle(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    _run_cli("build", "--path", str(bundle))
    result = _run_cli("validate", "--path", str(bundle))

    assert result.returncode == 0
    assert result.stdout.strip() == "RELEASE_INTEGRITY_PASS"


def test_cli_show_prints_release_integrity_status(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    _run_cli("build", "--path", str(bundle))
    result = _run_cli("show", "--path", str(bundle))

    assert result.returncode == 0
    assert "RELEASE_INTEGRITY_PASS" in result.stdout
    assert "next_phase=18.7G" in result.stdout


def test_importing_modules_does_not_execute_commands() -> None:
    result = subprocess.run(
        [sys.executable, "-c", "import sbp_lex.local_trust.release_integrity; print('imported')"],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == "imported"


def test_release_cli_sources_do_not_execute_runtime_replay_pytest_or_batch() -> None:
    source = _release_source()

    assert '["python"' not in source
    assert '["pytest"' not in source
    assert '["cmd"' not in source
    assert "shell=True" not in source


def test_no_prohibited_active_terms_in_release_implementation() -> None:
    source = _release_source()

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


def test_no_sbp_lex_runtime_authority_files_are_modified() -> None:
    result = subprocess.run(
        ["git", "diff", "--name-only", "HEAD"],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    changed = {line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()}

    assert not (changed & PROTECTED_RUNTIME_PATHS)


def _build_bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "bundle"
    result = build_release_integrity_bundle(REPOSITORY_ROOT, output_dir=bundle)
    assert result["release_status"] == RELEASE_INTEGRITY_PASS
    return bundle


def _manifest(tmp_path: Path) -> dict:
    return load_release_manifest(REPOSITORY_ROOT, output_dir=_build_bundle(tmp_path))


def _boundary(tmp_path: Path) -> dict:
    return load_json(_build_bundle(tmp_path) / "BOUNDARY_AND_SCOPE_LOCK.json")


def _bundle_inputs(bundle: Path) -> tuple[dict, dict, dict, dict]:
    return (
        load_json(bundle / "ARTIFACT_HASH_INDEX.json"),
        load_json(bundle / "VERIFICATION_COMMANDS.json"),
        load_json(bundle / "CLAIMS_TO_EVIDENCE_SEED.json"),
        load_json(bundle / "BOUNDARY_AND_SCOPE_LOCK.json"),
    )


def _load_repo_json(path: str) -> dict:
    return json.loads((REPOSITORY_ROOT / path).read_text(encoding="utf-8"))


def _refresh_manifest(manifest: dict) -> None:
    payload_digest = hash_release_payload(manifest)
    manifest["release_payload_digest"] = payload_digest
    manifest["release_signature"] = release_signature_for(payload_digest)
    manifest["release_digest"] = release_digest_for(payload_digest, manifest["release_signature"])


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sbp_lex.local_trust.release_integrity", *args],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _release_source() -> str:
    return "\n".join(
        (LOCAL_TRUST_ROOT / name).read_text(encoding="utf-8")
        for name in (
            "claims_seed.py",
            "release_hash_index.py",
            "release_integrity.py",
            "release_manifest.py",
            "release_validator.py",
        )
    )
