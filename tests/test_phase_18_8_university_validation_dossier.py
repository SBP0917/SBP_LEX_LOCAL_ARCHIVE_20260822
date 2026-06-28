from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from sbp_lex.local_trust.claims_to_evidence import (
    required_claim_ids,
    required_reviewer_command_ids,
)
from sbp_lex.local_trust.dossier_manifest import collect_bound_digests
from sbp_lex.local_trust.dossier_validator import (
    VALIDATION_DOSSIER_FAIL,
    VALIDATION_DOSSIER_INCOMPLETE,
    VALIDATION_DOSSIER_READY,
    validate_dossier_manifest,
)
from sbp_lex.local_trust.validation_dossier import (
    build_validation_dossier,
    load_dossier_manifest,
    validate_validation_dossier,
)
from sbp_lex.local_trust.validation_questions import required_validation_question_ids


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
REQUIRED_DOSSIER_FILES = {
    "DOSSIER_MANIFEST.json",
    "MASTER_CLAIMS_TO_EVIDENCE_INDEX.json",
    "VALIDATION_QUESTIONS.json",
    "EVIDENCE_ARTIFACT_INDEX.json",
    "SCOPE_AND_EXCLUSIONS_LOCK.json",
    "REVIEWER_VERIFICATION_COMMANDS.json",
    "UNIVERSITY_HANDOFF_README.md",
}
REQUIRED_EVIDENCE_PATHS = {
    "outputs/local_trust_root_manifest.json",
    "outputs/local_execution_environment_trust_envelope.json",
    "outputs/local_evidence_chain.json",
    "outputs/local_trust_regression_matrix.json",
    "outputs/local_constitutional_gates.json",
    "outputs/local_toolchain_guard.json",
    "outputs/local_trust_25_year_capstone.json",
    "outputs/release_integrity_bundle/RELEASE_MANIFEST.json",
    "outputs/release_integrity_bundle/ARTIFACT_HASH_INDEX.json",
    "outputs/release_integrity_bundle/VERIFICATION_COMMANDS.json",
    "outputs/release_integrity_bundle/CLAIMS_TO_EVIDENCE_SEED.json",
    "outputs/release_integrity_bundle/BOUNDARY_AND_SCOPE_LOCK.json",
    "outputs/adversarial_local_trust_negative_harness.json",
}


def test_builds_university_validation_dossier(tmp_path: Path) -> None:
    result = build_validation_dossier(REPOSITORY_ROOT, output_dir=tmp_path / "dossier")

    assert result["dossier_status"] == VALIDATION_DOSSIER_READY
    assert {path.name for path in Path(result["dossier_dir"]).iterdir()} == REQUIRED_DOSSIER_FILES


def test_dossier_manifest_exists(tmp_path: Path) -> None:
    dossier = _build_dossier(tmp_path)

    assert (dossier / "DOSSIER_MANIFEST.json").exists()


def test_master_claims_to_evidence_index_exists(tmp_path: Path) -> None:
    dossier = _build_dossier(tmp_path)

    assert (dossier / "MASTER_CLAIMS_TO_EVIDENCE_INDEX.json").exists()


def test_validation_questions_file_exists(tmp_path: Path) -> None:
    dossier = _build_dossier(tmp_path)

    assert (dossier / "VALIDATION_QUESTIONS.json").exists()


def test_evidence_artifact_index_exists(tmp_path: Path) -> None:
    dossier = _build_dossier(tmp_path)

    assert (dossier / "EVIDENCE_ARTIFACT_INDEX.json").exists()


def test_scope_and_exclusions_lock_exists(tmp_path: Path) -> None:
    dossier = _build_dossier(tmp_path)

    assert (dossier / "SCOPE_AND_EXCLUSIONS_LOCK.json").exists()


def test_reviewer_verification_commands_index_exists(tmp_path: Path) -> None:
    dossier = _build_dossier(tmp_path)

    assert (dossier / "REVIEWER_VERIFICATION_COMMANDS.json").exists()


def test_handoff_readme_exists(tmp_path: Path) -> None:
    dossier = _build_dossier(tmp_path)

    assert (dossier / "UNIVERSITY_HANDOFF_README.md").exists()


def test_dossier_binds_manifest_digest(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)

    assert manifest["bound_manifest_digest"] == _bound_digests()["manifest"]


def test_dossier_binds_execution_envelope_digest(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)

    assert manifest["bound_execution_envelope_digest"] == _bound_digests()["execution_envelope"]


def test_dossier_binds_evidence_chain_digest(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)

    assert manifest["bound_evidence_chain_digest"] == _bound_digests()["evidence_chain"]


def test_dossier_binds_regression_matrix_digest(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)

    assert manifest["bound_regression_matrix_digest"] == _bound_digests()["regression_matrix"]


def test_dossier_binds_constitutional_gates_digest(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)

    assert manifest["bound_constitutional_gates_digest"] == _bound_digests()["constitutional_gates"]


def test_dossier_binds_toolchain_guard_digest(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)

    assert manifest["bound_toolchain_guard_digest"] == _bound_digests()["toolchain_guard"]


def test_dossier_binds_capstone_digest(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)

    assert manifest["bound_capstone_digest"] == _bound_digests()["capstone"]


def test_dossier_binds_release_integrity_digest(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)

    assert manifest["bound_release_integrity_digest"] == _bound_digests()["release_integrity"]


def test_dossier_binds_adversarial_harness_digest(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)

    assert manifest["bound_adversarial_harness_digest"] == _bound_digests()["adversarial_harness"]


def test_dossier_digest_validates(tmp_path: Path) -> None:
    dossier = _build_dossier(tmp_path)

    assert validate_validation_dossier(REPOSITORY_ROOT, output_dir=dossier) == {
        "dossier_status": VALIDATION_DOSSIER_READY,
        "validation_failures": [],
    }


def test_tampered_dossier_digest_is_detected(tmp_path: Path) -> None:
    dossier = _build_dossier(tmp_path)
    manifest, claims, questions, artifacts, scope, commands = _dossier_inputs(dossier)
    manifest["dossier_digest"] = "0" * 64

    validation = validate_dossier_manifest(
        manifest,
        repository_root=REPOSITORY_ROOT,
        claims_index=claims,
        validation_questions=questions,
        evidence_artifact_index=artifacts,
        scope_lock=scope,
        reviewer_commands=commands,
    )

    assert validation["dossier_status"] == VALIDATION_DOSSIER_FAIL
    assert "dossier_digest_mismatch" in validation["validation_failures"]


def test_malformed_dossier_manifest_is_incomplete() -> None:
    validation = validate_dossier_manifest({"dossier_manifest_type": "broken"})

    assert validation["dossier_status"] == VALIDATION_DOSSIER_INCOMPLETE
    assert any(item.startswith("missing_required_section:") for item in validation["validation_failures"])


def test_required_claims_exist(tmp_path: Path) -> None:
    dossier = _build_dossier(tmp_path)
    claims = _load_json(dossier / "MASTER_CLAIMS_TO_EVIDENCE_INDEX.json")
    claim_ids = {claim["claim_id"] for claim in claims["claims"]}

    assert required_claim_ids() <= claim_ids
    assert claims["claim_summary"]["claim_count"] == 25


def test_required_validation_questions_exist(tmp_path: Path) -> None:
    dossier = _build_dossier(tmp_path)
    questions = _load_json(dossier / "VALIDATION_QUESTIONS.json")
    question_ids = {question["question_id"] for question in questions["questions"]}

    assert required_validation_question_ids() <= question_ids
    assert questions["question_summary"]["validation_question_count"] == 16


def test_required_evidence_artifacts_exist(tmp_path: Path) -> None:
    dossier = _build_dossier(tmp_path)
    artifact_index = _load_json(dossier / "EVIDENCE_ARTIFACT_INDEX.json")
    artifact_paths = {artifact["path"] for artifact in artifact_index["artifacts"]}

    assert REQUIRED_EVIDENCE_PATHS <= artifact_paths
    assert artifact_index["artifact_summary"]["missing_artifact_count"] == 0


def test_required_reviewer_commands_exist(tmp_path: Path) -> None:
    dossier = _build_dossier(tmp_path)
    commands = _load_json(dossier / "REVIEWER_VERIFICATION_COMMANDS.json")
    command_ids = {command["command_id"] for command in commands["commands"]}

    assert required_reviewer_command_ids() <= command_ids
    assert commands["command_summary"]["reviewer_command_count"] == 31


def test_scope_lock_confirms_phase_19_not_started(tmp_path: Path) -> None:
    scope = _scope(tmp_path)

    assert scope["phase_19_not_started"] is True
    assert scope["not_phase_19"] is True


def test_scope_lock_confirms_no_runtime_activation(tmp_path: Path) -> None:
    scope = _scope(tmp_path)

    assert scope["notRuntimeActivation"] is True


def test_scope_lock_confirms_no_skg_dtn_authority(tmp_path: Path) -> None:
    scope = _scope(tmp_path)

    assert scope["skg_dtn_external_non_authoritative"] is True
    assert scope["not_skg_dtn_implementation"] is True


def test_scope_lock_confirms_no_future_surfaces(tmp_path: Path) -> None:
    scope = _scope(tmp_path)

    assert scope["not_active_future_distributed_or_mobile_implementation"] is True
    assert scope["not_cloud_implementation"] is True
    assert scope["not_apk_implementation"] is True
    assert scope["not_v2_or_v3_implementation"] is True


def test_scope_lock_marks_18_9_as_next_phase_only(tmp_path: Path) -> None:
    scope = _scope(tmp_path)

    assert scope["next_phase"]["phase_id"] == "18.9"
    assert scope["next_phase"]["readiness_marker_only"] is True
    assert scope["next_phase"]["implemented_in_this_phase"] is False


def test_readme_states_what_dossier_is(tmp_path: Path) -> None:
    readme = _readme(tmp_path)

    assert "This package is a reviewer-facing dossier" in readme
    assert "claims-to-evidence index" in readme


def test_readme_states_what_dossier_is_not(tmp_path: Path) -> None:
    readme = _readme(tmp_path)

    assert "Not production certification." in readme
    assert "Not a university validation result." in readme
    assert "Not runtime activation." in readme


def test_readme_does_not_claim_university_validation_occurred(tmp_path: Path) -> None:
    readme = _readme(tmp_path).lower()

    assert "validation has occurred" not in readme
    assert "validated by a university" not in readme


def test_readme_does_not_claim_certification_occurred(tmp_path: Path) -> None:
    readme = _readme(tmp_path).lower()

    assert "certification has occurred" not in readme
    assert "certified by" not in readme


def test_cli_build_creates_dossier(tmp_path: Path) -> None:
    dossier = tmp_path / "dossier"
    result = _run_cli("build", "--path", str(dossier))

    assert result.returncode == 0
    assert "VALIDATION_DOSSIER_READY" in result.stdout
    assert (dossier / "DOSSIER_MANIFEST.json").exists()


def test_cli_validate_validates_dossier(tmp_path: Path) -> None:
    dossier = tmp_path / "dossier"
    _run_cli("build", "--path", str(dossier))
    result = _run_cli("validate", "--path", str(dossier))

    assert result.returncode == 0
    assert result.stdout.strip() == "VALIDATION_DOSSIER_READY"


def test_cli_show_prints_dossier_status(tmp_path: Path) -> None:
    dossier = tmp_path / "dossier"
    _run_cli("build", "--path", str(dossier))
    result = _run_cli("show", "--path", str(dossier))

    assert result.returncode == 0
    assert "VALIDATION_DOSSIER_READY" in result.stdout
    assert "next_phase=18.9" in result.stdout


def test_load_dossier_manifest_round_trip(tmp_path: Path) -> None:
    dossier = _build_dossier(tmp_path)
    manifest = load_dossier_manifest(REPOSITORY_ROOT, output_dir=dossier)

    assert manifest["dossier_status"] == VALIDATION_DOSSIER_READY


def test_importing_modules_does_not_execute_commands() -> None:
    result = subprocess.run(
        [sys.executable, "-c", "import sbp_lex.local_trust.validation_dossier; print('imported')"],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == "imported"


def test_dossier_sources_do_not_execute_review_commands() -> None:
    source = _dossier_source()

    assert "subprocess.run" not in source
    assert "os.system" not in source
    assert "Popen(" not in source
    assert "shell=True" not in source


def test_reviewer_commands_are_recorded_as_data_only(tmp_path: Path) -> None:
    dossier = _build_dossier(tmp_path)
    commands = _load_json(dossier / "REVIEWER_VERIFICATION_COMMANDS.json")
    command_text = {command["command"] for command in commands["commands"]}

    assert "python main.py" in command_text
    assert "python main.py replay" in command_text
    assert "scripts\\run_tests.bat" in command_text


def test_no_prohibited_active_terms_in_dossier_implementation() -> None:
    source = _dossier_source()

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


def test_false_validation_claim_in_claims_is_rejected(tmp_path: Path) -> None:
    dossier = _build_dossier(tmp_path)
    manifest, claims, questions, artifacts, scope, commands = _dossier_inputs(dossier)
    claims["claims"][0]["claim_text"] = "University validation has occurred."

    validation = validate_dossier_manifest(
        manifest,
        repository_root=REPOSITORY_ROOT,
        claims_index=claims,
        validation_questions=questions,
        evidence_artifact_index=artifacts,
        scope_lock=scope,
        reviewer_commands=commands,
    )

    assert validation["dossier_status"] == VALIDATION_DOSSIER_FAIL
    assert any(item.startswith("false_validation_or_certification_claim:") for item in validation["validation_failures"])


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


def _build_dossier(tmp_path: Path) -> Path:
    dossier = tmp_path / "dossier"
    result = build_validation_dossier(REPOSITORY_ROOT, output_dir=dossier)
    assert result["dossier_status"] == VALIDATION_DOSSIER_READY
    return dossier


def _manifest(tmp_path: Path) -> dict:
    return _load_json(_build_dossier(tmp_path) / "DOSSIER_MANIFEST.json")


def _scope(tmp_path: Path) -> dict:
    return _load_json(_build_dossier(tmp_path) / "SCOPE_AND_EXCLUSIONS_LOCK.json")


def _readme(tmp_path: Path) -> str:
    return (_build_dossier(tmp_path) / "UNIVERSITY_HANDOFF_README.md").read_text(encoding="utf-8")


def _dossier_inputs(dossier: Path) -> tuple[dict, dict, dict, dict, dict, dict]:
    return (
        _load_json(dossier / "DOSSIER_MANIFEST.json"),
        _load_json(dossier / "MASTER_CLAIMS_TO_EVIDENCE_INDEX.json"),
        _load_json(dossier / "VALIDATION_QUESTIONS.json"),
        _load_json(dossier / "EVIDENCE_ARTIFACT_INDEX.json"),
        _load_json(dossier / "SCOPE_AND_EXCLUSIONS_LOCK.json"),
        _load_json(dossier / "REVIEWER_VERIFICATION_COMMANDS.json"),
    )


def _load_json(path: Path | str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _bound_digests() -> dict[str, str]:
    return collect_bound_digests(REPOSITORY_ROOT)


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sbp_lex.local_trust.validation_dossier", *args],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _dossier_source() -> str:
    return "\n".join(
        (LOCAL_TRUST_ROOT / name).read_text(encoding="utf-8")
        for name in (
            "claims_to_evidence.py",
            "dossier_manifest.py",
            "dossier_validator.py",
            "validation_dossier.py",
            "validation_questions.py",
        )
    )
