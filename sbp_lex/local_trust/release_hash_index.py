from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence


RELEASE_BUNDLE_DIR = Path("outputs/release_integrity_bundle")
RELEASE_MANIFEST_FILE = RELEASE_BUNDLE_DIR / "RELEASE_MANIFEST.json"
ARTIFACT_HASH_INDEX_FILE = RELEASE_BUNDLE_DIR / "ARTIFACT_HASH_INDEX.json"
VERIFICATION_COMMANDS_FILE = RELEASE_BUNDLE_DIR / "VERIFICATION_COMMANDS.json"
CLAIMS_TO_EVIDENCE_SEED_FILE = RELEASE_BUNDLE_DIR / "CLAIMS_TO_EVIDENCE_SEED.json"
BOUNDARY_AND_SCOPE_LOCK_FILE = RELEASE_BUNDLE_DIR / "BOUNDARY_AND_SCOPE_LOCK.json"
RELEASE_README_FILE = RELEASE_BUNDLE_DIR / "RELEASE_README.md"


ARTIFACT_SPECS: tuple[dict[str, Any], ...] = (
    {
        "artifact_id": "local_trust_root_manifest",
        "artifact_group": "local_trust_artifacts",
        "path": "outputs/local_trust_root_manifest.json",
        "required": True,
        "reason": "Local trust root manifest.",
    },
    {
        "artifact_id": "execution_environment_trust_envelope",
        "artifact_group": "local_trust_artifacts",
        "path": "outputs/local_execution_environment_trust_envelope.json",
        "required": True,
        "reason": "Runtime and verification environment provenance.",
    },
    {
        "artifact_id": "local_evidence_chain",
        "artifact_group": "local_trust_artifacts",
        "path": "outputs/local_evidence_chain.json",
        "required": True,
        "reason": "Report integrity and evidence-chain attestation.",
    },
    {
        "artifact_id": "local_trust_regression_matrix",
        "artifact_group": "local_trust_artifacts",
        "path": "outputs/local_trust_regression_matrix.json",
        "required": True,
        "reason": "Local trust drift regression baseline.",
    },
    {
        "artifact_id": "constitutional_gates",
        "artifact_group": "local_trust_artifacts",
        "path": "outputs/local_constitutional_gates.json",
        "required": True,
        "reason": "Local trust constitutional gate result.",
    },
    {
        "artifact_id": "toolchain_guard",
        "artifact_group": "local_trust_artifacts",
        "path": "outputs/local_toolchain_guard.json",
        "required": True,
        "reason": "Dependency and toolchain guard.",
    },
    {
        "artifact_id": "local_trust_capstone",
        "artifact_group": "local_trust_artifacts",
        "path": "outputs/local_trust_25_year_capstone.json",
        "required": True,
        "reason": "25-year local trust completion lock.",
    },
    {
        "artifact_id": "zero_missing_cleanup_report",
        "artifact_group": "phase_reports",
        "path": "reports/PHASE_18_7D_1_ZERO_MISSING_EVIDENCE_CLEANUP_REPORT.md",
        "required": True,
        "reason": "Evidence chain zero-missing cleanup report.",
    },
    {
        "artifact_id": "regression_matrix_report",
        "artifact_group": "phase_reports",
        "path": "reports/PHASE_18_7E_1_LOCAL_TRUST_REGRESSION_MATRIX_REPORT.md",
        "required": True,
        "reason": "Regression matrix implementation report.",
    },
    {
        "artifact_id": "constitutional_gates_report",
        "artifact_group": "phase_reports",
        "path": "reports/PHASE_18_7E_2_CONSTITUTIONAL_ENFORCEMENT_GATES_REPORT.md",
        "required": True,
        "reason": "Constitutional gates implementation report.",
    },
    {
        "artifact_id": "toolchain_guard_report",
        "artifact_group": "phase_reports",
        "path": "reports/PHASE_18_7E_3_TOOLCHAIN_GUARD_REPORT.md",
        "required": True,
        "reason": "Toolchain guard implementation report.",
    },
    {
        "artifact_id": "capstone_report",
        "artifact_group": "phase_reports",
        "path": "reports/PHASE_18_7E_4_25_YEAR_LOCAL_TRUST_CAPSTONE_REPORT.md",
        "required": True,
        "reason": "25-year capstone implementation report.",
    },
    {
        "artifact_id": "release_integrity_report",
        "artifact_group": "phase_reports",
        "path": "reports/PHASE_18_7F_RELEASE_INTEGRITY_PACKAGE_REPORT.md",
        "required": True,
        "reason": "Release integrity implementation report.",
    },
    {
        "artifact_id": "local_trust_root_manifest_doc",
        "artifact_group": "doctrine_docs",
        "path": "docs/LOCAL_TRUST_ROOT_MANIFEST.md",
        "required": True,
        "reason": "Manifest doctrine and local-only boundary documentation.",
    },
    {
        "artifact_id": "execution_environment_doc",
        "artifact_group": "doctrine_docs",
        "path": "docs/LOCAL_EXECUTION_ENVIRONMENT_TRUST_ENVELOPE.md",
        "required": True,
        "reason": "Execution envelope documentation.",
    },
    {
        "artifact_id": "evidence_chain_doc",
        "artifact_group": "doctrine_docs",
        "path": "docs/LOCAL_EVIDENCE_CHAIN_REPORT_INTEGRITY_ATTESTATION.md",
        "required": True,
        "reason": "Evidence chain documentation.",
    },
    {
        "artifact_id": "regression_matrix_doc",
        "artifact_group": "doctrine_docs",
        "path": "docs/LOCAL_TRUST_REGRESSION_MATRIX.md",
        "required": True,
        "reason": "Regression matrix documentation.",
    },
    {
        "artifact_id": "constitutional_gates_doc",
        "artifact_group": "doctrine_docs",
        "path": "docs/LOCAL_TRUST_CONSTITUTIONAL_ENFORCEMENT_GATES.md",
        "required": True,
        "reason": "Constitutional gates documentation.",
    },
    {
        "artifact_id": "toolchain_guard_doc",
        "artifact_group": "doctrine_docs",
        "path": "docs/LOCAL_TRUST_TOOLCHAIN_GUARD.md",
        "required": True,
        "reason": "Toolchain guard documentation.",
    },
    {
        "artifact_id": "capstone_doc",
        "artifact_group": "doctrine_docs",
        "path": "docs/LOCAL_TRUST_25_YEAR_CAPSTONE.md",
        "required": True,
        "reason": "25-year capstone documentation.",
    },
    {
        "artifact_id": "release_integrity_doc",
        "artifact_group": "doctrine_docs",
        "path": "docs/RELEASE_INTEGRITY_PACKAGE.md",
        "required": True,
        "reason": "Release integrity package documentation.",
    },
    {
        "artifact_id": "test_local_trust_manifest",
        "artifact_group": "local_trust_tests",
        "path": "tests/test_phase_18_7b_local_trust_manifest.py",
        "required": True,
        "reason": "Manifest test coverage.",
    },
    {
        "artifact_id": "test_execution_envelope",
        "artifact_group": "local_trust_tests",
        "path": "tests/test_phase_18_7c_local_execution_environment_trust_envelope.py",
        "required": True,
        "reason": "Execution envelope test coverage.",
    },
    {
        "artifact_id": "test_evidence_chain",
        "artifact_group": "local_trust_tests",
        "path": "tests/test_phase_18_7d_local_evidence_chain.py",
        "required": True,
        "reason": "Evidence chain test coverage.",
    },
    {
        "artifact_id": "test_zero_missing_cleanup",
        "artifact_group": "local_trust_tests",
        "path": "tests/test_phase_18_7d_1_zero_missing_evidence_cleanup.py",
        "required": True,
        "reason": "Zero-missing cleanup test coverage.",
    },
    {
        "artifact_id": "test_regression_matrix",
        "artifact_group": "local_trust_tests",
        "path": "tests/test_phase_18_7e_1_local_trust_regression_matrix.py",
        "required": True,
        "reason": "Regression matrix test coverage.",
    },
    {
        "artifact_id": "test_constitutional_gates",
        "artifact_group": "local_trust_tests",
        "path": "tests/test_phase_18_7e_2_constitutional_enforcement_gates.py",
        "required": True,
        "reason": "Constitutional gates test coverage.",
    },
    {
        "artifact_id": "test_toolchain_guard",
        "artifact_group": "local_trust_tests",
        "path": "tests/test_phase_18_7e_3_toolchain_guard.py",
        "required": True,
        "reason": "Toolchain guard test coverage.",
    },
    {
        "artifact_id": "test_capstone",
        "artifact_group": "local_trust_tests",
        "path": "tests/test_phase_18_7e_4_local_trust_capstone.py",
        "required": True,
        "reason": "Capstone test coverage.",
    },
    {
        "artifact_id": "test_release_integrity",
        "artifact_group": "local_trust_tests",
        "path": "tests/test_phase_18_7f_release_integrity_package.py",
        "required": True,
        "reason": "Release integrity bundle test coverage.",
    },
    {
        "artifact_id": "runtime_main_entrypoint",
        "artifact_group": "runtime_replay_proof_references",
        "path": "main.py",
        "required": True,
        "reason": "Runtime verification entrypoint.",
    },
    {
        "artifact_id": "test_runner_batch",
        "artifact_group": "verification_policy_references",
        "path": "scripts/run_tests.bat",
        "required": True,
        "reason": "Windows verification wrapper.",
    },
    {
        "artifact_id": "verification_command_policy",
        "artifact_group": "verification_policy_references",
        "path": "sbp_lex/local_trust/command_policy.py",
        "required": True,
        "reason": "Local trust command policy reference.",
    },
    {
        "artifact_id": "capstone_command_index",
        "artifact_group": "verification_policy_references",
        "path": "sbp_lex/local_trust/capstone_report.py",
        "required": True,
        "reason": "Capstone command and phase index reference.",
    },
    {
        "artifact_id": "release_verification_commands",
        "artifact_group": "release_bundle",
        "path": "outputs/release_integrity_bundle/VERIFICATION_COMMANDS.json",
        "required": True,
        "reason": "Release verification command index.",
    },
    {
        "artifact_id": "release_claims_seed",
        "artifact_group": "release_bundle",
        "path": "outputs/release_integrity_bundle/CLAIMS_TO_EVIDENCE_SEED.json",
        "required": True,
        "reason": "Claims-to-evidence seed mapping.",
    },
    {
        "artifact_id": "release_boundary_lock",
        "artifact_group": "release_bundle",
        "path": "outputs/release_integrity_bundle/BOUNDARY_AND_SCOPE_LOCK.json",
        "required": True,
        "reason": "Boundary and scope lock.",
    },
    {
        "artifact_id": "release_readme",
        "artifact_group": "release_bundle",
        "path": "outputs/release_integrity_bundle/RELEASE_README.md",
        "required": True,
        "reason": "Review package README.",
    },
)


EXCLUDED_PATH_MARKERS = (
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".pytest_tmp_",
    "outputs/local_trust_temp",
)


def build_artifact_hash_index(
    repository_root: Path,
    specs: Sequence[Mapping[str, Any]] = ARTIFACT_SPECS,
    *,
    bundle_dir: Path | str = RELEASE_BUNDLE_DIR,
) -> dict[str, Any]:
    artifacts = [artifact_record(repository_root, _normalise_bundle_spec(spec, Path(bundle_dir))) for spec in specs]
    required_artifacts = [artifact for artifact in artifacts if artifact["required"]]
    missing = [artifact for artifact in required_artifacts if not artifact["exists"]]
    return {
        "artifact_hash_index_type": "release_integrity_artifact_hash_index",
        "artifact_hash_index_version": "18.7F",
        "excluded_path_markers": list(EXCLUDED_PATH_MARKERS),
        "artifacts": artifacts,
        "artifact_summary": {
            "artifact_count": len(artifacts),
            "required_artifact_count": len(required_artifacts),
            "missing_artifact_count": len(missing),
        },
    }


def artifact_record(repository_root: Path, spec: Mapping[str, Any]) -> dict[str, Any]:
    relative_path = str(spec["path"]).replace("\\", "/")
    if _is_excluded_path(relative_path):
        return {
            "artifact_id": spec["artifact_id"],
            "artifact_group": spec["artifact_group"],
            "path": relative_path,
            "exists": False,
            "size_bytes": 0,
            "sha256": "EXCLUDED_PATH",
            "required": bool(spec["required"]),
            "reason": str(spec["reason"]),
        }
    candidate = Path(relative_path)
    path = candidate if candidate.is_absolute() else repository_root / candidate
    if not path.exists() or not path.is_file():
        return {
            "artifact_id": spec["artifact_id"],
            "artifact_group": spec["artifact_group"],
            "path": relative_path,
            "exists": False,
            "size_bytes": 0,
            "sha256": "MISSING",
            "required": bool(spec["required"]),
            "reason": str(spec["reason"]),
        }
    data = path.read_bytes()
    return {
        "artifact_id": spec["artifact_id"],
        "artifact_group": spec["artifact_group"],
        "path": relative_path,
        "exists": True,
        "size_bytes": len(data),
        "sha256": sha256(data).hexdigest(),
        "required": bool(spec["required"]),
        "reason": str(spec["reason"]),
    }


def _normalise_bundle_spec(spec: Mapping[str, Any], bundle_dir: Path) -> dict[str, Any]:
    if spec.get("artifact_group") != "release_bundle":
        return dict(spec)
    filename = Path(str(spec["path"])).name
    return {**spec, "path": (bundle_dir / filename).as_posix()}


def artifact_by_path(index: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {
        str(artifact.get("path")): artifact
        for artifact in index.get("artifacts", [])
        if isinstance(artifact, Mapping)
    }


def file_sha256(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _is_excluded_path(relative_path: str) -> bool:
    return any(marker in relative_path for marker in EXCLUDED_PATH_MARKERS)
