from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterator, Mapping, Sequence

from sbp_lex.api.schema_validation import loads_strict_json
from sbp_lex.assurance.double_triple import (
    LEGACY_ASSURANCE_MARKERS,
    validate_trust_configuration,
)
from sbp_lex.custody.assurance import validate_profile
from sbp_lex.formal.assurance import (
    validate_artifact as validate_formal_artifact,
    write_artifact as write_formal_artifact,
)
from sbp_lex.ivvp.package import (
    _generate_current_evidence,
    build_package,
)
from sbp_lex.ivvp.verifier import verify_package
from sbp_lex.local_trust.git_provenance import (
    generated_evidence_lineage_is_bounded,
    generated_evidence_path_allowed,
)
from sbp_lex.runtime.measured_startup import (
    DEFAULT_BASELINE_PATH,
    MeasuredStartupService,
    add_pending_baseline,
    approve_pending_baseline,
    approved_baseline,
    baseline_record,
    compare_measurements,
    configured_baseline_path,
    drift_class_for,
    load_baseline_store,
    measure_runtime,
    validate_baseline_store,
    write_baseline_store,
)
from sbp_lex.security.pqc import trusted_signing_key_fingerprint
from sbp_lex.supply_chain.assurance import validate_bundle
from sbp_lex.supply_chain.provenance import (
    CANONICAL_UPSTREAM,
    EXPECTED_REPOSITORY_IDENTITY,
    collect_repository_provenance,
    normalize_repository_identity,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
STAGE_MANIFEST_NAME = "HANDOVER_STAGE_MANIFEST.json"
FINAL_ARCHIVE_PREFIX = "GRIFFITH_UNIVERSITY_EVALUATION_PACKAGE"
CONTROLLED_REVIEW_LABEL = (
    "CONFIDENTIAL - CONTROLLED UNIVERSITY REVIEW COPY"
)
EXTERNAL_EVIDENCE_DIRECTORY = "TECHNICAL_EVIDENCE"
EXTERNAL_PROPOSAL_NAME = (
    "SBP_LEX_GRIFFITH_RESEARCH_PARTNERSHIP_PROPOSAL_CONTROLLED.pdf"
)
FORBIDDEN_EXTERNAL_SUFFIXES = frozenset({
    ".bat",
    ".bundle",
    ".c",
    ".cmd",
    ".com",
    ".cpp",
    ".cs",
    ".dll",
    ".env",
    ".exe",
    ".go",
    ".idx",
    ".ipynb",
    ".jar",
    ".java",
    ".js",
    ".msi",
    ".pack",
    ".php",
    ".pl",
    ".ps1",
    ".py",
    ".pyc",
    ".pyo",
    ".rb",
    ".rs",
    ".scr",
    ".sh",
    ".ts",
    ".vb",
    ".whl",
    ".zip",
})
LOCAL_TRUST_BUILD_COMMANDS = (
    (
        "local_trust_manifest",
        "sbp_lex.local_trust.manifest",
        "build",
        "LOCAL_TRUST_VALID",
    ),
    (
        "execution_envelope",
        "sbp_lex.local_trust.execution_envelope",
        "build",
        "EXECUTION_ENV_VALID",
    ),
    (
        "evidence_chain",
        "sbp_lex.local_trust.evidence_chain",
        "build",
        "EVIDENCE_CHAIN_VALID",
    ),
    (
        "regression_matrix",
        "sbp_lex.local_trust.regression_matrix",
        "build",
        "REGRESSION_MATRIX_VALID",
    ),
    (
        "constitutional_gates",
        "sbp_lex.local_trust.constitutional_gates",
        "evaluate",
        "CONSTITUTIONAL_GATES_PASS",
    ),
    (
        "toolchain_guard",
        "sbp_lex.local_trust.toolchain_guard",
        "build",
        "TOOLCHAIN_GUARD_PASS",
    ),
    (
        "local_trust_capstone",
        "sbp_lex.local_trust.local_trust_capstone",
        "build",
        "LOCAL_TRUST_CAPSTONE_PASS",
    ),
    (
        "release_integrity",
        "sbp_lex.local_trust.release_integrity",
        "build",
        "RELEASE_INTEGRITY_PASS",
    ),
    (
        "adversarial_harness",
        "sbp_lex.local_trust.adversarial_negative_harness",
        "run",
        "ADVERSARIAL_NEGATIVE_HARNESS_PASS",
    ),
    (
        "university_dossier",
        "sbp_lex.local_trust.validation_dossier",
        "build",
        "VALIDATION_DOSSIER_READY",
    ),
)
LOCAL_TRUST_VALIDATE_COMMANDS = (
    (
        "local_trust_manifest_validate",
        "sbp_lex.local_trust.manifest",
        "validate",
        "LOCAL_TRUST_VALID",
    ),
    (
        "execution_envelope_validate",
        "sbp_lex.local_trust.execution_envelope",
        "validate",
        "EXECUTION_ENV_VALID",
    ),
    (
        "evidence_chain_validate",
        "sbp_lex.local_trust.evidence_chain",
        "validate",
        "EVIDENCE_CHAIN_VALID",
    ),
    (
        "evidence_chain_compare",
        "sbp_lex.local_trust.evidence_chain",
        "compare",
        "changed_evidence_items=0",
    ),
    (
        "regression_matrix_validate",
        "sbp_lex.local_trust.regression_matrix",
        "validate",
        "REGRESSION_MATRIX_VALID",
    ),
    (
        "constitutional_gates_validate",
        "sbp_lex.local_trust.constitutional_gates",
        "validate",
        "CONSTITUTIONAL_GATES_PASS",
    ),
    (
        "toolchain_guard_validate",
        "sbp_lex.local_trust.toolchain_guard",
        "validate",
        "TOOLCHAIN_GUARD_PASS",
    ),
    (
        "local_trust_capstone_validate",
        "sbp_lex.local_trust.local_trust_capstone",
        "validate",
        "LOCAL_TRUST_CAPSTONE_PASS",
    ),
    (
        "release_integrity_validate",
        "sbp_lex.local_trust.release_integrity",
        "validate",
        "RELEASE_INTEGRITY_PASS",
    ),
    (
        "adversarial_harness_validate",
        "sbp_lex.local_trust.adversarial_negative_harness",
        "validate",
        "ADVERSARIAL_NEGATIVE_HARNESS_PASS",
    ),
    (
        "university_dossier_validate",
        "sbp_lex.local_trust.validation_dossier",
        "validate",
        "VALIDATION_DOSSIER_READY",
    ),
)
REQUIRED_STAGE_PATHS = (
    "outputs/local_trust_root_manifest.json",
    "outputs/local_execution_environment_trust_envelope.json",
    "outputs/local_evidence_chain.json",
    "outputs/local_trust_regression_matrix.json",
    "outputs/local_constitutional_gates.json",
    "outputs/local_toolchain_guard.json",
    "outputs/local_trust_25_year_capstone.json",
    "outputs/release_integrity_bundle/RELEASE_MANIFEST.json",
    "outputs/adversarial_local_trust_negative_harness.json",
    "outputs/university_validation_dossier/DOSSIER_MANIFEST.json",
    "outputs/phq_formal_architecture_assurance.json",
    "outputs/recovery_critical_inventory.json",
    "outputs/r1_recovery_drill.json",
    "outputs/r2_software_bill_of_materials.json",
    "outputs/r2_deterministic_build_manifest.json",
    "outputs/r2_offline_verification.json",
    "outputs/r3_operational_custody_assurance.json",
    "validation_package/PACKAGE_MANIFEST.json",
)
REPLACED_DIRECTORIES = (
    "outputs/release_integrity_bundle",
    "outputs/university_validation_dossier",
    "validation_package",
)


class HandoverRegenerationError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(temporary, path)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        if not raw or len(raw) > 64 * 1024 * 1024:
            raise ValueError
        value = loads_strict_json(raw.decode("utf-8"))
    except Exception as exc:
        raise HandoverRegenerationError(
            f"json_invalid:{path.name}",
        ) from exc
    if not isinstance(value, dict):
        raise HandoverRegenerationError(f"json_invalid:{path.name}")
    return value


def _git(
    root: Path,
    *arguments: str,
    text: bool = True,
    allow_stderr: bool = False,
) -> str | bytes:
    try:
        completed = subprocess.run(
            ("git", *arguments),
            cwd=root,
            capture_output=True,
            text=text,
            check=False,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HandoverRegenerationError(
            f"git_unavailable:{arguments[0]}",
        ) from exc
    stderr = (
        completed.stderr.strip()
        if text
        else completed.stderr.strip()
    )
    if completed.returncode != 0 or (stderr and not allow_stderr):
        detail = stderr or (
            completed.stdout.strip()
            if text
            else completed.stdout.strip()
        )
        raise HandoverRegenerationError(
            f"git_failed:{arguments[0]}:{detail}",
        )
    return completed.stdout.rstrip()


def _require_clean_synced_repository(root: Path) -> str:
    status = str(
        _git(
            root,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        )
    )
    if status:
        raise HandoverRegenerationError(
            f"repository_not_clean:{status}",
        )
    if _git(root, "branch", "--show-current") != "main":
        raise HandoverRegenerationError("noncanonical_branch")
    remote = str(_git(root, "remote", "get-url", "origin"))
    if normalize_repository_identity(remote) != EXPECTED_REPOSITORY_IDENTITY:
        raise HandoverRegenerationError("noncanonical_origin")
    if (
        _git(
            root,
            "rev-parse",
            "--abbrev-ref",
            "--symbolic-full-name",
            "@{upstream}",
        )
        != CANONICAL_UPSTREAM
    ):
        raise HandoverRegenerationError("noncanonical_upstream")
    head = str(_git(root, "rev-parse", "HEAD"))
    upstream = str(_git(root, "rev-parse", "@{upstream}"))
    if head != upstream:
        raise HandoverRegenerationError(
            "repository_not_synced_to_origin_main",
        )
    if _git(root, "diff", "--check") != "":
        raise HandoverRegenerationError("git_diff_check_failed")
    symlinks = [
        line
        for line in str(_git(root, "ls-files", "-s")).splitlines()
        if line.startswith("120000 ")
    ]
    if symlinks:
        raise HandoverRegenerationError("tracked_symlink_present")
    collect_repository_provenance(root)
    return head


def _canonical_baseline_path(root: Path) -> Path:
    expected = (
        root / "sbp_lex/runtime/approved_runtime_baselines.json"
    ).resolve()
    configured = configured_baseline_path()
    default = DEFAULT_BASELINE_PATH.resolve()
    if configured != expected or default != expected:
        raise HandoverRegenerationError(
            "noncanonical_baseline_store_path",
        )
    return expected


def _require_portable_handover_environment() -> None:
    configured = [
        name
        for name in (
            "SBP_LEX_APPROVED_RUNTIME_BASELINE_PATH",
            "SBP_LEX_INTEGRITY_STORE",
            "SBP_LEX_MEASURED_STARTUP_STATE_ROOT",
            "SBP_LEX_LOCAL_TRUST_EVIDENCE_ROOT",
        )
        if os.environ.get(name)
    ]
    if configured:
        raise HandoverRegenerationError(
            "nonportable_handover_environment:"
            + ",".join(configured),
        )


def _require_trust_and_baseline(
    root: Path,
    expected_fingerprint: str,
) -> dict[str, Any]:
    configured_fingerprint = validate_trust_configuration()
    actual_fingerprint = trusted_signing_key_fingerprint()
    if (
        expected_fingerprint != configured_fingerprint
        or expected_fingerprint != actual_fingerprint
    ):
        raise HandoverRegenerationError(
            "trusted_signer_fingerprint_mismatch",
        )
    baseline_path = _canonical_baseline_path(root)
    store = load_baseline_store(baseline_path)
    baseline = approved_baseline(validate_baseline_store(store))
    service = MeasuredStartupService(
        repository_root=root,
        baseline_path=baseline_path,
    )
    status = service.validate_startup(persist=False)
    if status.get("status") != "MEASURED_STARTUP_APPROVED":
        raise HandoverRegenerationError(
            "measured_startup_not_approved",
        )
    if (
        status.get("approved_baseline_identifier")
        != baseline["baseline_identifier"]
        or status.get("runtime_identity") != baseline["runtime_identity"]
    ):
        raise HandoverRegenerationError(
            "measured_startup_baseline_linkage_invalid",
        )
    return baseline


def _reject_link_components(path: Path) -> None:
    cursor = path
    while cursor != cursor.parent:
        if cursor.exists() and cursor.is_symlink():
            raise HandoverRegenerationError("path_symlink_rejected")
        cursor = cursor.parent


def _safe_stage_root(
    repository_root: Path,
    stage_root: Path,
    *,
    require_empty: bool,
) -> Path:
    if not stage_root.is_absolute():
        raise HandoverRegenerationError("stage_root_must_be_absolute")
    _reject_link_components(stage_root)
    root = repository_root.resolve()
    stage = stage_root.resolve(strict=False)
    filesystem_root = Path(stage.anchor)
    if (
        stage == filesystem_root
        or stage == root
        or stage.is_relative_to(root)
        or root.is_relative_to(stage)
    ):
        raise HandoverRegenerationError("unsafe_stage_root")
    if stage.exists():
        if not stage.is_dir():
            raise HandoverRegenerationError("stage_root_not_directory")
        if require_empty and any(stage.iterdir()):
            raise HandoverRegenerationError("stage_root_not_empty")
    return stage


@contextlib.contextmanager
def _temporary_environment(
    changes: Mapping[str, str | None],
) -> Iterator[None]:
    previous = {name: os.environ.get(name) for name in changes}
    try:
        for name, value in changes.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _stage_environment(
    root: Path,
    stage: Path,
) -> dict[str, str | None]:
    del root
    return {
        "SBP_LEX_LOCAL_TRUST_EVIDENCE_ROOT": str(stage),
    }


def _final_environment(
    root: Path,
    stage: Path,
) -> dict[str, str | None]:
    del root, stage
    return {
        "SBP_LEX_LOCAL_TRUST_EVIDENCE_ROOT": None,
        "SBP_LEX_APPROVED_RUNTIME_BASELINE_PATH": None,
        "SBP_LEX_MEASURED_STARTUP_STATE_ROOT": None,
    }


def _run_expected(
    root: Path,
    label: str,
    command: Sequence[str],
    expected: str,
    *,
    environment: Mapping[str, str] | None = None,
    log_path: Path | None = None,
    timeout: int = 1200,
) -> None:
    try:
        completed = subprocess.run(
            tuple(command),
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            env=dict(os.environ if environment is None else environment),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HandoverRegenerationError(
            f"command_unavailable:{label}",
        ) from exc
    combined = completed.stdout + completed.stderr
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(combined, encoding="utf-8", newline="\n")
    if completed.stdout:
        print(completed.stdout, end="")
    if completed.stderr:
        print(completed.stderr, end="", file=sys.stderr)
    if completed.returncode != 0:
        raise HandoverRegenerationError(
            f"command_failed:{label}:exit_{completed.returncode}",
        )
    if expected not in combined:
        raise HandoverRegenerationError(
            f"expected_output_missing:{label}:{expected}",
        )


def baseline_preview(root: Path = REPOSITORY_ROOT) -> dict[str, Any]:
    _require_portable_handover_environment()
    source_commit = _require_clean_synced_repository(root)
    baseline_path = _canonical_baseline_path(root)
    payload = validate_baseline_store(
        load_baseline_store(baseline_path),
    )
    current_baseline = approved_baseline(payload)
    current_measurement = measure_runtime(root)
    findings = compare_measurements(
        current_measurement,
        current_baseline["measurement"],
    )
    return {
        "source_commit": source_commit,
        "current_baseline_identifier":
            current_baseline["baseline_identifier"],
        "current_baseline_sequence": current_baseline["sequence"],
        "current_measurement_digest":
            current_measurement["measurement_digest"],
        "drift_class": drift_class_for(findings),
        "findings": [
            {
                "drift_class": item.drift_class,
                "reason": item.reason,
                "component": item.component,
            }
            for item in findings
        ],
    }


def approve_successor_baseline(
    new_identifier: str,
    approval_reference: str,
    confirmation: str,
    *,
    root: Path = REPOSITORY_ROOT,
) -> dict[str, Any]:
    preview = baseline_preview(root)
    retired_identifier = str(
        preview["current_baseline_identifier"],
    )
    expected_confirmation = (
        f"APPROVE:{new_identifier}:RETIRE:{retired_identifier}"
    )
    if confirmation != expected_confirmation:
        raise HandoverRegenerationError(
            "baseline_confirmation_mismatch",
        )
    if preview["drift_class"] == "approved":
        raise HandoverRegenerationError(
            "successor_baseline_not_required",
        )
    path = _canonical_baseline_path(root)
    store = load_baseline_store(path)
    payload = validate_baseline_store(store)
    sequence = max(
        int(item["sequence"]) for item in payload["baselines"]
    ) + 1
    pending = baseline_record(
        new_identifier,
        measure_runtime(root),
        sequence=sequence,
    )
    proposed = add_pending_baseline(store, pending)
    approved = approve_pending_baseline(
        proposed,
        new_identifier,
        approval_reference=approval_reference,
        retire_approved_identifier=retired_identifier,
    )
    write_baseline_store(path, approved)
    final_payload = validate_baseline_store(load_baseline_store(path))
    final = approved_baseline(final_payload)
    if final["baseline_identifier"] != new_identifier:
        raise HandoverRegenerationError(
            "successor_baseline_approval_failed",
        )
    status = str(
        _git(
            root,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        )
    ).splitlines()
    expected_path = "sbp_lex/runtime/approved_runtime_baselines.json"
    if not status or any(
        line[3:].replace("\\", "/") != expected_path
        for line in status
        if len(line) >= 4
    ):
        raise HandoverRegenerationError(
            "baseline_approval_changed_unexpected_paths",
        )
    return {
        **preview,
        "approved_baseline_identifier": new_identifier,
        "retired_baseline_identifier": retired_identifier,
        "approval_reference": approval_reference,
        "runtime_identity": final["runtime_identity"],
    }


def _command(
    module: str,
    action: str,
) -> tuple[str, ...]:
    return (
        sys.executable,
        "-m",
        module,
        action,
        "--clean-required",
    )


def _bounded_files(stage: Path) -> tuple[Path, ...]:
    files: list[Path] = []
    for relative in ("outputs", "validation_package"):
        boundary = stage / relative
        if boundary.is_symlink() or not boundary.is_dir():
            raise HandoverRegenerationError(
                f"stage_boundary_missing:{relative}",
            )
        for path in boundary.rglob("*"):
            if path.is_symlink():
                raise HandoverRegenerationError(
                    "stage_symlink_rejected",
                )
            if path.is_file():
                files.append(path)
    return tuple(
        sorted(files, key=lambda item: item.relative_to(stage).as_posix())
    )


def _scan_legacy(
    stage: Path,
    baseline_path: Path,
) -> None:
    findings: list[str] = []
    for path in (*_bounded_files(stage), baseline_path):
        raw = path.read_bytes()
        for marker in LEGACY_ASSURANCE_MARKERS:
            if marker in raw:
                findings.append(
                    f"{path}:{marker.decode('ascii')}",
                )
    if findings:
        raise HandoverRegenerationError(
            "legacy_assurance_evidence:" + ",".join(findings),
        )


def _stage_file_records(stage: Path) -> list[dict[str, Any]]:
    return [
        {
            "path": path.relative_to(stage).as_posix(),
            "sha256": _sha256(path),
            "size_bytes": path.stat().st_size,
        }
        for path in _bounded_files(stage)
    ]


def _validate_required_stage_paths(stage: Path) -> None:
    missing = [
        relative
        for relative in REQUIRED_STAGE_PATHS
        if not (stage / relative).is_file()
        or (stage / relative).is_symlink()
    ]
    if missing:
        raise HandoverRegenerationError(
            "stage_evidence_missing:" + ",".join(missing),
        )


def _write_stage_manifest(
    root: Path,
    stage: Path,
    source_commit: str,
    expected_fingerprint: str,
    baseline: Mapping[str, Any],
) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "manifest_version":
            "SBP_UNIVERSITY_HANDOVER_STAGE_MANIFEST_V1",
        "source_commit": source_commit,
        "source_tree": str(
            _git(root, "rev-parse", f"{source_commit}^{{tree}}"),
        ),
        "trusted_signer_fingerprint": expected_fingerprint,
        "measured_baseline_identifier":
            baseline["baseline_identifier"],
        "runtime_identity": baseline["runtime_identity"],
        "generated_at": datetime.now(timezone.utc).replace(
            microsecond=0,
        ).isoformat(),
        "files": _stage_file_records(stage),
    }
    manifest["manifest_digest"] = hashlib.sha256(
        json.dumps(
            manifest,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    _atomic_json(stage / STAGE_MANIFEST_NAME, manifest)
    return manifest


def validate_stage(
    stage_root: Path,
    *,
    root: Path = REPOSITORY_ROOT,
) -> dict[str, Any]:
    stage = _safe_stage_root(root, stage_root, require_empty=False)
    manifest = _read_json(stage / STAGE_MANIFEST_NAME)
    digest = manifest.get("manifest_digest")
    core = {
        key: value
        for key, value in manifest.items()
        if key != "manifest_digest"
    }
    expected = hashlib.sha256(
        json.dumps(
            core,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    if digest != expected:
        raise HandoverRegenerationError(
            "stage_manifest_digest_invalid",
        )
    records = manifest.get("files")
    if not isinstance(records, list) or not records:
        raise HandoverRegenerationError(
            "stage_manifest_files_invalid",
        )
    actual = _stage_file_records(stage)
    if records != actual:
        raise HandoverRegenerationError(
            "stage_manifest_file_mismatch",
        )
    _validate_required_stage_paths(stage)
    return manifest


def _build_runtime_seeded_evidence(
    root: Path,
    stage: Path,
) -> dict[str, Path]:
    """Create runtime evidence before recovery inventory construction.

    ``build_package`` performs the canonical runtime traversal that writes the
    signed integrity ledger and its checkpoint.  Recovery inventory generation
    must follow that producer; reversing this order fails closed because the
    required ``security.integrity_ledger`` artefact does not yet exist.
    """
    build_package(root, stage / "validation_package")
    return _generate_current_evidence(root, stage)


def generate_handover_stage(
    stage_root: Path,
    expected_fingerprint: str,
    *,
    root: Path = REPOSITORY_ROOT,
) -> dict[str, Any]:
    _require_portable_handover_environment()
    source_commit = _require_clean_synced_repository(root)
    baseline = _require_trust_and_baseline(
        root,
        expected_fingerprint,
    )
    stage = _safe_stage_root(root, stage_root, require_empty=True)
    stage.mkdir(parents=True, exist_ok=True)
    environment_changes = _stage_environment(root, stage)
    with _temporary_environment(environment_changes):
        formal_path = (
            stage
            / "outputs/phq_formal_architecture_assurance.json"
        )
        write_formal_artifact(formal_path, root)
        validate_formal_artifact(_read_json(formal_path), root)

        for label, module, action, expected in (
            LOCAL_TRUST_BUILD_COMMANDS
        ):
            _run_expected(
                root,
                label,
                _command(module, action),
                expected,
            )

        state_service = MeasuredStartupService(
            repository_root=root,
            baseline_path=_canonical_baseline_path(root),
        )
        state_service.validate_startup(persist=True)

        artifact_sources = _build_runtime_seeded_evidence(root, stage)
        workspace = stage / "r1_recovery_drill_workspace"
        if workspace.exists():
            shutil.rmtree(workspace)

        for label, module, action, expected in (
            LOCAL_TRUST_VALIDATE_COMMANDS
        ):
            _run_expected(
                root,
                label,
                _command(module, action),
                expected,
            )

        outputs = stage / "outputs"
        validate_bundle(
            root,
            sbom_path=outputs / "r2_software_bill_of_materials.json",
            manifest_path=(
                outputs / "r2_deterministic_build_manifest.json"
            ),
            verification_path=outputs / "r2_offline_verification.json",
            artifact_sources=artifact_sources,
        )
        r3_path = outputs / "r3_operational_custody_assurance.json"
        validate_profile(
            _read_json(r3_path),
            root,
            baseline_path=_canonical_baseline_path(root),
            r2_manifest_path=(
                outputs / "r2_deterministic_build_manifest.json"
            ),
        )
        verify_package(
            stage / "validation_package",
            repository_root=root,
            expected_signer_fingerprint=expected_fingerprint,
        )

    _validate_required_stage_paths(stage)
    _scan_legacy(stage, _canonical_baseline_path(root))
    return _write_stage_manifest(
        root,
        stage,
        source_commit,
        expected_fingerprint,
        baseline,
    )


def _backup_path(stage: Path, relative: str) -> Path:
    return stage / "previous_repository_evidence" / relative


def _copy_file_with_backup(
    source: Path,
    destination: Path,
    backup: Path,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if destination.is_symlink() or not destination.is_file():
            raise HandoverRegenerationError(
                f"unsafe_existing_file:{destination}",
            )
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(destination, backup)
    temporary = destination.with_name(
        f".{destination.name}.{uuid.uuid4().hex}.handover",
    )
    shutil.copy2(source, temporary)
    os.replace(temporary, destination)


def _replace_directory_with_backup(
    source: Path,
    destination: Path,
    backup: Path,
) -> None:
    if source.is_symlink() or not source.is_dir():
        raise HandoverRegenerationError(
            f"stage_directory_invalid:{source}",
        )
    if destination.exists():
        if destination.is_symlink() or not destination.is_dir():
            raise HandoverRegenerationError(
                f"unsafe_existing_directory:{destination}",
            )
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(destination, backup)
    temporary = destination.with_name(
        f".{destination.name}.{uuid.uuid4().hex}.handover",
    )
    shutil.copytree(source, temporary)
    if destination.exists():
        shutil.rmtree(destination)
    os.replace(temporary, destination)


def _install_stage_files(
    root: Path,
    stage: Path,
) -> tuple[str, ...]:
    backup_root = stage / "previous_repository_evidence"
    if backup_root.exists():
        raise HandoverRegenerationError(
            "stage_backup_already_exists",
        )
    replaced = set(REPLACED_DIRECTORIES)
    installed: list[str] = []
    for relative in REPLACED_DIRECTORIES:
        _replace_directory_with_backup(
            stage / relative,
            root / relative,
            _backup_path(stage, relative),
        )
        installed.append(relative)
    for source in sorted(
        (stage / "outputs").rglob("*"),
        key=lambda item: item.relative_to(stage).as_posix(),
    ):
        if not source.is_file():
            continue
        relative = source.relative_to(stage).as_posix()
        if any(
            relative == directory
            or relative.startswith(directory + "/")
            for directory in replaced
        ):
            continue
        if not generated_evidence_path_allowed(relative):
            raise HandoverRegenerationError(
                f"unapproved_generated_path:{relative}",
            )
        _copy_file_with_backup(
            source,
            root / relative,
            _backup_path(stage, relative),
        )
        installed.append(relative)
    return tuple(installed)


def record_handover_evidence(
    stage_root: Path,
    *,
    root: Path = REPOSITORY_ROOT,
    commit_message: str = (
        "chore(evidence): regenerate university handover package"
    ),
) -> dict[str, Any]:
    source_commit = _require_clean_synced_repository(root)
    stage = _safe_stage_root(root, stage_root, require_empty=False)
    manifest = validate_stage(stage, root=root)
    if manifest.get("source_commit") != source_commit:
        raise HandoverRegenerationError(
            "stage_source_commit_mismatch",
        )
    installed = _install_stage_files(root, stage)
    status = str(
        _git(
            root,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        )
    )
    if not status:
        raise HandoverRegenerationError(
            "no_generated_evidence_changes",
        )
    status_paths = [
        line[3:].replace("\\", "/")
        for line in status.splitlines()
        if len(line) >= 4
    ]
    if any(
        not generated_evidence_path_allowed(path)
        for path in status_paths
    ):
        raise HandoverRegenerationError(
            "unexpected_repository_change:"
            + ",".join(status_paths),
        )
    _git(root, "add", "-A", "--", *installed)
    staged_raw = _git(
        root,
        "diff",
        "--cached",
        "--name-only",
        "-z",
        text=False,
    )
    if not isinstance(staged_raw, bytes):
        raise HandoverRegenerationError(
            "staged_path_inventory_invalid",
        )
    staged_paths = tuple(
        path.decode("utf-8")
        for path in staged_raw.split(b"\0")
        if path
    )
    if (
        not staged_paths
        or any(
            not generated_evidence_path_allowed(path)
            for path in staged_paths
        )
    ):
        raise HandoverRegenerationError(
            "staged_generated_path_scope_invalid",
        )
    _git(root, "commit", "-m", commit_message)
    evidence_commit = str(_git(root, "rev-parse", "HEAD"))
    if not generated_evidence_lineage_is_bounded(
        root,
        source_commit,
        current_commit=evidence_commit,
    ):
        raise HandoverRegenerationError(
            "recorded_evidence_lineage_invalid",
        )
    if _git(
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    ) != "":
        raise HandoverRegenerationError(
            "repository_dirty_after_evidence_commit",
        )
    return {
        "source_commit": source_commit,
        "evidence_commit": evidence_commit,
        "recorded_paths": list(staged_paths),
    }


def _assert_repository_matches_stage(
    root: Path,
    stage: Path,
    manifest: Mapping[str, Any],
) -> None:
    records = manifest.get("files")
    if not isinstance(records, list):
        raise HandoverRegenerationError(
            "stage_manifest_files_invalid",
        )
    for record in records:
        if not isinstance(record, Mapping):
            raise HandoverRegenerationError(
                "stage_manifest_files_invalid",
            )
        relative = str(record.get("path", ""))
        if not generated_evidence_path_allowed(relative):
            raise HandoverRegenerationError(
                f"stage_path_not_installable:{relative}",
            )
        path = root / relative
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_size != record.get("size_bytes")
            or _sha256(path) != record.get("sha256")
        ):
            raise HandoverRegenerationError(
                f"repository_stage_mismatch:{relative}",
            )


def verify_recorded_handover(
    stage_root: Path,
    expected_fingerprint: str,
    *,
    root: Path = REPOSITORY_ROOT,
) -> dict[str, Any]:
    evidence_commit = _require_clean_synced_repository(root)
    baseline = _require_trust_and_baseline(
        root,
        expected_fingerprint,
    )
    stage = _safe_stage_root(root, stage_root, require_empty=False)
    manifest = validate_stage(stage, root=root)
    source_commit = str(manifest.get("source_commit", ""))
    if not generated_evidence_lineage_is_bounded(
        root,
        source_commit,
        current_commit=evidence_commit,
    ):
        raise HandoverRegenerationError(
            "final_evidence_lineage_invalid",
        )
    if (
        manifest.get("trusted_signer_fingerprint")
        != expected_fingerprint
        or manifest.get("measured_baseline_identifier")
        != baseline["baseline_identifier"]
    ):
        raise HandoverRegenerationError(
            "stage_trust_identity_mismatch",
        )
    _assert_repository_matches_stage(root, stage, manifest)
    _scan_legacy(root, _canonical_baseline_path(root))

    logs = stage / "verification_logs"
    environment_changes = _final_environment(root, stage)
    with _temporary_environment(environment_changes):
        environment = dict(os.environ)
        _run_expected(
            root,
            "double_triple_handover",
            (
                sys.executable,
                "-m",
                "sbp_lex.assurance.double_triple",
                "--mode",
                "handover",
            ),
            "DOUBLE_TRIPLE_HANDOVER_ASSURANCE_PASS",
            environment=environment,
            log_path=logs / "double_triple_handover_run_1.log",
            timeout=2400,
        )
        for run_number in (2, 3):
            _run_expected(
                root,
                f"double_triple_evidence_{run_number}",
                (
                    sys.executable,
                    "-m",
                    "sbp_lex.assurance.double_triple",
                    "--mode",
                    "evidence",
                ),
                "DOUBLE_TRIPLE_HANDOVER_ASSURANCE_PASS",
                environment=environment,
                log_path=(
                    logs
                    / f"double_triple_evidence_run_{run_number}.log"
                ),
                timeout=1200,
            )
    return {
        "status": "OWNER_SIDE_HANDOVER_ASSURANCE_PASSED",
        "source_commit": source_commit,
        "evidence_commit": evidence_commit,
        "measured_baseline_identifier":
            baseline["baseline_identifier"],
        "trusted_signer_fingerprint": expected_fingerprint,
        "verification_runs": 3,
    }


def _external_readme(
    verification: Mapping[str, Any],
) -> str:
    return "\n".join([
        "# Griffith University Evaluation Package",
        "",
        CONTROLLED_REVIEW_LABEL,
        "",
        "This is a bounded, assessor-facing technical evidence package. "
        "It records owner-side assurance and requests independent "
        "examination. It does not claim Griffith University validation, "
        "endorsement, certification, production approval, legal "
        "conclusions, or runtime authority.",
        "",
        "Release is permitted only after a named assessor, approved review "
        "scope, confidentiality/IP controls, and explicit owner approval "
        "are recorded. For an initial institutional enquiry, send only the "
        "controlled proposal unless Griffith requests the Level C "
        "technical material.",
        "",
        "No repository, Git history, source snapshot, executable code, "
        "credentials, signing seed, or private key is included.",
        "",
        (
            "Recorded source authority commit: "
            f"`{verification['source_commit']}`"
        ),
        (
            "Recorded evidence commit: "
            f"`{verification['evidence_commit']}`"
        ),
        (
            "Measured baseline: "
            f"`{verification['measured_baseline_identifier']}`"
        ),
        (
            "Trusted signer fingerprint: "
            f"`{verification['trusted_signer_fingerprint']}`"
        ),
        (
            "Controlled proposal SHA-256: "
            f"`{verification['proposal_sha256']}`"
        ),
        "",
        "The trusted ML-DSA public key must be obtained through a separate "
        "authenticated channel. Do not establish trust from this archive "
        "alone.",
        "",
        "Contents:",
        "",
        f"- `{EXTERNAL_PROPOSAL_NAME}`: controlled partnership proposal.",
        f"- `{EXTERNAL_EVIDENCE_DIRECTORY}/`: bounded R4 evidence package.",
        "- `VERIFICATION_LOGS/`: path-redacted owner-side assurance logs "
        "and an index binding each redacted log to its private raw-log "
        "SHA-256.",
        "- `OWNER_ASSURANCE_RECORD.json`: owner-side verification status "
        "and bounded identifiers.",
        "- `SHA256SUMS.txt`: outer-package file hashes.",
        "",
        f"Start with `{EXTERNAL_PROPOSAL_NAME}`, then "
        f"`{EXTERNAL_EVIDENCE_DIRECTORY}/QUICK_START.md`.",
        "",
        "Repository-bound reproduction, if later approved, must occur in a "
        "separately controlled verification session. Repository custody is "
        "not transferred by this package.",
        "",
    ])


def _controlled_review_notice() -> str:
    return "\n".join([
        f"# {CONTROLLED_REVIEW_LABEL}",
        "",
        "Recipient restriction: named Griffith University assessor or "
        "research-development contact only.",
        "",
        "Permitted purpose: confidential technical scoping and evaluation "
        "of the bounded SBP-LEX Desktop V1 evidence.",
        "",
        "Prohibited: forwarding, publication, repository inference or "
        "reconstruction, credential use, source transfer, or treating "
        "owner-side results as independent university findings.",
        "",
        "External validation remains pending. Adverse findings and "
        "limitations must be preserved in the assessment record.",
        "",
    ])


def _text_digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _redact_log_text(
    raw: str,
    root: Path,
    stage: Path,
) -> str:
    secret = os.environ.get("SBP_LEX_SIGNING_SECRET", "")
    if secret and secret in raw:
        raise HandoverRegenerationError(
            "private_signing_material_in_verification_log",
        )
    if "-----BEGIN PRIVATE KEY-----" in raw:
        raise HandoverRegenerationError(
            "private_key_material_in_verification_log",
        )
    replacements: dict[str, str] = {}
    for path, label in (
        (root, "<CANONICAL_REPOSITORY>"),
        (stage, "<PRIVATE_STAGING_ROOT>"),
    ):
        rendered = str(path)
        replacements[rendered] = label
        replacements[rendered.replace("\\", "/")] = label
        replacements[rendered.replace("/", "\\")] = label
    result = raw
    for value, replacement in sorted(
        replacements.items(),
        key=lambda item: len(item[0]),
        reverse=True,
    ):
        if value:
            result = result.replace(value, replacement)
    return result


def _copy_redacted_logs(
    source: Path,
    destination: Path,
    *,
    root: Path,
    stage: Path,
) -> None:
    if source.is_symlink() or not source.is_dir():
        raise HandoverRegenerationError(
            "verification_logs_missing",
        )
    destination.mkdir(parents=True)
    records: list[dict[str, Any]] = []
    paths = sorted(source.glob("*.log"), key=lambda item: item.name)
    if len(paths) != 3:
        raise HandoverRegenerationError(
            "verification_log_count_invalid",
        )
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise HandoverRegenerationError(
                "verification_log_invalid",
            )
        raw = path.read_bytes()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HandoverRegenerationError(
                "verification_log_encoding_invalid",
            ) from exc
        redacted = _redact_log_text(text, root, stage)
        header = "\n".join([
            CONTROLLED_REVIEW_LABEL,
            "Path redaction only; technical result text is unchanged.",
            f"Private raw-log SHA-256: {_text_digest(raw)}",
            "",
        ])
        output = destination / path.name
        output.write_text(
            header + redacted,
            encoding="utf-8",
            newline="\n",
        )
        records.append({
            "path": path.name,
            "private_raw_sha256": _text_digest(raw),
            "released_sha256": _sha256(output),
            "redaction_scope": "repository_and_staging_paths_only",
        })
    _atomic_json(
        destination / "VERIFICATION_LOG_INDEX.json",
        {
            "classification": CONTROLLED_REVIEW_LABEL,
            "records": records,
        },
    )


def _tree_records(boundary: Path) -> list[dict[str, Any]]:
    if boundary.is_symlink() or not boundary.is_dir():
        raise HandoverRegenerationError(
            f"external_boundary_invalid:{boundary.name}",
        )
    records: list[dict[str, Any]] = []
    for path in sorted(
        boundary.rglob("*"),
        key=lambda item: item.relative_to(boundary).as_posix(),
    ):
        if path.is_symlink():
            raise HandoverRegenerationError(
                "external_symlink_rejected",
            )
        if path.is_file():
            records.append({
                "path": path.relative_to(boundary).as_posix(),
                "sha256": _sha256(path),
                "size_bytes": path.stat().st_size,
            })
    return records


def _assert_external_package_boundary(
    outer: Path,
    *,
    root: Path,
    stage: Path,
) -> None:
    expected_files = {
        "CONTROLLED_REVIEW_NOTICE.md",
        "EVALUATION_README.md",
        "OWNER_ASSURANCE_RECORD.json",
        EXTERNAL_PROPOSAL_NAME,
        "SHA256SUMS.txt",
    }
    expected_directories = {
        EXTERNAL_EVIDENCE_DIRECTORY,
        "VERIFICATION_LOGS",
    }
    actual_files = {
        path.name for path in outer.iterdir() if path.is_file()
    }
    actual_directories = {
        path.name for path in outer.iterdir() if path.is_dir()
    }
    if (
        actual_files != expected_files
        or actual_directories != expected_directories
    ):
        raise HandoverRegenerationError(
            "external_package_topology_invalid",
        )
    secret = os.environ.get("SBP_LEX_SIGNING_SECRET", "")
    path_markers = {
        str(root),
        str(root).replace("\\", "/"),
        str(root).replace("/", "\\"),
        str(stage),
        str(stage).replace("\\", "/"),
        str(stage).replace("/", "\\"),
    }
    text_suffixes = {
        ".csv",
        ".json",
        ".log",
        ".md",
        ".txt",
        ".xml",
    }
    for path in sorted(
        outer.rglob("*"),
        key=lambda item: item.relative_to(outer).as_posix(),
    ):
        relative = path.relative_to(outer)
        if path.is_symlink():
            raise HandoverRegenerationError(
                "external_symlink_rejected",
            )
        if any(
            part.casefold() in {
                ".git",
                "source_snapshot",
            }
            for part in relative.parts
        ):
            raise HandoverRegenerationError(
                f"external_repository_material_rejected:{relative}",
            )
        if path.is_file() and path.suffix.casefold() in (
            FORBIDDEN_EXTERNAL_SUFFIXES
        ):
            raise HandoverRegenerationError(
                f"external_source_material_rejected:{relative}",
            )
        if not path.is_file():
            continue
        raw = path.read_bytes()
        if secret and secret.encode("utf-8") in raw:
            raise HandoverRegenerationError(
                "external_private_signing_material_rejected",
            )
        if b"-----BEGIN PRIVATE KEY-----" in raw:
            raise HandoverRegenerationError(
                "external_private_key_material_rejected",
            )
        if path.suffix.casefold() in text_suffixes:
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise HandoverRegenerationError(
                    f"external_text_encoding_invalid:{relative}",
                ) from exc
            if any(marker and marker in text for marker in path_markers):
                raise HandoverRegenerationError(
                    f"external_private_path_rejected:{relative}",
                )
    proposal = outer / EXTERNAL_PROPOSAL_NAME
    if not proposal.read_bytes().startswith(b"%PDF-"):
        raise HandoverRegenerationError(
            "external_proposal_pdf_invalid",
        )
    notice = (
        outer / "CONTROLLED_REVIEW_NOTICE.md"
    ).read_text(encoding="utf-8")
    if CONTROLLED_REVIEW_LABEL not in notice:
        raise HandoverRegenerationError(
            "external_controlled_notice_invalid",
        )
    record = _read_json(outer / "OWNER_ASSURANCE_RECORD.json")
    if record.get("status") != "OWNER_SIDE_HANDOVER_ASSURANCE_PASSED":
        raise HandoverRegenerationError(
            "external_assurance_record_invalid",
        )


def _write_outer_hashes(outer: Path) -> None:
    records = []
    for path in sorted(
        outer.rglob("*"),
        key=lambda item: item.relative_to(outer).as_posix(),
    ):
        if path.is_file() and path.name != "SHA256SUMS.txt":
            records.append(
                f"{_sha256(path)}  "
                f"{path.relative_to(outer).as_posix()}"
            )
    (outer / "SHA256SUMS.txt").write_text(
        "\n".join(records) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _zip_tree(source: Path, destination: Path) -> None:
    with zipfile.ZipFile(
        destination,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for path in sorted(
            source.rglob("*"),
            key=lambda item: item.relative_to(source.parent).as_posix(),
        ):
            if not path.is_file():
                continue
            relative = path.relative_to(source.parent).as_posix()
            info = zipfile.ZipInfo(relative)
            info.date_time = (2026, 1, 1, 0, 0, 0)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())


def _safe_extract(archive_path: Path, destination: Path) -> Path:
    with zipfile.ZipFile(archive_path) as archive:
        if archive.testzip() is not None:
            raise HandoverRegenerationError("archive_crc_invalid")
        roots: set[str] = set()
        seen: set[str] = set()
        for info in archive.infolist():
            candidate = PurePosixPath(info.filename)
            mode = (info.external_attr >> 16) & 0o170000
            if (
                candidate.is_absolute()
                or any(part in {"", ".", ".."} for part in candidate.parts)
                or "\\" in info.filename
                or info.filename in seen
                or mode == 0o120000
            ):
                raise HandoverRegenerationError(
                    "archive_path_invalid",
                )
            seen.add(info.filename)
            roots.add(candidate.parts[0])
            target = destination.joinpath(*candidate.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(info))
    if len(roots) != 1:
        raise HandoverRegenerationError(
            "archive_root_invalid",
        )
    return destination / next(iter(roots))


def _verify_outer_hashes(outer: Path) -> None:
    checksum_path = outer / "SHA256SUMS.txt"
    lines = checksum_path.read_text("utf-8").splitlines()
    if not lines:
        raise HandoverRegenerationError(
            "archive_checksums_missing",
        )
    for line in lines:
        digest, separator, relative = line.partition("  ")
        candidate = PurePosixPath(relative)
        if (
            separator != "  "
            or len(digest) != 64
            or candidate.is_absolute()
            or any(part in {"", ".", ".."} for part in candidate.parts)
        ):
            raise HandoverRegenerationError(
                "archive_checksum_record_invalid",
            )
        path = outer.joinpath(*candidate.parts)
        if not path.is_file() or _sha256(path) != digest:
            raise HandoverRegenerationError(
                f"archive_checksum_mismatch:{relative}",
            )


def _archive_verification_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.pop("SBP_LEX_SIGNING_SECRET", None)
    environment.pop("SBP_LEX_LOCAL_TRUST_EVIDENCE_ROOT", None)
    environment.pop("SBP_LEX_APPROVED_RUNTIME_BASELINE_PATH", None)
    environment.pop("SBP_LEX_MEASURED_STARTUP_STATE_ROOT", None)
    return environment


def _scan_external_legacy(outer: Path) -> None:
    findings: list[str] = []
    for path in sorted(
        outer.rglob("*"),
        key=lambda item: item.relative_to(outer).as_posix(),
    ):
        if not path.is_file():
            continue
        raw = path.read_bytes()
        for marker in LEGACY_ASSURANCE_MARKERS:
            if marker in raw:
                findings.append(
                    f"{path.relative_to(outer).as_posix()}:"
                    f"{marker.decode('ascii')}",
                )
    if findings:
        raise HandoverRegenerationError(
            "external_legacy_assurance_evidence:"
            + ",".join(findings),
        )


def _validated_proposal_path(
    proposal_path: Path,
    expected_sha256: str,
    *,
    root: Path,
) -> tuple[Path, str]:
    if not proposal_path.is_absolute():
        raise HandoverRegenerationError(
            "proposal_path_must_be_absolute",
        )
    _reject_link_components(proposal_path)
    proposal = proposal_path.resolve(strict=False)
    if (
        proposal.is_symlink()
        or not proposal.is_file()
        or proposal.is_relative_to(root.resolve())
    ):
        raise HandoverRegenerationError(
            "proposal_path_invalid",
        )
    size = proposal.stat().st_size
    if (
        size < 1024
        or size > 25 * 1024 * 1024
        or not proposal.read_bytes().startswith(b"%PDF-")
    ):
        raise HandoverRegenerationError(
            "proposal_pdf_invalid",
        )
    digest = _sha256(proposal)
    if (
        len(expected_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in expected_sha256
        )
        or digest != expected_sha256
    ):
        raise HandoverRegenerationError(
            "proposal_sha256_mismatch",
        )
    return proposal, digest


def _verify_archive_once(
    archive_path: Path,
    verification_root: Path,
    expected_fingerprint: str,
    *,
    root: Path,
    stage: Path,
) -> None:
    outer = _safe_extract(archive_path, verification_root)
    _verify_outer_hashes(outer)
    _assert_external_package_boundary(
        outer,
        root=root,
        stage=stage,
    )
    released_evidence = outer / EXTERNAL_EVIDENCE_DIRECTORY
    if _tree_records(released_evidence) != _tree_records(
        root / "validation_package",
    ):
        raise HandoverRegenerationError(
            "external_evidence_copy_mismatch",
        )
    environment = _archive_verification_environment()
    _run_expected(
        root,
        "detached_archive_verifier",
        (
            sys.executable,
            "-m",
            "sbp_lex.ivvp.verifier",
            str(released_evidence),
            "--expected-signer-fingerprint",
            expected_fingerprint,
        ),
        "R4_IVVP_VALID",
        environment=environment,
        timeout=1200,
    )
    _scan_external_legacy(outer)


def create_final_archive(
    stage_root: Path,
    output_path: Path,
    proposal_path: Path,
    expected_proposal_sha256: str,
    expected_fingerprint: str,
    *,
    root: Path = REPOSITORY_ROOT,
) -> dict[str, Any]:
    verification = verify_recorded_handover(
        stage_root,
        expected_fingerprint,
        root=root,
    )
    stage = _safe_stage_root(root, stage_root, require_empty=False)
    proposal, proposal_digest = _validated_proposal_path(
        proposal_path,
        expected_proposal_sha256,
        root=root,
    )
    release_verification = {
        **verification,
        "proposal_sha256": proposal_digest,
    }
    if not output_path.is_absolute():
        raise HandoverRegenerationError(
            "archive_output_must_be_absolute",
        )
    output = output_path.resolve(strict=False)
    if output.is_relative_to(root.resolve()):
        raise HandoverRegenerationError(
            "archive_output_inside_repository",
        )
    if output.exists() or output.with_suffix(
        output.suffix + ".sha256",
    ).exists():
        raise HandoverRegenerationError(
            "archive_output_already_exists",
        )
    output.parent.mkdir(parents=True, exist_ok=True)

    build_root = Path(
        tempfile.mkdtemp(
            prefix="sbp-lex-university-handover-",
            dir=stage,
        )
    )
    try:
        name = (
            f"{FINAL_ARCHIVE_PREFIX}_"
            f"{str(verification['evidence_commit'])[:12]}"
        )
        outer = build_root / name
        outer.mkdir(parents=True)
        shutil.copytree(
            root / "validation_package",
            outer / EXTERNAL_EVIDENCE_DIRECTORY,
        )
        shutil.copy2(proposal, outer / EXTERNAL_PROPOSAL_NAME)
        (outer / "EVALUATION_README.md").write_text(
            _external_readme(release_verification),
            encoding="utf-8",
            newline="\n",
        )
        (outer / "CONTROLLED_REVIEW_NOTICE.md").write_text(
            _controlled_review_notice(),
            encoding="utf-8",
            newline="\n",
        )
        _atomic_json(
            outer / "OWNER_ASSURANCE_RECORD.json",
            {
                **release_verification,
                "classification": CONTROLLED_REVIEW_LABEL,
                "external_validation_status": "PENDING",
                "repository_material_included": False,
                "release_requires_explicit_owner_approval": True,
            },
        )
        logs = stage / "verification_logs"
        _copy_redacted_logs(
            logs,
            outer / "VERIFICATION_LOGS",
            root=root,
            stage=stage,
        )
        _write_outer_hashes(outer)
        _assert_external_package_boundary(
            outer,
            root=root,
            stage=stage,
        )
        _zip_tree(outer, output)
    finally:
        shutil.rmtree(build_root, ignore_errors=True)

    verification_parent = Path(
        tempfile.mkdtemp(
            prefix="sbp-lex-archive-triple-check-",
            dir=stage,
        )
    )
    try:
        for run_number in range(1, 4):
            run_root = verification_parent / f"run_{run_number}"
            run_root.mkdir()
            _verify_archive_once(
                output,
                run_root,
                expected_fingerprint,
                root=root,
                stage=stage,
            )
    finally:
        shutil.rmtree(verification_parent, ignore_errors=True)

    archive_digest = _sha256(output)
    checksum_path = output.with_suffix(output.suffix + ".sha256")
    checksum_path.write_text(
        f"{archive_digest}  {output.name}\n",
        encoding="utf-8",
        newline="\n",
    )
    return {
        **release_verification,
        "status":
            "GRIFFITH_EVALUATION_PACKAGE_ASSEMBLED_AND_TRIPLE_VERIFIED",
        "owner_assurance_status":
            "OWNER_SIDE_HANDOVER_ASSURANCE_PASSED",
        "external_validation_status": "PENDING",
        "repository_material_included": False,
        "archive_path": str(output),
        "archive_sha256": archive_digest,
        "archive_verification_runs": 3,
    }


def _print_json(value: Mapping[str, Any]) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Regenerate, record, triple-verify, and archive the bounded "
            "SBP-LEX Griffith University evaluation evidence without "
            "transferring repository material."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("baseline-preview")
    approve = subparsers.add_parser("baseline-approve")
    approve.add_argument("--identifier", required=True)
    approve.add_argument("--approval-reference", required=True)
    approve.add_argument("--confirmation", required=True)

    generate = subparsers.add_parser("generate")
    generate.add_argument("--stage-root", type=Path, required=True)
    generate.add_argument("--expected-fingerprint", required=True)

    record = subparsers.add_parser("record")
    record.add_argument("--stage-root", type=Path, required=True)
    record.add_argument(
        "--commit-message",
        default=(
            "chore(evidence): regenerate university handover package"
        ),
    )

    verify = subparsers.add_parser("verify")
    verify.add_argument("--stage-root", type=Path, required=True)
    verify.add_argument("--expected-fingerprint", required=True)

    archive = subparsers.add_parser("archive")
    archive.add_argument("--stage-root", type=Path, required=True)
    archive.add_argument("--output", type=Path, required=True)
    archive.add_argument("--proposal", type=Path, required=True)
    archive.add_argument(
        "--expected-proposal-sha256",
        required=True,
    )
    archive.add_argument("--expected-fingerprint", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "baseline-preview":
            result = baseline_preview()
        elif args.command == "baseline-approve":
            result = approve_successor_baseline(
                args.identifier,
                args.approval_reference,
                args.confirmation,
            )
        elif args.command == "generate":
            result = generate_handover_stage(
                args.stage_root,
                args.expected_fingerprint,
            )
        elif args.command == "record":
            result = record_handover_evidence(
                args.stage_root,
                commit_message=args.commit_message,
            )
        elif args.command == "verify":
            result = verify_recorded_handover(
                args.stage_root,
                args.expected_fingerprint,
            )
        else:
            result = create_final_archive(
                args.stage_root,
                args.output,
                args.proposal,
                args.expected_proposal_sha256,
                args.expected_fingerprint,
            )
    except Exception as exc:
        print(
            "[FAIL] UNIVERSITY_HANDOVER_REGENERATION_FAILED:"
            f"{exc}",
        )
        return 1
    _print_json(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
