from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from sbp_lex.local_trust.adversarial_negative_harness import DEFAULT_ADVERSARIAL_OUTPUT_PATH
from sbp_lex.local_trust.claims_to_evidence import (
    CANONICAL_BLUEPRINT_SERIES_ARTIFACTS,
    PHASE_18_8B_HARDENING_ARTIFACTS,
    required_claim_ids,
)
from sbp_lex.local_trust.manifest import canonical_json, repository_root_from
from sbp_lex.local_trust.paths import resolve_local_trust_path
from sbp_lex.local_trust.release_hash_index import file_sha256
from sbp_lex.local_trust.release_integrity import DEFAULT_RELEASE_BUNDLE_DIR, load_json
from sbp_lex.local_trust.release_manifest import collect_release_git_status
from sbp_lex.local_trust.signing import (
    LOCAL_TRUST_SIGNATURE_MODE,
    local_trust_binding_digest,
    sign_local_trust_digest,
)

DOSSIER_SIGNATURE_MODE = LOCAL_TRUST_SIGNATURE_MODE
DOSSIER_SIGNATURE_DOMAIN = "SBP_LEX_UNIVERSITY_VALIDATION_DOSSIER"
DOSSIER_MANIFEST_VERSION = "18.8"
DEFAULT_DOSSIER_DIR = Path("outputs/university_validation_dossier")
DOSSIER_MANIFEST_FILE = DEFAULT_DOSSIER_DIR / "DOSSIER_MANIFEST.json"
MASTER_CLAIMS_FILE = DEFAULT_DOSSIER_DIR / "MASTER_CLAIMS_TO_EVIDENCE_INDEX.json"
VALIDATION_QUESTIONS_FILE = DEFAULT_DOSSIER_DIR / "VALIDATION_QUESTIONS.json"
EVIDENCE_ARTIFACT_INDEX_FILE = DEFAULT_DOSSIER_DIR / "EVIDENCE_ARTIFACT_INDEX.json"
SCOPE_AND_EXCLUSIONS_FILE = DEFAULT_DOSSIER_DIR / "SCOPE_AND_EXCLUSIONS_LOCK.json"
REVIEWER_COMMANDS_FILE = DEFAULT_DOSSIER_DIR / "REVIEWER_VERIFICATION_COMMANDS.json"
UNIVERSITY_HANDOFF_README_FILE = DEFAULT_DOSSIER_DIR / "UNIVERSITY_HANDOFF_README.md"

_DIGEST_EXCLUDED_FIELDS = {
    "dossier_status",
    "validation_failures",
    "dossier_payload_digest",
    "dossier_digest",
    "dossier_signature",
}


def build_dossier_manifest(
    repository_root: Path | str | None = None,
    *,
    claims_index: Mapping[str, Any],
    validation_questions: Mapping[str, Any],
    evidence_artifact_index: Mapping[str, Any],
    scope_lock: Mapping[str, Any],
    reviewer_commands: Mapping[str, Any],
    output_dir: Path | str = DEFAULT_DOSSIER_DIR,
    output_reference_dir: Path | str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    from sbp_lex.local_trust.dossier_validator import validate_dossier_manifest

    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    dossier_dir = _resolve(root, output_dir)
    reference_dir = (
        Path(output_reference_dir)
        if output_reference_dir is not None
        else Path(output_dir)
    )
    git = collect_release_git_status(root)
    bindings = collect_bound_digests(root)
    manifest: dict[str, Any] = {
        "dossier_manifest_type": "university_validation_dossier_manifest",
        "dossier_manifest_version": DOSSIER_MANIFEST_VERSION,
        "created_at": created_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "repository_root": str(root),
        "git_commit": git.get("git_commit"),
        "git_branch": git.get("git_branch"),
        "github_remote": _origin_remote(root),
        "github_sync_status": git,
        "source_phase": "18.8",
        "dossier_scope": dossier_scope(),
        "bound_manifest_digest": bindings["manifest"],
        "bound_execution_envelope_digest": bindings["execution_envelope"],
        "bound_evidence_chain_digest": bindings["evidence_chain"],
        "bound_regression_matrix_digest": bindings["regression_matrix"],
        "bound_constitutional_gates_digest": bindings["constitutional_gates"],
        "bound_toolchain_guard_digest": bindings["toolchain_guard"],
        "bound_capstone_digest": bindings["capstone"],
        "bound_release_integrity_digest": bindings["release_integrity"],
        "bound_adversarial_harness_digest": bindings["adversarial_harness"],
        "claims_to_evidence_reference": file_reference(
            root,
            dossier_dir / MASTER_CLAIMS_FILE.name,
            reference_dir / MASTER_CLAIMS_FILE.name,
        ),
        "validation_questions_reference": file_reference(
            root,
            dossier_dir / VALIDATION_QUESTIONS_FILE.name,
            reference_dir / VALIDATION_QUESTIONS_FILE.name,
        ),
        "evidence_artifact_index_reference": file_reference(
            root,
            dossier_dir / EVIDENCE_ARTIFACT_INDEX_FILE.name,
            reference_dir / EVIDENCE_ARTIFACT_INDEX_FILE.name,
        ),
        "scope_and_exclusions_reference": file_reference(
            root,
            dossier_dir / SCOPE_AND_EXCLUSIONS_FILE.name,
            reference_dir / SCOPE_AND_EXCLUSIONS_FILE.name,
        ),
        "reviewer_commands_reference": file_reference(
            root,
            dossier_dir / REVIEWER_COMMANDS_FILE.name,
            reference_dir / REVIEWER_COMMANDS_FILE.name,
        ),
        "handoff_readme_reference": file_reference(
            root,
            dossier_dir / UNIVERSITY_HANDOFF_README_FILE.name,
            reference_dir / UNIVERSITY_HANDOFF_README_FILE.name,
        ),
        "dossier_summary": {
            "claim_count": len(claims_index.get("claims", [])),
            "validation_question_count": len(validation_questions.get("questions", [])),
            "evidence_artifact_count": evidence_artifact_index.get("artifact_summary", {}).get("evidence_artifact_count"),
            "reviewer_command_count": len(reviewer_commands.get("commands", [])),
            "phase_19_not_started": scope_lock.get("phase_19_not_started"),
            "next_phase": scope_lock.get("next_phase", {}).get("phase_id")
            if isinstance(scope_lock.get("next_phase"), Mapping)
            else None,
        },
        "signature_mode": DOSSIER_SIGNATURE_MODE,
        "dossier_status": "VALIDATION_DOSSIER_INCOMPLETE",
        "validation_failures": [],
    }
    payload = hash_dossier_payload(manifest)
    signature = dossier_signature_for(payload)
    manifest["dossier_payload_digest"] = payload
    manifest["dossier_signature"] = signature
    manifest["dossier_digest"] = dossier_digest_for(payload, signature)
    validation = validate_dossier_manifest(
        manifest,
        repository_root=root,
        claims_index=claims_index,
        validation_questions=validation_questions,
        evidence_artifact_index=evidence_artifact_index,
        scope_lock=scope_lock,
        reviewer_commands=reviewer_commands,
    )
    manifest["dossier_status"] = validation["dossier_status"]
    manifest["validation_failures"] = validation["validation_failures"]
    return manifest


def build_evidence_artifact_index(
    repository_root: Path | str | None = None,
    *,
    specs: Sequence[Mapping[str, Any]] = (),
    output_dir: Path | str = DEFAULT_DOSSIER_DIR,
    reference_dir: Path | str | None = None,
) -> dict[str, Any]:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    dossier_dir = _resolve(root, output_dir)
    logical_dir = (
        Path(reference_dir)
        if reference_dir is not None
        else Path(output_dir)
    )
    artifact_specs = specs or EVIDENCE_ARTIFACT_SPECS
    artifacts = [
        artifact_record(
            root,
            _normalise_dossier_spec(
                spec,
                physical_dir=dossier_dir,
                logical_dir=logical_dir,
            ),
        )
        for spec in artifact_specs
    ]
    required = [artifact for artifact in artifacts if artifact["required"] is True]
    missing = [artifact for artifact in required if artifact["exists"] is not True]
    return {
        "evidence_artifact_index_type": "university_validation_evidence_artifact_index",
        "evidence_artifact_index_version": "18.8",
        "excluded_path_markers": [
            ".git",
            "__pycache__",
            ".pytest_cache",
            ".pytest_tmp_",
            "outputs/local_trust_temp",
            "outputs/local_trust_adversarial_temp",
        ],
        "artifacts": artifacts,
        "artifact_summary": {
            "evidence_artifact_count": len(artifacts),
            "required_artifact_count": len(required),
            "missing_artifact_count": len(missing),
        },
    }


def artifact_record(repository_root: Path, spec: Mapping[str, Any]) -> dict[str, Any]:
    relative_path = str(spec["path"]).replace("\\", "/")
    physical = spec.get("_physical_path")
    path = (
        Path(str(physical)).resolve(strict=False)
        if physical is not None
        else resolve_local_trust_path(repository_root, relative_path)
    )
    exists = path.exists() and path.is_file()
    return {
        "artifact_id": spec["artifact_id"],
        "artifact_group": spec["artifact_group"],
        "path": relative_path,
        "exists": exists,
        "size_bytes": path.stat().st_size if exists else 0,
        "sha256": file_sha256(path) if exists else "MISSING",
        "required": bool(spec["required"]),
        "related_claim_ids": list(spec["related_claim_ids"]),
        "reason": spec["reason"],
    }


def collect_bound_digests(repository_root: Path) -> dict[str, str]:
    return {
        "manifest": str(load_json(_resolve(repository_root, "outputs/local_trust_root_manifest.json")).get("manifest_digest")),
        "execution_envelope": str(
            load_json(_resolve(repository_root, "outputs/local_execution_environment_trust_envelope.json")).get("envelope_digest")
        ),
        "evidence_chain": str(load_json(_resolve(repository_root, "outputs/local_evidence_chain.json")).get("chain_digest")),
        "regression_matrix": str(
            load_json(_resolve(repository_root, "outputs/local_trust_regression_matrix.json")).get("matrix_digest")
        ),
        "constitutional_gates": str(load_json(_resolve(repository_root, "outputs/local_constitutional_gates.json")).get("gate_digest")),
        "toolchain_guard": str(load_json(_resolve(repository_root, "outputs/local_toolchain_guard.json")).get("toolchain_digest")),
        "capstone": str(load_json(_resolve(repository_root, "outputs/local_trust_25_year_capstone.json")).get("capstone_digest")),
        "release_integrity": str(
            load_json(_resolve(repository_root, DEFAULT_RELEASE_BUNDLE_DIR) / "RELEASE_MANIFEST.json").get("release_digest")
        ),
        "adversarial_harness": str(load_json(_resolve(repository_root, DEFAULT_ADVERSARIAL_OUTPUT_PATH)).get("adversarial_digest")),
    }


def dossier_scope() -> dict[str, Any]:
    return {
        "phase_id": "18.8",
        "phase_name": "Master Claims-to-Evidence Index / University Validation Dossier",
        "purpose": "Reviewer-facing bounded claims-to-evidence handoff package.",
        "bounded_validation_questions_only": True,
        "review_readiness_only": True,
        "not_external_validation_result": True,
        "not_certification": True,
        "not_runtime_authority": True,
        "phase_19_not_started": True,
        "next_phase": "18.9",
        "next_phase_implemented": False,
    }


def file_reference(
    repository_root: Path,
    path: Path,
    reference_path: Path | None = None,
) -> dict[str, Any]:
    resolved = path if path.is_absolute() else repository_root / path
    logical = reference_path or path
    exists = resolved.exists() and resolved.is_file()
    return {
        "path": logical.as_posix(),
        "exists": exists,
        "size_bytes": resolved.stat().st_size if exists else 0,
        "sha256": file_sha256(resolved) if exists else "MISSING",
    }


def payload_for_digest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value) for key, value in manifest.items() if key not in _DIGEST_EXCLUDED_FIELDS}


def hash_dossier_payload(manifest: Mapping[str, Any]) -> str:
    return sha256(canonical_json(payload_for_digest(manifest)).encode("utf-8")).hexdigest()


def dossier_signature_for(payload_digest: str) -> dict[str, Any]:
    return sign_local_trust_digest(DOSSIER_SIGNATURE_DOMAIN, payload_digest)


def dossier_digest_for(payload_digest: str, signature: Mapping[str, Any]) -> str:
    return local_trust_binding_digest(
        DOSSIER_SIGNATURE_DOMAIN, payload_digest, signature,
    )


def _normalise_dossier_spec(
    spec: Mapping[str, Any],
    *,
    physical_dir: Path,
    logical_dir: Path,
) -> dict[str, Any]:
    if spec.get("artifact_group") != "dossier_outputs":
        return dict(spec)
    filename = Path(str(spec["path"])).name
    return {
        **spec,
        "path": (logical_dir / filename).as_posix(),
        "_physical_path": (physical_dir / filename).as_posix(),
    }


def _resolve(repository_root: Path, path: Path | str) -> Path:
    return resolve_local_trust_path(repository_root, path)


def _origin_remote(repository_root: Path) -> str:
    config = repository_root / ".git" / "config"
    if not config.exists():
        return "UNKNOWN_FROM_CURRENT_CONTEXT"
    in_origin = False
    for line in config.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if stripped.startswith("[remote "):
            in_origin = stripped == '[remote "origin"]'
            continue
        if in_origin and stripped.startswith("url ="):
            return stripped.split("=", 1)[1].strip()
    return "UNKNOWN_FROM_CURRENT_CONTEXT"


def _claims(*claim_ids: str) -> list[str]:
    return list(claim_ids)


EVIDENCE_ARTIFACT_SPECS: tuple[dict[str, Any], ...] = (
    {
        "artifact_id": "local_trust_root_manifest",
        "artifact_group": "local_trust_artifacts",
        "path": "outputs/local_trust_root_manifest.json",
        "required": True,
        "related_claim_ids": _claims("local_trust_manifest_validates"),
        "reason": "Local trust manifest evidence.",
    },
    {
        "artifact_id": "execution_environment_trust_envelope",
        "artifact_group": "local_trust_artifacts",
        "path": "outputs/local_execution_environment_trust_envelope.json",
        "required": True,
        "related_claim_ids": _claims(
            "execution_envelope_validates",
            "runtime_verification_passes_current_scenario",
            "replay_verification_passes_matched",
        ),
        "reason": "Execution environment and runtime/replay evidence.",
    },
    {
        "artifact_id": "local_evidence_chain",
        "artifact_group": "local_trust_artifacts",
        "path": "outputs/local_evidence_chain.json",
        "required": True,
        "related_claim_ids": _claims("evidence_chain_validates", "evidence_chain_zero_missing", "evidence_chain_zero_changed"),
        "reason": "Evidence chain integrity evidence.",
    },
    {
        "artifact_id": "local_trust_regression_matrix",
        "artifact_group": "local_trust_artifacts",
        "path": "outputs/local_trust_regression_matrix.json",
        "required": True,
        "related_claim_ids": _claims("regression_matrix_validates", "regression_matrix_detects_drift"),
        "reason": "Local trust regression evidence.",
    },
    {
        "artifact_id": "constitutional_gates",
        "artifact_group": "local_trust_artifacts",
        "path": "outputs/local_constitutional_gates.json",
        "required": True,
        "related_claim_ids": _claims("constitutional_gates_pass", "constitutional_gates_block_unclean_states"),
        "reason": "Constitutional gate evidence.",
    },
    {
        "artifact_id": "toolchain_guard",
        "artifact_group": "local_trust_artifacts",
        "path": "outputs/local_toolchain_guard.json",
        "required": True,
        "related_claim_ids": _claims("toolchain_guard_passes", "toolchain_guard_records_assumptions"),
        "reason": "Toolchain and dependency assumption evidence.",
    },
    {
        "artifact_id": "local_trust_capstone",
        "artifact_group": "local_trust_artifacts",
        "path": "outputs/local_trust_25_year_capstone.json",
        "required": True,
        "related_claim_ids": _claims("local_trust_capstone_passes"),
        "reason": "25-year local trust capstone evidence.",
    },
    {
        "artifact_id": "release_manifest",
        "artifact_group": "release_integrity_artifacts",
        "path": "outputs/release_integrity_bundle/RELEASE_MANIFEST.json",
        "required": True,
        "related_claim_ids": _claims("release_integrity_passes"),
        "reason": "Release integrity manifest.",
    },
    {
        "artifact_id": "release_artifact_hash_index",
        "artifact_group": "release_integrity_artifacts",
        "path": "outputs/release_integrity_bundle/ARTIFACT_HASH_INDEX.json",
        "required": True,
        "related_claim_ids": _claims("release_integrity_contains_required_files"),
        "reason": "Release artifact hash index.",
    },
    {
        "artifact_id": "release_verification_commands",
        "artifact_group": "release_integrity_artifacts",
        "path": "outputs/release_integrity_bundle/VERIFICATION_COMMANDS.json",
        "required": True,
        "related_claim_ids": _claims("release_integrity_contains_required_files"),
        "reason": "Release verification command index.",
    },
    {
        "artifact_id": "release_claims_seed",
        "artifact_group": "release_integrity_artifacts",
        "path": "outputs/release_integrity_bundle/CLAIMS_TO_EVIDENCE_SEED.json",
        "required": True,
        "related_claim_ids": _claims("release_integrity_contains_required_files"),
        "reason": "Release claims-to-evidence seed.",
    },
    {
        "artifact_id": "release_boundary_lock",
        "artifact_group": "release_integrity_artifacts",
        "path": "outputs/release_integrity_bundle/BOUNDARY_AND_SCOPE_LOCK.json",
        "required": True,
        "related_claim_ids": _claims("release_integrity_contains_required_files"),
        "reason": "Release boundary lock.",
    },
    {
        "artifact_id": "release_readme",
        "artifact_group": "release_integrity_artifacts",
        "path": "outputs/release_integrity_bundle/RELEASE_README.md",
        "required": True,
        "related_claim_ids": _claims("release_integrity_contains_required_files"),
        "reason": "Release integrity README.",
    },
    {
        "artifact_id": "adversarial_local_trust_negative_harness",
        "artifact_group": "adversarial_artifacts",
        "path": "outputs/adversarial_local_trust_negative_harness.json",
        "required": True,
        "related_claim_ids": _claims("adversarial_harness_passes", "adversarial_harness_detects_bad_states"),
        "reason": "Adversarial local trust negative-test evidence.",
    },
    {
        "artifact_id": "eie_pt_blueprint_impact_report",
        "artifact_group": "eie_pt_rebuild_artifacts",
        "path": "docs/blueprint_addenda/BLUEPRINT_IMPACT_REPORT_EIE_PT_SKG_DTN_REBUILD.md",
        "required": True,
        "related_claim_ids": _claims("eie_canonical_traversal_state", "procedural_truth_evidentiary_sufficiency_certifies", "skg_dtn_external_non_authoritative"),
        "reason": "Blueprint impact report for EIE/PT/SKG/DTN rebuild.",
    },
    {
        "artifact_id": "eie_adapter_ingress_addendum",
        "artifact_group": "eie_pt_rebuild_artifacts",
        "path": "docs/blueprint_addenda/EIE_ADAPTER_INGRESS_BLUEPRINT_ADDENDUM.md",
        "required": True,
        "related_claim_ids": _claims("eie_canonical_traversal_state"),
        "reason": "EIE ingress and state formalisation addendum.",
    },
    {
        "artifact_id": "skg_rebuild_addendum",
        "artifact_group": "eie_pt_rebuild_artifacts",
        "path": "docs/blueprint_addenda/SKG_REBUILD_BLUEPRINT_ADDENDUM.md",
        "required": True,
        "related_claim_ids": _claims("skg_dtn_external_non_authoritative", "procedural_truth_evidentiary_sufficiency_certifies"),
        "reason": "SKG PT-aware enrichment addendum.",
    },
    {
        "artifact_id": "dtn_rebuild_addendum",
        "artifact_group": "eie_pt_rebuild_artifacts",
        "path": "docs/blueprint_addenda/DTN_REBUILD_BLUEPRINT_ADDENDUM.md",
        "required": True,
        "related_claim_ids": _claims("skg_dtn_external_non_authoritative", "procedural_truth_evidentiary_sufficiency_certifies"),
        "reason": "DTN PT-aware enrichment addendum.",
    },
    {
        "artifact_id": "procedural_truth_rebuild_addendum",
        "artifact_group": "eie_pt_rebuild_artifacts",
        "path": "docs/blueprint_addenda/PROCEDURAL_TRUTH_REBUILD_BLUEPRINT_ADDENDUM.md",
        "required": True,
        "related_claim_ids": _claims("procedural_truth_evidentiary_sufficiency_certifies"),
        "reason": "Procedural Truth Evidentiary Sufficiency addendum.",
    },
    {
        "artifact_id": "root_of_trust_anchorage_addendum",
        "artifact_group": "eie_pt_rebuild_artifacts",
        "path": "docs/blueprint_addenda/ROOT_OF_TRUST_ANCHORAGE_BLUEPRINT_ADDENDUM.md",
        "required": True,
        "related_claim_ids": _claims("root_of_trust_anchorage_binds_eie_truth_foundations"),
        "reason": "Root of Trust Anchorage addendum.",
    },
    {
        "artifact_id": "traversal_integration_addendum",
        "artifact_group": "eie_pt_rebuild_artifacts",
        "path": "docs/blueprint_addenda/TRAVERSAL_INTEGRATION_BLUEPRINT_ADDENDUM.md",
        "required": True,
        "related_claim_ids": _claims("eie_canonical_traversal_state", "execution_gate_enforces_pt_certification"),
        "reason": "Traversal integration addendum.",
    },
    {
        "artifact_id": "execution_gate_enforcement_addendum",
        "artifact_group": "eie_pt_rebuild_artifacts",
        "path": "docs/blueprint_addenda/EXECUTION_GATE_ENFORCEMENT_ADDENDUM.md",
        "required": True,
        "related_claim_ids": _claims("execution_gate_enforces_pt_certification"),
        "reason": "Execution Gate PT certification enforcement addendum.",
    },
    {
        "artifact_id": "audit_replay_telemetry_addendum",
        "artifact_group": "eie_pt_rebuild_artifacts",
        "path": "docs/blueprint_addenda/AUDIT_REPLAY_TELEMETRY_METADATA_ADDENDUM.md",
        "required": True,
        "related_claim_ids": _claims("root_of_trust_anchorage_binds_eie_truth_foundations"),
        "reason": "Audit/replay metadata addendum.",
    },
    {
        "artifact_id": "eie_pt_handover_readiness_report",
        "artifact_group": "eie_pt_rebuild_artifacts",
        "path": "reports/EIE_PT_SKG_DTN_CONTROL_PLANE_HANDOVER_READINESS_REPORT.md",
        "required": True,
        "related_claim_ids": _claims(
            "eie_canonical_traversal_state",
            "procedural_truth_evidentiary_sufficiency_certifies",
            "root_of_trust_anchorage_binds_eie_truth_foundations",
            "execution_gate_enforces_pt_certification",
            "skg_dtn_external_non_authoritative",
        ),
        "reason": "Control-plane robustness, weak-point, fix-plan, test, and non-runtime code inventory report.",
    },
    {
        "artifact_id": "eie_pt_rebuild_tests",
        "artifact_group": "eie_pt_rebuild_artifacts",
        "path": "tests/test_eie_pt_sufficiency_rebuild.py",
        "required": True,
        "related_claim_ids": _claims(
            "eie_canonical_traversal_state",
            "procedural_truth_evidentiary_sufficiency_certifies",
            "root_of_trust_anchorage_binds_eie_truth_foundations",
            "execution_gate_enforces_pt_certification",
            "skg_dtn_external_non_authoritative",
        ),
        "reason": "Focused EIE/PT/SKG/DTN rebuild tests.",
    },
    *[
        {
            "artifact_id": f"phase_18_8b_{Path(path).stem.lower()}",
            "artifact_group": "phase_18_8b_hardening_artifacts",
            "path": path,
            "required": True,
            "related_claim_ids": _claims(
                "phase_18_8b_repository_hardening_controls",
                "external_production_readiness_gaps_reported",
            ),
            "reason": "Phase 18.8B repository-contained hardening evidence.",
        }
        for path in PHASE_18_8B_HARDENING_ARTIFACTS
    ],
    *[
        {
            "artifact_id": f"canonical_blueprint_{Path(path).stem.lower()}",
            "artifact_group": "canonical_blueprint_series",
            "path": path,
            "required": True,
            "related_claim_ids": _claims("canonical_blueprint_series_current"),
            "reason": "Canonical blueprint series implementation-alignment document.",
        }
        for path in CANONICAL_BLUEPRINT_SERIES_ARTIFACTS
    ],
    {
        "artifact_id": "dossier_claims_index",
        "artifact_group": "dossier_outputs",
        "path": "outputs/university_validation_dossier/MASTER_CLAIMS_TO_EVIDENCE_INDEX.json",
        "required": True,
        "related_claim_ids": sorted(required_claim_ids()),
        "reason": "Master claims-to-evidence mapping.",
    },
    {
        "artifact_id": "dossier_validation_questions",
        "artifact_group": "dossier_outputs",
        "path": "outputs/university_validation_dossier/VALIDATION_QUESTIONS.json",
        "required": True,
        "related_claim_ids": sorted(required_claim_ids()),
        "reason": "Reviewer validation questions.",
    },
    {
        "artifact_id": "dossier_scope_lock",
        "artifact_group": "dossier_outputs",
        "path": "outputs/university_validation_dossier/SCOPE_AND_EXCLUSIONS_LOCK.json",
        "required": True,
        "related_claim_ids": _claims(
            "skg_dtn_external_non_authoritative",
            "future_surfaces_absent",
            "phase_19_not_started",
            "runtime_authority_unchanged",
            "governance_truth_gates_unchanged",
        ),
        "reason": "Dossier scope and exclusions lock.",
    },
    {
        "artifact_id": "dossier_reviewer_commands",
        "artifact_group": "dossier_outputs",
        "path": "outputs/university_validation_dossier/REVIEWER_VERIFICATION_COMMANDS.json",
        "required": True,
        "related_claim_ids": sorted(required_claim_ids()),
        "reason": "Reviewer verification command index.",
    },
    {
        "artifact_id": "dossier_handoff_readme",
        "artifact_group": "dossier_outputs",
        "path": "outputs/university_validation_dossier/UNIVERSITY_HANDOFF_README.md",
        "required": True,
        "related_claim_ids": sorted(required_claim_ids()),
        "reason": "Reviewer handoff README.",
    },
)
