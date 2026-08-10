from __future__ import annotations

import argparse
import os
import re
import subprocess
from hashlib import sha256
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

from sbp_lex.custody.common import unseal as unseal_r3
from sbp_lex.formal.assurance import (
    ASSURANCE_DOMAIN,
    ARTIFACT_VERSION,
    FORMAL_EVIDENCE_VERSION,
    FORMAL_MODEL_VERSION,
)
from sbp_lex.local_trust.adversarial_validator import (
    ADVERSARIAL_NEGATIVE_HARNESS_PASS,
    validate_adversarial_harness,
)
from sbp_lex.local_trust.capstone_validator import (
    LOCAL_TRUST_CAPSTONE_PASS,
    validate_local_trust_capstone,
)
from sbp_lex.local_trust.dossier_validator import (
    VALIDATION_DOSSIER_READY,
    validate_dossier_manifest,
)
from sbp_lex.local_trust.evidence_chain_validator import (
    EVIDENCE_CHAIN_VALID,
    validate_local_evidence_chain,
)
from sbp_lex.local_trust.execution_envelope_validator import (
    EXECUTION_ENV_VALID,
    validate_execution_envelope,
)
from sbp_lex.local_trust.gate_validator import (
    CONSTITUTIONAL_GATES_PASS,
    validate_constitutional_gate_result,
)
from sbp_lex.local_trust.git_provenance import (
    generated_evidence_lineage_is_bounded,
)
from sbp_lex.local_trust.manifest_validator import (
    LOCAL_TRUST_VALID,
    validate_local_trust_manifest,
)
from sbp_lex.local_trust.regression_validator import (
    REGRESSION_MATRIX_VALID,
    validate_local_trust_regression_matrix,
)
from sbp_lex.local_trust.release_validator import (
    RELEASE_INTEGRITY_PASS,
    validate_release_manifest,
)
from sbp_lex.local_trust.toolchain_validator import (
    TOOLCHAIN_GUARD_PASS,
    validate_toolchain_guard,
)
from sbp_lex.recovery.inventory import validate_inventory
from sbp_lex.runtime.measured_startup import (
    _validate_anchor,
    approved_baseline,
    validate_baseline_store,
    verify_startup_attestation,
)
from sbp_lex.security.migration_profile import (
    CRYPTO_PROFILE_VERSION,
    VERIFICATION_POLICY_VERSION,
)
from sbp_lex.security.pqc import (
    EXPECTED_SIGNER_FINGERPRINT_ENVIRONMENT_NAME,
    generate_digest,
    trusted_signing_key_fingerprint,
    verify_signature,
)
from sbp_lex.supply_chain.common import (
    DESKTOP_SCOPE as R2_DESKTOP_SCOPE,
    R2_DOMAIN,
    R2_VERSION,
    unseal as unseal_r2,
)
from sbp_lex.supply_chain.assurance import MANIFEST_PAYLOAD_FIELDS
from sbp_lex.supply_chain.provenance import (
    ARTIFACT_RECORD_FIELDS,
    BUILD_PROVENANCE_FIELDS,
    CANONICAL_UPSTREAM,
    EXPECTED_REPOSITORY_IDENTITY,
    REPOSITORY_PROVENANCE_FIELDS,
    TRUSTED_REPOSITORY_ANCHOR_COMMIT,
    normalize_repository_identity,
    validate_dependency_provenance,
)

from .common import (
    DESKTOP_SCOPE,
    EVIDENCE_PATHS,
    REPOSITORY_IDENTITY,
    R4_VERSION,
    IVVPError,
    file_sha256,
    read_json,
    unseal,
)

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PACKAGE_MANIFEST_FIELDS = frozenset({
    "manifest_version",
    "desktop_scope",
    "repository_identity",
    "repository_commit",
    "git_tree_identity",
    "trusted_repository_anchor_commit",
    "trusted_repository_anchor_tree",
    "trusted_signing_key_fingerprint",
    "measured_baseline_identifier",
    "runtime_identity",
    "identity_digest",
    "claims_digest",
    "traceability_digest",
    "evidence_inventory_digest",
    "package_files",
    "package_status",
    "package_identity",
})
IDENTITY_FIELDS = frozenset({
    "identity_version",
    "repository_name",
    "canonical_designation",
    "repository_identity",
    "repository_commit",
    "git_tree_identity",
    "repository_digest",
    "trusted_repository_anchor_commit",
    "trusted_repository_anchor_tree",
    "trusted_signing_key_fingerprint",
    "measured_baseline_identifier",
    "measurement_digest",
    "runtime_identity",
    "desktop_scope",
    "identity_digest",
})
CLAIMS_REGISTER_FIELDS = frozenset({
    "register_version",
    "repository_commit",
    "measured_baseline_identifier",
    "runtime_identity",
    "claims",
    "claims_digest",
})
CLAIM_FIELDS = frozenset({
    "claim_identifier",
    "engineering_claim",
    "implementation_reference",
    "verification_source",
    "supporting_reports",
    "supporting_tests",
    "evidence_status",
})
TRACEABILITY_FIELDS = frozenset({
    "traceability_version",
    "repository_commit",
    "measured_baseline_identifier",
    "runtime_identity",
    "evidence_items",
    "traceability_digest",
})
TRACEABILITY_ITEM_FIELDS = frozenset({
    "evidence_identifier",
    "assurance_layer",
    "originating_report",
    "verification_method",
    "current_status",
})
EVIDENCE_INVENTORY_FIELDS = frozenset({
    "inventory_version",
    "repository_commit",
    "measured_baseline_identifier",
    "runtime_identity",
    "evidence",
    "evidence_inventory_digest",
})
EVIDENCE_RECORD_FIELDS = frozenset({
    "evidence_identifier",
    "source_path",
    "package_path",
    "sha256",
    "size_bytes",
    "status",
})
COMMAND_PACK_FIELDS = frozenset({
    "command_pack_version",
    "commands",
    "command_pack_digest",
})
COMMAND_RECORD_FIELDS = frozenset({
    "command_identifier",
    "command",
    "expected_output",
    "mutates_tracked_repository_state",
})
LEGACY_ASSURANCE_MARKERS = (
    b"PQC_01_PROVIDER_SIGNATURE_V1",
    b"DETERMINISTIC_PLACEHOLDER",
)
RECOVERY_PACKAGE_LINK_PATHS = (
    "sbp_lex/runtime/approved_runtime_baselines.json",
    "runtime_artifacts/measured_startup/measurement.anchor.json",
    "runtime_artifacts/measured_startup/startup.attestation.json",
    "outputs/local_trust_root_manifest.json",
    "outputs/local_execution_environment_trust_envelope.json",
    "outputs/local_evidence_chain.json",
    "outputs/local_constitutional_gates.json",
    "outputs/local_toolchain_guard.json",
    "outputs/local_trust_25_year_capstone.json",
    "outputs/release_integrity_bundle/RELEASE_MANIFEST.json",
    "outputs/phq_formal_architecture_assurance.json",
)


def _verify_repository_handoff_lineage(
    repository_root: Path,
    evidence_source_commit: str,
    repository_head: str,
) -> None:
    if (
        repository_head != evidence_source_commit
        and not generated_evidence_lineage_is_bounded(
            repository_root,
            evidence_source_commit,
            current_commit=repository_head,
        )
    ):
        raise IVVPError("repository_handoff_scope_invalid")


def _expected_signer_fingerprint(value: str | None) -> str:
    selected = value or os.environ.get(
        EXPECTED_SIGNER_FINGERPRINT_ENVIRONMENT_NAME,
        "",
    )
    if not HEX64.fullmatch(selected):
        raise IVVPError("expected_signer_fingerprint_required")
    if selected != trusted_signing_key_fingerprint():
        raise IVVPError("expected_signer_fingerprint_mismatch")
    return selected


def _load(package: Path, name: str) -> dict[str, Any]:
    path = package / name
    if path.is_symlink() or not path.is_file(): raise IVVPError(f"missing_package_file:{name}")
    return read_json(path, label=name.lower().replace(".", "_"))


def _identity(value: Mapping[str, Any]) -> None:
    if set(value) != IDENTITY_FIELDS:
        raise IVVPError("repository_identity_schema_invalid")
    digest = value.get("identity_digest"); core = {key: item for key, item in value.items() if key != "identity_digest"}
    if digest != generate_digest(core): raise IVVPError("repository_identity_digest_invalid")
    if value.get("repository_identity") != REPOSITORY_IDENTITY or value.get("desktop_scope") != DESKTOP_SCOPE: raise IVVPError("foreign_repository_identity")
    for key in (
        "repository_commit",
        "git_tree_identity",
        "trusted_repository_anchor_commit",
        "trusted_repository_anchor_tree",
    ):
        if not HEX40.fullmatch(str(value.get(key, ""))):
            raise IVVPError("repository_identity_invalid")
    for key in (
        "repository_digest",
        "measurement_digest",
        "runtime_identity",
        "trusted_signing_key_fingerprint",
    ):
        if not HEX64.fullmatch(str(value.get(key, ""))):
            raise IVVPError("repository_identity_invalid")
    if (
        value.get("identity_version") != R4_VERSION
        or value.get("repository_name") != "SBP-LEX Dual V6 Desktop V1"
        or value.get("canonical_designation")
        != "SBP_LEX_DUAL_V6_DESKTOP_V1"
        or
        value.get("trusted_repository_anchor_commit")
        != TRUSTED_REPOSITORY_ANCHOR_COMMIT
        or value.get("trusted_signing_key_fingerprint")
        != trusted_signing_key_fingerprint()
    ):
        raise IVVPError("repository_trust_anchor_invalid")


def _evidence_json(
    package: Path,
    relative: str,
    *,
    label: str | None = None,
) -> dict[str, Any]:
    path = package / "evidence" / relative
    if (
        path.is_symlink()
        or not path.is_file()
        or not path.resolve(strict=False).is_relative_to(package)
    ):
        raise IVVPError(f"missing_package_file:evidence/{relative}")
    return read_json(path, label=label or relative.replace("/", "_"))


def _expect_validation(
    name: str,
    result: Mapping[str, Any],
    field: str,
    expected: str,
) -> None:
    if result.get(field) != expected or result.get("validation_failures") != []:
        raise IVVPError(f"{name}_evidence_invalid")


def _portable_reference_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise IVVPError("nonportable_evidence_reference")
    candidate = PurePosixPath(value)
    if (
        value != candidate.as_posix()
        or candidate.is_absolute()
        or "\\" in value
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or re.match(r"^[A-Za-z]:", value)
        or value.startswith("//")
    ):
        raise IVVPError("nonportable_evidence_reference")
    return candidate.as_posix()


def _verify_packaged_reference(
    package: Path,
    reference: Mapping[str, Any],
    *,
    required_in_package: bool,
) -> None:
    relative = _portable_reference_path(reference.get("path"))
    path = package / "evidence" / relative
    present = path.is_file() and not path.is_symlink()
    if required_in_package and not present:
        raise IVVPError(f"referenced_evidence_missing:{relative}")
    if present and (
        reference.get("exists") is not True
        or reference.get("size_bytes") != path.stat().st_size
        or reference.get("sha256") != file_sha256(path)
    ):
        raise IVVPError(f"referenced_evidence_substituted:{relative}")


def _verify_local_trust_evidence(
    package: Path,
    identity: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    values: dict[str, Mapping[str, Any]] = {
        "manifest": _evidence_json(
            package, "outputs/local_trust_root_manifest.json",
        ),
        "envelope": _evidence_json(
            package,
            "outputs/local_execution_environment_trust_envelope.json",
        ),
        "chain": _evidence_json(
            package, "outputs/local_evidence_chain.json",
        ),
        "regression": _evidence_json(
            package, "outputs/local_trust_regression_matrix.json",
        ),
        "gates": _evidence_json(
            package, "outputs/local_constitutional_gates.json",
        ),
        "toolchain": _evidence_json(
            package, "outputs/local_toolchain_guard.json",
        ),
        "capstone": _evidence_json(
            package, "outputs/local_trust_25_year_capstone.json",
        ),
        "release": _evidence_json(
            package,
            "outputs/release_integrity_bundle/RELEASE_MANIFEST.json",
        ),
        "adversarial": _evidence_json(
            package,
            "outputs/adversarial_local_trust_negative_harness.json",
        ),
        "dossier": _evidence_json(
            package,
            "outputs/university_validation_dossier/DOSSIER_MANIFEST.json",
        ),
    }
    release_companions = {
        "artifact_hash_index": _evidence_json(
            package,
            "outputs/release_integrity_bundle/ARTIFACT_HASH_INDEX.json",
        ),
        "verification_commands": _evidence_json(
            package,
            "outputs/release_integrity_bundle/VERIFICATION_COMMANDS.json",
        ),
        "claims_to_evidence_seed": _evidence_json(
            package,
            "outputs/release_integrity_bundle/CLAIMS_TO_EVIDENCE_SEED.json",
        ),
        "boundary_lock": _evidence_json(
            package,
            "outputs/release_integrity_bundle/BOUNDARY_AND_SCOPE_LOCK.json",
        ),
    }
    dossier_companions = {
        "claims_index": _evidence_json(
            package,
            "outputs/university_validation_dossier/MASTER_CLAIMS_TO_EVIDENCE_INDEX.json",
        ),
        "validation_questions": _evidence_json(
            package,
            "outputs/university_validation_dossier/VALIDATION_QUESTIONS.json",
        ),
        "evidence_artifact_index": _evidence_json(
            package,
            "outputs/university_validation_dossier/EVIDENCE_ARTIFACT_INDEX.json",
        ),
        "scope_lock": _evidence_json(
            package,
            "outputs/university_validation_dossier/SCOPE_AND_EXCLUSIONS_LOCK.json",
        ),
        "reviewer_commands": _evidence_json(
            package,
            "outputs/university_validation_dossier/REVIEWER_VERIFICATION_COMMANDS.json",
        ),
    }
    validations = (
        (
            "local_trust",
            validate_local_trust_manifest(
                values["manifest"], clean_required=True,
            ),
            "local_trust_status",
            LOCAL_TRUST_VALID,
        ),
        (
            "execution_envelope",
            validate_execution_envelope(
                values["envelope"], clean_required=True,
            ),
            "verification_status",
            EXECUTION_ENV_VALID,
        ),
        (
            "evidence_chain",
            validate_local_evidence_chain(
                values["chain"], clean_required=True,
            ),
            "evidence_chain_status",
            EVIDENCE_CHAIN_VALID,
        ),
        (
            "regression_matrix",
            validate_local_trust_regression_matrix(
                values["regression"], clean_required=True,
            ),
            "matrix_status",
            REGRESSION_MATRIX_VALID,
        ),
        (
            "constitutional_gates",
            validate_constitutional_gate_result(
                values["gates"], clean_required=True,
            ),
            "gate_status",
            CONSTITUTIONAL_GATES_PASS,
        ),
        (
            "toolchain_guard",
            validate_toolchain_guard(
                values["toolchain"], clean_required=True,
            ),
            "toolchain_status",
            TOOLCHAIN_GUARD_PASS,
        ),
        (
            "local_trust_capstone",
            validate_local_trust_capstone(
                values["capstone"], clean_required=True,
            ),
            "capstone_status",
            LOCAL_TRUST_CAPSTONE_PASS,
        ),
        (
            "release_integrity",
            validate_release_manifest(
                values["release"],
                artifact_hash_index=release_companions[
                    "artifact_hash_index"
                ],
                verification_commands=release_companions[
                    "verification_commands"
                ],
                claims_to_evidence_seed=release_companions[
                    "claims_to_evidence_seed"
                ],
                boundary_lock=release_companions["boundary_lock"],
                clean_required=True,
            ),
            "release_status",
            RELEASE_INTEGRITY_PASS,
        ),
        (
            "adversarial_harness",
            validate_adversarial_harness(
                values["adversarial"], clean_required=True,
            ),
            "adversarial_status",
            ADVERSARIAL_NEGATIVE_HARNESS_PASS,
        ),
        (
            "university_dossier",
            validate_dossier_manifest(
                values["dossier"],
                claims_index=dossier_companions["claims_index"],
                validation_questions=dossier_companions[
                    "validation_questions"
                ],
                evidence_artifact_index=dossier_companions[
                    "evidence_artifact_index"
                ],
                scope_lock=dossier_companions["scope_lock"],
                reviewer_commands=dossier_companions[
                    "reviewer_commands"
                ],
                clean_required=True,
            ),
            "dossier_status",
            VALIDATION_DOSSIER_READY,
        ),
    )
    for name, result, field, expected in validations:
        _expect_validation(name, result, field, expected)
    for reference in values["release"].get("release_artifacts", ()):
        if not isinstance(reference, Mapping):
            raise IVVPError("release_reference_invalid")
        _verify_packaged_reference(
            package, reference, required_in_package=True,
        )
    for field in (
        "verification_commands_reference",
        "claims_to_evidence_seed_reference",
        "boundary_lock_reference",
        "artifact_hash_index_reference",
    ):
        reference = values["release"].get(field)
        if not isinstance(reference, Mapping):
            raise IVVPError("release_reference_invalid")
        _verify_packaged_reference(
            package, reference, required_in_package=True,
        )
    for reference in release_companions[
        "artifact_hash_index"
    ].get("artifacts", ()):
        if not isinstance(reference, Mapping):
            raise IVVPError("release_artifact_index_invalid")
        _verify_packaged_reference(
            package, reference, required_in_package=False,
        )
    for field in (
        "claims_to_evidence_reference",
        "validation_questions_reference",
        "evidence_artifact_index_reference",
        "scope_and_exclusions_reference",
        "reviewer_commands_reference",
        "handoff_readme_reference",
    ):
        reference = values["dossier"].get(field)
        if not isinstance(reference, Mapping):
            raise IVVPError("dossier_reference_invalid")
        _verify_packaged_reference(
            package, reference, required_in_package=True,
        )
    for reference in dossier_companions[
        "evidence_artifact_index"
    ].get("artifacts", ()):
        if not isinstance(reference, Mapping):
            raise IVVPError("dossier_artifact_index_invalid")
        _verify_packaged_reference(
            package, reference, required_in_package=False,
        )
    for name, value in values.items():
        if value.get("git_commit") != identity["repository_commit"]:
            raise IVVPError(f"{name}_repository_commit_mismatch")
        if value.get("git_branch") != "main":
            raise IVVPError(f"{name}_repository_branch_mismatch")

    digests = {
        "manifest": values["manifest"]["manifest_digest"],
        "envelope": values["envelope"]["envelope_digest"],
        "chain": values["chain"]["chain_digest"],
        "regression": values["regression"]["matrix_digest"],
        "gates": values["gates"]["gate_digest"],
        "toolchain": values["toolchain"]["toolchain_digest"],
        "capstone": values["capstone"]["capstone_digest"],
        "release": values["release"]["release_digest"],
        "adversarial": values["adversarial"]["adversarial_digest"],
    }
    bindings = (
        ("envelope", "bound_local_trust_manifest_digest", "manifest"),
        ("chain", "bound_local_trust_manifest_digest", "manifest"),
        ("chain", "bound_execution_envelope_digest", "envelope"),
        ("regression", "bound_manifest_digest", "manifest"),
        ("regression", "bound_execution_envelope_digest", "envelope"),
        ("regression", "bound_evidence_chain_digest", "chain"),
        ("gates", "bound_manifest_digest", "manifest"),
        ("gates", "bound_execution_envelope_digest", "envelope"),
        ("gates", "bound_evidence_chain_digest", "chain"),
        ("gates", "bound_regression_matrix_digest", "regression"),
        ("toolchain", "bound_manifest_digest", "manifest"),
        ("toolchain", "bound_execution_envelope_digest", "envelope"),
        ("toolchain", "bound_evidence_chain_digest", "chain"),
        ("toolchain", "bound_regression_matrix_digest", "regression"),
        ("toolchain", "bound_constitutional_gates_digest", "gates"),
        ("capstone", "bound_manifest_digest", "manifest"),
        ("capstone", "bound_execution_envelope_digest", "envelope"),
        ("capstone", "bound_evidence_chain_digest", "chain"),
        ("capstone", "bound_regression_matrix_digest", "regression"),
        ("capstone", "bound_constitutional_gates_digest", "gates"),
        ("capstone", "bound_toolchain_guard_digest", "toolchain"),
        ("release", "bound_manifest_digest", "manifest"),
        ("release", "bound_execution_envelope_digest", "envelope"),
        ("release", "bound_evidence_chain_digest", "chain"),
        ("release", "bound_regression_matrix_digest", "regression"),
        ("release", "bound_constitutional_gates_digest", "gates"),
        ("release", "bound_toolchain_guard_digest", "toolchain"),
        ("release", "bound_capstone_digest", "capstone"),
        ("adversarial", "bound_manifest_digest", "manifest"),
        ("adversarial", "bound_execution_envelope_digest", "envelope"),
        ("adversarial", "bound_evidence_chain_digest", "chain"),
        ("adversarial", "bound_regression_matrix_digest", "regression"),
        ("adversarial", "bound_constitutional_gates_digest", "gates"),
        ("adversarial", "bound_toolchain_guard_digest", "toolchain"),
        ("adversarial", "bound_capstone_digest", "capstone"),
        ("adversarial", "bound_release_integrity_digest", "release"),
        ("dossier", "bound_manifest_digest", "manifest"),
        ("dossier", "bound_execution_envelope_digest", "envelope"),
        ("dossier", "bound_evidence_chain_digest", "chain"),
        ("dossier", "bound_regression_matrix_digest", "regression"),
        ("dossier", "bound_constitutional_gates_digest", "gates"),
        ("dossier", "bound_toolchain_guard_digest", "toolchain"),
        ("dossier", "bound_capstone_digest", "capstone"),
        ("dossier", "bound_release_integrity_digest", "release"),
        ("dossier", "bound_adversarial_harness_digest", "adversarial"),
    )
    for source, field, target in bindings:
        if values[source].get(field) != digests[target]:
            raise IVVPError(
                f"local_trust_linkage_mismatch:{source}:{field}"
            )
    return values


def _verify_r2_evidence(
    package: Path,
    identity: Mapping[str, Any],
) -> tuple[dict[str, Any], list[Mapping[str, Any]]]:
    sbom = _evidence_json(
        package, "outputs/r2_software_bill_of_materials.json",
    )
    try:
        validate_dependency_provenance(sbom, verify_installed=False)
    except Exception as exc:
        raise IVVPError("r2_sbom_invalid") from exc
    sealed_manifest = _evidence_json(
        package, "outputs/r2_deterministic_build_manifest.json",
    )
    try:
        payload = unseal_r2(sealed_manifest, label="r2_manifest")
    except Exception as exc:
        raise IVVPError("r2_manifest_invalid") from exc
    if (
        set(payload) != MANIFEST_PAYLOAD_FIELDS
        or
        payload.get("manifest_version")
        != "R2_DESKTOP_V1_DETERMINISTIC_BUILD_MANIFEST_V1"
        or payload.get("desktop_scope") != R2_DESKTOP_SCOPE
        or payload.get("manifest_status")
        != "SUPPLY_CHAIN_PROVENANCE_APPROVED"
    ):
        raise IVVPError("r2_manifest_scope_invalid")
    identity_value = payload.get("supply_chain_identity")
    if identity_value != generate_digest({
        key: item
        for key, item in payload.items()
        if key != "supply_chain_identity"
    }):
        raise IVVPError("r2_supply_chain_identity_invalid")
    repository = payload.get("repository_provenance")
    build = payload.get("build_provenance")
    if not isinstance(repository, Mapping) or not isinstance(build, Mapping):
        raise IVVPError("r2_provenance_link_missing")
    if (
        set(repository) != REPOSITORY_PROVENANCE_FIELDS
        or set(build) != BUILD_PROVENANCE_FIELDS
    ):
        raise IVVPError("r2_provenance_schema_invalid")
    if repository.get("repository_digest") != generate_digest({
        key: item
        for key, item in repository.items()
        if key != "repository_digest"
    }):
        raise IVVPError("r2_repository_digest_invalid")
    repository_expected = {
        "provenance_version": R2_VERSION,
        "desktop_scope": R2_DESKTOP_SCOPE,
        "repository_identity": EXPECTED_REPOSITORY_IDENTITY,
        "canonical_branch": "main",
        "repository_commit": identity["repository_commit"],
        "repository_tree": identity["git_tree_identity"],
        "trusted_repository_anchor_commit":
            identity["trusted_repository_anchor_commit"],
        "trusted_repository_anchor_tree":
            identity["trusted_repository_anchor_tree"],
        "upstream_reference": CANONICAL_UPSTREAM,
        "tracked_working_tree_clean": True,
        "untracked_files_checked": True,
        "origin_kind": "canonical_origin",
    }
    if any(
        repository.get(key) != value
        for key, value in repository_expected.items()
    ):
        raise IVVPError("r2_repository_linkage_invalid")
    lineage = repository.get("parent_lineage")
    if (
        not isinstance(lineage, list)
        or not lineage
        or lineage[0] != identity["repository_commit"]
        or len(lineage) != len(set(lineage))
        or any(not HEX40.fullmatch(str(item)) for item in lineage)
        or repository.get("lineage_depth_recorded") != len(lineage)
    ):
        raise IVVPError("r2_repository_lineage_invalid")
    if build.get("build_identity") != generate_digest({
        key: item
        for key, item in build.items()
        if key != "build_identity"
    }):
        raise IVVPError("r2_build_identity_invalid")
    build_expected = {
        "build_provenance_version": R2_VERSION,
        "desktop_scope": R2_DESKTOP_SCOPE,
        "repository_commit": identity["repository_commit"],
        "measured_baseline_identifier":
            identity["measured_baseline_identifier"],
        "measurement_digest": identity["measurement_digest"],
        "runtime_identity": identity["runtime_identity"],
        "environment_policy": "LOCAL_OFFLINE_APPROVED_TOOLCHAIN_ONLY",
    }
    if any(build.get(key) != value for key, value in build_expected.items()):
        raise IVVPError("stale_r2_evidence")
    provider = build.get("pqc_provider")
    cryptographic_provider = build.get("cryptographic_provider")
    if (
        not isinstance(provider, Mapping)
        or set(provider) != {
            "policy",
            "signature_algorithm",
            "provider",
            "provider_version",
            "provider_available",
            "trusted_signing_key_available",
            "trusted_signing_key_fingerprint",
            "crypto_profile_version",
            "verification_policy_version",
            "migration_profile_ready",
            "migration_profile_error",
            "fail_closed",
        }
        or provider.get("policy") != "NIST_FIPS_203_204_205"
        or provider.get("signature_algorithm") != "ML-DSA"
        or provider.get("provider") != "cryptography.mldsa"
        or not isinstance(provider.get("provider_version"), str)
        or not provider["provider_version"]
        or provider.get("provider_available") is not True
        or provider.get("trusted_signing_key_available") is not True
        or provider.get("crypto_profile_version") != CRYPTO_PROFILE_VERSION
        or provider.get("verification_policy_version")
        != VERIFICATION_POLICY_VERSION
        or provider.get("migration_profile_ready") is not True
        or provider.get("migration_profile_error") is not None
        or provider.get("fail_closed") is not True
        or provider.get("trusted_signing_key_fingerprint")
        != identity["trusted_signing_key_fingerprint"]
        or not isinstance(cryptographic_provider, Mapping)
        or provider.get("provider_version")
        != cryptographic_provider.get("version")
    ):
        raise IVVPError("r2_pqc_provider_invalid")
    python = build.get("python")
    operating_system = build.get("operating_system")
    if (
        not isinstance(build.get("measured_baseline_sequence"), int)
        or isinstance(build.get("measured_baseline_sequence"), bool)
        or build["measured_baseline_sequence"] <= 0
        or not isinstance(python, Mapping)
        or set(python) != {
            "implementation",
            "version",
            "architecture",
            "executable_name",
            "executable_sha256",
        }
        or not HEX64.fullmatch(
            str(python.get("executable_sha256", ""))
        )
        or not isinstance(operating_system, Mapping)
        or set(operating_system) != {"system", "release", "machine"}
        or not isinstance(cryptographic_provider, Mapping)
        or set(cryptographic_provider) != {"package", "version"}
        or cryptographic_provider.get("package") != "cryptography"
        or not isinstance(cryptographic_provider.get("version"), str)
        or not cryptographic_provider["version"]
    ):
        raise IVVPError("r2_build_environment_invalid")
    toolchain_path = (
        package / "evidence/outputs/local_toolchain_guard.json"
    )
    if build.get("toolchain_guard_sha256") != file_sha256(toolchain_path):
        raise IVVPError("r2_toolchain_linkage_invalid")
    if (
        payload.get("dependency_digest") != sbom.get("dependency_digest")
        or payload.get("dependency_count") != sbom.get("dependency_count")
    ):
        raise IVVPError("r2_sbom_linkage_invalid")
    artifacts = payload.get("artefact_inventory")
    if not isinstance(artifacts, list) or not artifacts:
        raise IVVPError("r2_artifact_inventory_invalid")
    if payload.get("artefact_inventory_digest") != generate_digest(
        {"artefacts": artifacts}
    ):
        raise IVVPError("r2_artifact_inventory_digest_invalid")
    paths: set[str] = set()
    identities: set[str] = set()
    for record in artifacts:
        if (
            not isinstance(record, Mapping)
            or set(record) != ARTIFACT_RECORD_FIELDS
        ):
            raise IVVPError("r2_artifact_record_invalid")
        try:
            relative = _portable_reference_path(record.get("path"))
        except IVVPError as exc:
            raise IVVPError("r2_artifact_record_invalid") from exc
        logical = record.get("logical_identity")
        relationship = record.get("creation_relationship")
        if (
            relative in paths
            or logical in identities
            or logical != relative.lower().replace("/", ".")
            or record.get("repository_origin")
            != EXPECTED_REPOSITORY_IDENTITY
            or not HEX64.fullmatch(str(record.get("sha256", "")))
            or not isinstance(record.get("size_bytes"), int)
            or isinstance(record.get("size_bytes"), bool)
            or record["size_bytes"] <= 0
            or not isinstance(record.get("artefact_type"), str)
            or not record["artefact_type"]
        ):
            raise IVVPError("r2_artifact_record_invalid")
        expected_relationship = (
            "GENERATED_EVIDENCE"
            if relative.startswith("outputs/")
            else (
                "PROTECTED_REPORT"
                if relative.startswith("reports/")
                else "REPOSITORY_SOURCE"
            )
        )
        if relationship != expected_relationship:
            raise IVVPError("r2_artifact_relationship_invalid")
        if relationship == "GENERATED_EVIDENCE":
            if (
                record.get("repository_blob") is not None
                or record.get("repository_blob_sha256") is not None
                or record.get("repository_blob_size_bytes") is not None
                or record.get("tracked_at_repository_commit") is not False
            ):
                raise IVVPError("r2_generated_artifact_origin_invalid")
        elif (
            not HEX40.fullmatch(str(record.get("repository_blob", "")))
            or not HEX64.fullmatch(
                str(record.get("repository_blob_sha256", ""))
            )
            or not isinstance(
                record.get("repository_blob_size_bytes"), int,
            )
            or isinstance(record.get("repository_blob_size_bytes"), bool)
            or record["repository_blob_size_bytes"] < 0
            or record.get("tracked_at_repository_commit") is not True
        ):
            raise IVVPError("r2_repository_artifact_origin_invalid")
        paths.add(relative)
        identities.add(str(logical))
    bindings = {
        item["path"]: item["sha256"]
        for item in artifacts
        if item.get("creation_relationship") == "GENERATED_EVIDENCE"
    }
    if (
        payload.get("validation_evidence_bindings") != bindings
        or payload.get("validation_identity") != generate_digest(
            {"validation_evidence_bindings": bindings}
        )
    ):
        raise IVVPError("r2_validation_evidence_linkage_invalid")
    for relative, digest in bindings.items():
        path = package / "evidence" / relative
        if not path.is_file() or path.is_symlink():
            raise IVVPError(f"r2_generated_evidence_missing:{relative}")
        if file_sha256(path) != digest:
            raise IVVPError(f"r2_generated_evidence_stale:{relative}")
    if (
        payload.get("network_required_for_verification") is not False
        or payload.get("canonical_payload_contains_timestamp") is not False
    ):
        raise IVVPError("r2_offline_policy_invalid")
    verification_wrapper = _evidence_json(
        package, "outputs/r2_offline_verification.json",
    )
    try:
        verification = unseal_r2(
            verification_wrapper, label="r2_verification",
        )
    except Exception as exc:
        raise IVVPError("r2_offline_verification_invalid") from exc
    expected_verification = {
        "verification_version":
            "R2_DESKTOP_V1_OFFLINE_VERIFICATION_V1",
        "desktop_scope": R2_DESKTOP_SCOPE,
        "manifest_digest": sealed_manifest["payload_digest"],
        "supply_chain_identity": payload["supply_chain_identity"],
        "link_results": {
            "repository": "VERIFIED",
            "dependencies": "VERIFIED",
            "build": "VERIFIED",
            "artefacts": "VERIFIED",
            "runtime_linkage": "VERIFIED",
            "validation_evidence": "VERIFIED",
        },
        "network_used": False,
        "verification_status": "R2_SUPPLY_CHAIN_ASSURANCE_PASS",
    }
    if verification != expected_verification:
        raise IVVPError("r2_offline_verification_stale")
    return payload, artifacts


def _verify_formal_evidence(
    package: Path,
    r2_artifacts: Sequence[Mapping[str, Any]],
) -> None:
    artifact = _evidence_json(
        package, "outputs/phq_formal_architecture_assurance.json",
    )
    if set(artifact) != {
        "payload", "payload_digest", "integrity_signature",
    }:
        raise IVVPError("formal_assurance_wrapper_invalid")
    payload = artifact.get("payload")
    if not isinstance(payload, Mapping):
        raise IVVPError("formal_assurance_payload_invalid")
    if artifact.get("payload_digest") != generate_digest(payload):
        raise IVVPError("formal_assurance_digest_invalid")
    if not verify_signature(
        {"integrity_domain": ASSURANCE_DOMAIN, "payload": dict(payload)},
        artifact.get("integrity_signature", {}),
    ):
        raise IVVPError("formal_assurance_signature_invalid")
    formal_expected = {
        "artifact_version": ARTIFACT_VERSION,
        "model_version": FORMAL_MODEL_VERSION,
        "evidence_version": FORMAL_EVIDENCE_VERSION,
        "authority_granted": False,
        "formalisation_boundary":
            "DETACHED_NON_AUTHORITATIVE_ASSURANCE_ONLY",
        "architecture": "SBP_LEX_DUAL_V6_DESKTOP_V1",
        "topology": "LOCAL_PRIVATE_SINGLE_HOST_NO_NODE",
    }
    if any(payload.get(key) != value for key, value in formal_expected.items()):
        raise IVVPError("formal_assurance_boundary_invalid")
    specification_digest = payload.get("formal_specification_digest")
    if specification_digest != generate_digest({
        key: item
        for key, item in payload.items()
        if key != "formal_specification_digest"
    }):
        raise IVVPError("formal_assurance_specification_digest_invalid")
    source_measurements = payload.get("source_measurements")
    if not isinstance(source_measurements, list) or not source_measurements:
        raise IVVPError("formal_assurance_sources_missing")
    r2_by_path = {
        str(item.get("path")): item
        for item in r2_artifacts
        if isinstance(item, Mapping)
    }
    for source in source_measurements:
        if not isinstance(source, Mapping):
            raise IVVPError("formal_assurance_source_invalid")
        r2 = r2_by_path.get(str(source.get("path")))
        if (
            r2 is None
            or source.get("sha256") != r2.get("sha256")
            or source.get("size_bytes") != r2.get("size_bytes")
        ):
            raise IVVPError("formal_assurance_source_linkage_invalid")


def _verify_recovery_evidence(package: Path) -> None:
    inventory = _evidence_json(
        package, "outputs/recovery_critical_inventory.json",
    )
    try:
        validate_inventory(inventory)
    except Exception as exc:
        raise IVVPError("r1_recovery_inventory_invalid") from exc
    _verify_recovery_inventory_links(package, inventory)
    drill = _evidence_json(package, "outputs/r1_recovery_drill.json")
    digest = drill.get("result_digest")
    core = {
        key: item for key, item in drill.items()
        if key != "result_digest"
    }
    if (
        digest != generate_digest(core)
        or drill.get("status") != "RECOVERY_DRILL_PASS"
        or drill.get("fresh_process_validated") is not True
        or drill.get("corruption_rejected") is not True
        or drill.get("replay_rejected") is not True
        or drill.get("live_state_modified") is not False
    ):
        raise IVVPError("r1_recovery_drill_invalid")


def _verify_recovery_inventory_links(
    package: Path,
    inventory: Mapping[str, Any],
    *,
    required_paths: Sequence[str] = RECOVERY_PACKAGE_LINK_PATHS,
) -> None:
    records = inventory.get("artefacts")
    if not isinstance(records, list):
        raise IVVPError("r1_recovery_inventory_linkage_invalid")
    by_source: dict[str, Mapping[str, Any]] = {}
    for record in records:
        if not isinstance(record, Mapping):
            raise IVVPError("r1_recovery_inventory_linkage_invalid")
        relative = _portable_reference_path(record.get("source_path"))
        if relative in by_source:
            raise IVVPError("r1_recovery_inventory_linkage_invalid")
        by_source[relative] = record
    for raw in required_paths:
        relative = _portable_reference_path(raw)
        record = by_source.get(relative)
        path = package / "evidence" / relative
        if (
            record is None
            or path.is_symlink()
            or not path.is_file()
            or not path.resolve(strict=False).is_relative_to(package)
            or record.get("current_digest") != file_sha256(path)
            or record.get("size_bytes") != path.stat().st_size
        ):
            raise IVVPError("r1_recovery_inventory_linkage_invalid")


def _verify_r3_evidence(
    package: Path,
    identity: Mapping[str, Any],
    r2: Mapping[str, Any],
) -> None:
    wrapper = _evidence_json(
        package, "outputs/r3_operational_custody_assurance.json",
    )
    try:
        payload = unseal_r3(
            wrapper, label="custody_assurance_profile",
        )
    except Exception as exc:
        raise IVVPError("r3_profile_invalid") from exc
    digest = payload.get("profile_digest")
    if digest != generate_digest({
        key: item
        for key, item in payload.items()
        if key != "profile_digest"
    }):
        raise IVVPError("r3_profile_digest_invalid")
    expected = {
        "repository_commit": identity["repository_commit"],
        "r2_supply_chain_identity": r2["supply_chain_identity"],
        "measured_baseline_identifier":
            identity["measured_baseline_identifier"],
        "runtime_identity": identity["runtime_identity"],
        "private_key_material_present": False,
        "cloud_service_required": False,
        "distributed_authority_introduced": False,
        "operational_status": "R3_CUSTODY_ASSURANCE_READY",
    }
    if any(payload.get(key) != value for key, value in expected.items()):
        raise IVVPError("stale_r3_evidence")


def _verify_runtime_evidence(
    package: Path,
    identity: Mapping[str, Any],
    baseline_store: Mapping[str, Any],
) -> None:
    runtime = _load(package, "RUNTIME_REPLAY_EVIDENCE.json")
    expected = {
        "runtime_result": "PASS",
        "runtime_decision": "ALLOW",
        "execution_result": "EXECUTE",
        "convergence_matched": True,
        "runtime_identity": identity["runtime_identity"],
        "measured_baseline_identifier":
            identity["measured_baseline_identifier"],
        "measurement_digest": identity["measurement_digest"],
        "replay_result": "PASS",
        "replay_matched": True,
        "replay_mismatches": 0,
        "replay_runtime_identity": identity["runtime_identity"],
        "replay_measured_baseline_identifier":
            identity["measured_baseline_identifier"],
        "replay_measurement_digest": identity["measurement_digest"],
    }
    if any(runtime.get(key) != value for key, value in expected.items()):
        raise IVVPError("runtime_replay_evidence_failed")
    runtime_sequence = runtime.get("runtime_startup_sequence")
    replay_sequence = runtime.get("replay_startup_sequence")
    if (
        not isinstance(runtime_sequence, int)
        or isinstance(runtime_sequence, bool)
        or not isinstance(replay_sequence, int)
        or isinstance(replay_sequence, bool)
        or runtime_sequence <= 0
        or replay_sequence != runtime_sequence + 1
    ):
        raise IVVPError("runtime_replay_startup_sequence_invalid")
    baseline_store_digest = baseline_store["payload_digest"]
    attestations = (
        (
            "runtime",
            runtime.get("runtime_startup_attestation"),
            runtime.get("runtime_startup_attestation_digest"),
            runtime_sequence,
        ),
        (
            "replay",
            runtime.get("replay_startup_attestation"),
            runtime.get("replay_startup_attestation_digest"),
            replay_sequence,
        ),
    )
    for name, attestation, digest, sequence in attestations:
        if (
            not isinstance(attestation, Mapping)
            or not verify_startup_attestation(attestation)
            or generate_digest(attestation) != digest
        ):
            raise IVVPError(f"{name}_startup_attestation_invalid")
        payload = attestation.get("payload")
        if (
            not isinstance(payload, Mapping)
            or payload.get("startup_sequence") != sequence
            or payload.get("approved_baseline_identifier")
            != identity["measured_baseline_identifier"]
            or payload.get("baseline_store_digest")
            != baseline_store_digest
            or payload.get("runtime_identity") != identity["runtime_identity"]
            or payload.get("measurement_digest")
            != identity["measurement_digest"]
        ):
            raise IVVPError(f"{name}_startup_attestation_linkage_invalid")
    replay_attestation = _evidence_json(
        package,
        "runtime_artifacts/measured_startup/startup.attestation.json",
    )
    if replay_attestation != runtime["replay_startup_attestation"]:
        raise IVVPError("replay_startup_attestation_substitution")
    anchor = _evidence_json(
        package,
        "runtime_artifacts/measured_startup/measurement.anchor.json",
    )
    try:
        anchor_payload = _validate_anchor(anchor)
    except Exception as exc:
        raise IVVPError("measurement_anchor_invalid") from exc
    if (
        anchor_payload.get("startup_sequence") != replay_sequence
        or anchor_payload.get("last_attestation_digest")
        != runtime["replay_startup_attestation_digest"]
        or anchor_payload.get("approved_baseline_identifier")
        != identity["measured_baseline_identifier"]
        or anchor_payload.get("baseline_store_digest")
        != baseline_store_digest
    ):
        raise IVVPError("measurement_anchor_linkage_invalid")


def _verify_claim_repository_links(
    claims: Sequence[Mapping[str, Any]],
    artifacts: Sequence[Mapping[str, Any]],
) -> None:
    tracked_paths = {
        str(record.get("path"))
        for record in artifacts
        if record.get("creation_relationship") != "GENERATED_EVIDENCE"
        and record.get("tracked_at_repository_commit") is True
    }
    for claim in claims:
        implementation = _portable_reference_path(
            claim.get("implementation_reference")
        )
        if (
            implementation not in tracked_paths
            and not any(
                path.startswith(f"{implementation}/")
                for path in tracked_paths
            )
        ):
            raise IVVPError(
                f"claim_implementation_unbound:{implementation}"
            )
        verification_source = _portable_reference_path(
            claim.get("verification_source")
        )
        if (
            verification_source not in tracked_paths
            or verification_source not in claim["supporting_tests"]
        ):
            raise IVVPError(
                f"claim_verification_source_unbound:{verification_source}"
            )
        for test_path in claim["supporting_tests"]:
            test_reference = _portable_reference_path(test_path)
            if test_reference not in tracked_paths:
                raise IVVPError(
                    f"claim_test_unbound:{test_reference}"
                )
        for report in claim["supporting_reports"]:
            if report == "RUNTIME_REPLAY_EVIDENCE.json":
                continue
            report_reference = _portable_reference_path(
                f"reports/{Path(report).name}"
            )
            if report_reference not in tracked_paths:
                raise IVVPError(
                    f"claim_report_unbound:{report_reference}"
                )


def verify_package(
    package_root: Path,
    *,
    repository_root: Path | None = None,
    expected_signer_fingerprint: str | None = None,
) -> dict[str, Any]:
    expected_signer = _expected_signer_fingerprint(
        expected_signer_fingerprint,
    )
    package = package_root.resolve()
    if package.is_symlink() or not package.is_dir(): raise IVVPError("validation_package_missing")
    for path in package.rglob("*"):
        if path.is_symlink(): raise IVVPError("validation_package_symlink")
    manifest_wrapper = _load(package, "PACKAGE_MANIFEST.json"); manifest = unseal(manifest_wrapper, label="package_manifest")
    if set(manifest) != PACKAGE_MANIFEST_FIELDS:
        raise IVVPError("package_manifest_schema_invalid")
    package_identity = manifest.get("package_identity"); core = {key: item for key, item in manifest.items() if key != "package_identity"}
    if package_identity != generate_digest(core) or manifest.get("manifest_version") != R4_VERSION or manifest.get("package_status") != "R4_IVVP_READY": raise IVVPError("package_manifest_invalid")
    if manifest.get("repository_identity") != REPOSITORY_IDENTITY or manifest.get("desktop_scope") != DESKTOP_SCOPE: raise IVVPError("foreign_validation_package")
    expected_files = {"PACKAGE_MANIFEST.json"}
    records = manifest.get("package_files")
    if not isinstance(records, list) or not records: raise IVVPError("package_file_inventory_missing")
    seen: set[str] = set()
    for record in records:
        if (
            not isinstance(record, Mapping)
            or set(record) != {"path", "sha256", "size_bytes"}
        ):
            raise IVVPError("package_file_record_invalid")
        relative = _portable_reference_path(record.get("path"))
        if relative in seen:
            raise IVVPError("duplicate_package_file")
        path = (package / relative).resolve(strict=False)
        if not path.is_relative_to(package) or not path.is_file() or path.is_symlink(): raise IVVPError(f"missing_package_file:{relative}")
        if (
            not HEX64.fullmatch(str(record.get("sha256", "")))
            or not isinstance(record.get("size_bytes"), int)
            or isinstance(record.get("size_bytes"), bool)
            or record["size_bytes"] < 0
            or record.get("sha256") != file_sha256(path)
            or record.get("size_bytes") != path.stat().st_size
        ):
            raise IVVPError(f"substituted_package_file:{relative}")
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise IVVPError(f"package_file_read_failed:{relative}") from exc
        if any(marker in raw for marker in LEGACY_ASSURANCE_MARKERS):
            raise IVVPError(f"legacy_assurance_evidence:{relative}")
        seen.add(relative); expected_files.add(relative)
    actual_files = {path.relative_to(package).as_posix() for path in package.rglob("*") if path.is_file()}
    if actual_files != expected_files: raise IVVPError("unexpected_package_file")
    identity = _load(package, "REPOSITORY_IDENTITY.json"); _identity(identity)
    if identity.get("trusted_signing_key_fingerprint") != expected_signer:
        raise IVVPError("package_signer_fingerprint_mismatch")
    for key in (
        "repository_commit",
        "git_tree_identity",
        "trusted_repository_anchor_commit",
        "trusted_repository_anchor_tree",
        "trusted_signing_key_fingerprint",
        "measured_baseline_identifier",
        "runtime_identity",
        "identity_digest",
    ):
        if manifest.get(key) != identity.get(key): raise IVVPError(f"identity_consistency_mismatch:{key}")
    claims = _load(package, "ENGINEERING_CLAIMS_REGISTER.json")
    claim_items = claims.get("claims")
    if (
        set(claims) != CLAIMS_REGISTER_FIELDS
        or claims.get("register_version") != R4_VERSION
        or not isinstance(claim_items, list)
        or not claim_items
        or claims.get("claims_digest")
        != generate_digest({"claims": claim_items})
    ):
        raise IVVPError("claims_register_invalid")
    claim_ids: set[str] = set(); evidence_basenames = {Path(item).name for item in seen if item.startswith("evidence/")}
    for claim in claim_items:
        if (
            not isinstance(claim, Mapping)
            or set(claim) != CLAIM_FIELDS
            or not all(
                isinstance(claim.get(field), str)
                and claim[field].strip()
                for field in (
                    "claim_identifier",
                    "engineering_claim",
                    "implementation_reference",
                    "verification_source",
                )
            )
            or not isinstance(claim.get("supporting_reports"), list)
            or not isinstance(claim.get("supporting_tests"), list)
            or any(
                not isinstance(value, str) or not value
                for value in (
                    claim["supporting_reports"]
                    + claim["supporting_tests"]
                )
            )
            or claim["supporting_reports"]
            != list(dict.fromkeys(claim["supporting_reports"]))
            or claim["supporting_tests"]
            != list(dict.fromkeys(claim["supporting_tests"]))
            or claim.get("claim_identifier") in claim_ids
        ):
            raise IVVPError("claim_traceability_invalid")
        claim_ids.add(str(claim["claim_identifier"]))
        if claim.get("evidence_status") not in {"SUPPORTED", "UNSUPPORTED"}: raise IVVPError("claim_status_invalid")
        if claim.get("evidence_status") == "SUPPORTED" and (not claim.get("supporting_reports") or not claim.get("supporting_tests")): raise IVVPError("claim_without_evidence")
        for report in claim["supporting_reports"]:
            if report != "RUNTIME_REPLAY_EVIDENCE.json" and Path(report).name not in evidence_basenames: raise IVVPError(f"broken_report_link:{report}")
    if claims.get("repository_commit") != identity["repository_commit"] or claims.get("measured_baseline_identifier") != identity["measured_baseline_identifier"] or claims.get("runtime_identity") != identity["runtime_identity"]: raise IVVPError("claims_identity_mismatch")
    trace = _load(package, "EVIDENCE_TRACEABILITY_INDEX.json"); trace_items = trace.get("evidence_items")
    if (
        set(trace) != TRACEABILITY_FIELDS
        or trace.get("traceability_version") != R4_VERSION
        or not isinstance(trace_items, list)
        or not trace_items
        or trace.get("traceability_digest")
        != generate_digest({"evidence_items": trace_items})
    ):
        raise IVVPError("traceability_invalid")
    trace_ids: set[str] = set()
    trace_layers: set[str] = set()
    for item in trace_items:
        if (
            not isinstance(item, Mapping)
            or set(item) != TRACEABILITY_ITEM_FIELDS
            or item.get("current_status") != "VERIFIED"
            or not isinstance(item.get("evidence_identifier"), str)
            or not item["evidence_identifier"]
            or not isinstance(item.get("assurance_layer"), str)
            or not item["assurance_layer"]
            or not isinstance(item.get("verification_method"), str)
            or not item["verification_method"]
            or item["evidence_identifier"] in trace_ids
            or item["assurance_layer"] in trace_layers
        ):
            raise IVVPError("broken_traceability")
        trace_ids.add(item["evidence_identifier"])
        trace_layers.add(item["assurance_layer"])
        report = item.get("originating_report")
        if (
            not isinstance(report, str)
            or not report
            or (
                report != "RUNTIME_REPLAY_EVIDENCE.json"
                and Path(report).name not in evidence_basenames
            )
        ):
            raise IVVPError(f"broken_traceability:{report}")
    if trace_layers != {
        "H7",
        "PHQ",
        "R1",
        "R2",
        "R3",
        "DOUBLE_TRIPLE",
        "LOCAL_TRUST",
        "CONSTITUTIONAL_GATES",
        "TOOLCHAIN_GUARD",
        "RELEASE_INTEGRITY",
        "CAPSTONE",
        "RUNTIME_REPLAY",
    }:
        raise IVVPError("traceability_layer_coverage_invalid")
    if (
        trace.get("repository_commit") != identity["repository_commit"]
        or trace.get("measured_baseline_identifier")
        != identity["measured_baseline_identifier"]
        or trace.get("runtime_identity") != identity["runtime_identity"]
    ):
        raise IVVPError("traceability_identity_mismatch")
    inventory = _load(package, "EVIDENCE_INVENTORY.json"); evidence = inventory.get("evidence")
    if (
        set(inventory) != EVIDENCE_INVENTORY_FIELDS
        or inventory.get("inventory_version") != R4_VERSION
        or not isinstance(evidence, list)
        or not evidence
        or inventory.get("evidence_inventory_digest")
        != generate_digest({"evidence": evidence})
    ):
        raise IVVPError("evidence_inventory_invalid")
    evidence_ids: set[str] = set()
    evidence_sources: set[str] = set()
    evidence_paths: set[str] = set()
    for record in evidence:
        if (
            not isinstance(record, Mapping)
            or set(record) != EVIDENCE_RECORD_FIELDS
        ):
            raise IVVPError("evidence_record_invalid")
        source_path = _portable_reference_path(record.get("source_path"))
        package_path = _portable_reference_path(record.get("package_path"))
        expected_identifier = (
            "FILE_"
            + source_path.upper().replace("/", "_").replace(".", "_")
        )
        if (
            package_path != f"evidence/{source_path}"
            or record.get("evidence_identifier") != expected_identifier
            or record.get("evidence_identifier") in evidence_ids
            or source_path in evidence_sources
            or package_path in evidence_paths
            or package_path not in seen
        ):
            raise IVVPError("evidence_inventory_linkage_invalid")
        path = (package / package_path).resolve(strict=False)
        if (
            record.get("status") != "PRESENT"
            or not path.is_relative_to(package)
            or not path.is_file()
            or path.is_symlink()
            or not HEX64.fullmatch(str(record.get("sha256", "")))
            or not isinstance(record.get("size_bytes"), int)
            or isinstance(record.get("size_bytes"), bool)
            or record["size_bytes"] <= 0
            or record.get("sha256") != file_sha256(path)
            or record.get("size_bytes") != path.stat().st_size
        ):
            raise IVVPError(
                f"stale_or_substituted_evidence:{package_path}"
            )
        evidence_ids.add(record["evidence_identifier"])
        evidence_sources.add(source_path)
        evidence_paths.add(package_path)
    expected_evidence_sources = set(EVIDENCE_PATHS)
    expected_evidence_paths = {
        f"evidence/{relative}" for relative in EVIDENCE_PATHS
    }
    if (
        evidence_sources != expected_evidence_sources
        or evidence_paths != expected_evidence_paths
    ):
        raise IVVPError("evidence_inventory_coverage_invalid")
    if (
        inventory.get("repository_commit") != identity["repository_commit"]
        or inventory.get("measured_baseline_identifier")
        != identity["measured_baseline_identifier"]
        or inventory.get("runtime_identity") != identity["runtime_identity"]
    ):
        raise IVVPError("evidence_inventory_identity_mismatch")
    if manifest.get("claims_digest") != claims["claims_digest"] or manifest.get("traceability_digest") != trace["traceability_digest"] or manifest.get("evidence_inventory_digest") != inventory["evidence_inventory_digest"]: raise IVVPError("manifest_traceability_binding_invalid")
    baseline_store = read_json(package / "evidence/sbp_lex/runtime/approved_runtime_baselines.json", label="baseline_store"); baseline = approved_baseline(validate_baseline_store(baseline_store))
    if baseline["baseline_identifier"] != identity["measured_baseline_identifier"] or baseline["runtime_identity"] != identity["runtime_identity"] or baseline["measurement_digest"] != identity["measurement_digest"]: raise IVVPError("stale_measured_identity")
    _verify_local_trust_evidence(package, identity)
    r2, r2_artifacts = _verify_r2_evidence(package, identity)
    _verify_claim_repository_links(claim_items, r2_artifacts)
    _verify_formal_evidence(package, r2_artifacts)
    _verify_recovery_evidence(package)
    _verify_r3_evidence(package, identity, r2)
    _verify_runtime_evidence(package, identity, baseline_store)
    commands = _load(package, "VERIFICATION_COMMANDS.json"); command_items = commands.get("commands")
    if (
        set(commands) != COMMAND_PACK_FIELDS
        or commands.get("command_pack_version") != R4_VERSION
        or not isinstance(command_items, list)
        or not command_items
        or commands.get("command_pack_digest")
        != generate_digest({"commands": command_items})
    ):
        raise IVVPError("verification_command_pack_invalid")
    command_ids: set[str] = set()
    for item in command_items:
        command = item.get("command") if isinstance(item, Mapping) else None
        approved_command_shape = (
            isinstance(command, str)
            and (
                command.startswith("python -m sbp_lex.")
                or command
                == "scripts\\run_double_triple_assurance.bat"
            )
        )
        if (
            not isinstance(item, Mapping)
            or set(item) != COMMAND_RECORD_FIELDS
            or not isinstance(item.get("command_identifier"), str)
            or not item["command_identifier"]
            or item["command_identifier"] in command_ids
            or not approved_command_shape
            or any(token in item["command"] for token in ("\n", "\r", ";", "|", "&", ">", "<"))
            or not isinstance(item.get("expected_output"), str)
            or not item["expected_output"]
            or item.get("mutates_tracked_repository_state") is not False
        ):
            raise IVVPError("verification_command_pack_invalid")
        command_ids.add(item["command_identifier"])
    if repository_root is not None:
        def git(*args: str) -> str:
            result = subprocess.run(
                ["git", *args],
                cwd=repository_root,
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0 or result.stderr.strip():
                raise IVVPError("repository_verification_unavailable")
            return result.stdout.strip()

        def git_bytes(*args: str) -> bytes:
            result = subprocess.run(
                ["git", *args],
                cwd=repository_root,
                capture_output=True,
                text=False,
                check=False,
            )
            if result.returncode != 0 or result.stderr.strip():
                raise IVVPError("repository_verification_unavailable")
            return result.stdout

        if normalize_repository_identity(
            git("remote", "get-url", "origin")
        ) != REPOSITORY_IDENTITY:
            raise IVVPError("foreign_repository")
        if git("branch", "--show-current") != "main":
            raise IVVPError("noncanonical_branch")
        if git(
            "rev-parse",
            "--abbrev-ref",
            "--symbolic-full-name",
            "@{upstream}",
        ) != CANONICAL_UPSTREAM:
            raise IVVPError("noncanonical_upstream")
        if git(
            "status", "--porcelain=v1", "--untracked-files=all",
        ):
            raise IVVPError("tracked_working_tree_dirty")
        repository_head = git("rev-parse", "HEAD")
        evidence_source_commit = identity["repository_commit"]
        _verify_repository_handoff_lineage(
            repository_root,
            evidence_source_commit,
            repository_head,
        )
        git(
            "merge-base",
            "--is-ancestor",
            identity["trusted_repository_anchor_commit"],
            evidence_source_commit,
        )
        git(
            "merge-base",
            "--is-ancestor",
            evidence_source_commit,
            "HEAD",
        )
        tree = git(
            "rev-parse", f"{evidence_source_commit}^{{tree}}",
        )
        if tree != identity["git_tree_identity"]:
            raise IVVPError("repository_tree_mismatch")
        anchor_tree = git(
            "rev-parse",
            f"{identity['trusted_repository_anchor_commit']}^{{tree}}",
        )
        if anchor_tree != identity["trusted_repository_anchor_tree"]:
            raise IVVPError("repository_anchor_tree_mismatch")
        for record in r2_artifacts:
            if record.get("creation_relationship") == "GENERATED_EVIDENCE":
                continue
            relative = _portable_reference_path(record.get("path"))
            revision = f"{evidence_source_commit}:{relative}"
            if git("rev-parse", revision) != record.get("repository_blob"):
                raise IVVPError(
                    f"repository_artifact_blob_mismatch:{relative}"
                )
            raw = git_bytes("show", revision)
            if (
                sha256(raw).hexdigest()
                != record.get("repository_blob_sha256")
                or len(raw) != record.get("repository_blob_size_bytes")
            ):
                raise IVVPError(
                    f"repository_artifact_content_mismatch:{relative}"
                )
    return {"status": "R4_IVVP_VALID", "package_identity": package_identity, "evidence_items": len(evidence), "claims": len(claim_items), "traceability_items": len(trace_items)}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify detached Desktop V1 IVVP"); parser.add_argument("package", nargs="?", type=Path, default=Path("validation_package")); parser.add_argument("--repository-root", type=Path); parser.add_argument("--expected-signer-fingerprint"); args = parser.parse_args(argv)
    result = verify_package(args.package, repository_root=args.repository_root, expected_signer_fingerprint=args.expected_signer_fingerprint)
    print("R4_IVVP_VALID"); print(f"package_identity={result['package_identity']}"); print(f"evidence_items={result['evidence_items']}"); print(f"claims={result['claims']}")
    return 0


if __name__ == "__main__": raise SystemExit(main())
