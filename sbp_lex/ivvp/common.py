from __future__ import annotations

import json
import os
import uuid
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from sbp_lex.api.schema_validation import loads_strict_json
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

R4_VERSION = "R4_DESKTOP_V1_IVVP_V1"
R4_DOMAIN = "SBP_LEX_DESKTOP_V1_INDEPENDENT_VERIFICATION_PACKAGE"
DESKTOP_SCOPE = "SBP_LEX_DUAL_V6_DESKTOP_V1_LOCAL_PRIVATE_SINGLE_HOST_NO_NODE"
REPOSITORY_IDENTITY = "github.com/SBP0917/SBP_LEX_DUAL_V6"
EVIDENCE_PATHS = (
    "reports/H7_DETERMINISTIC_EXECUTION_INTEGRITY_REPORT.md",
    "reports/PHQ_FORMAL_DETERMINISTIC_ARCHITECTURE_REPORT.md",
    "reports/R1_CANONICAL_BACKUP_RECOVERY_RESTORE_INTEGRITY_REPORT.md",
    "reports/R2_SUPPLY_CHAIN_BUILD_PROVENANCE_REPORT.md",
    "reports/R3_EXTERNAL_CUSTODY_OPERATIONAL_RECOVERY_REPORT.md",
    "reports/DOUBLE_TRIPLE_PRE_HANDOVER_ASSURANCE_REPORT.md",
    "reports/PHASE_18_7E_2_CONSTITUTIONAL_ENFORCEMENT_GATES_REPORT.md",
    "reports/PHASE_18_7B_LOCAL_TRUST_ROOT_MANIFEST_REPORT.md",
    "reports/PHASE_18_7C_LOCAL_EXECUTION_ENVIRONMENT_TRUST_ENVELOPE_REPORT.md",
    "reports/PHASE_18_7D_LOCAL_EVIDENCE_CHAIN_REPORT.md",
    "reports/PHASE_18_7E_1_LOCAL_TRUST_REGRESSION_MATRIX_REPORT.md",
    "reports/PHASE_18_7E_3_TOOLCHAIN_GUARD_REPORT.md",
    "reports/PHASE_18_7E_4_25_YEAR_LOCAL_TRUST_CAPSTONE_REPORT.md",
    "reports/PHASE_18_7F_RELEASE_INTEGRITY_PACKAGE_REPORT.md",
    "reports/PHASE_18_7G_ADVERSARIAL_LOCAL_TRUST_NEGATIVE_TEST_HARNESS_REPORT.md",
    "reports/PHASE_18_8_UNIVERSITY_VALIDATION_DOSSIER_REPORT.md",
    "outputs/SBP_OPERATOR_ASSISTANT_V1_COMMIT_AND_TEST_REPORT.md",
    "outputs/local_trust_root_manifest.json",
    "outputs/local_execution_environment_trust_envelope.json",
    "outputs/local_evidence_chain.json",
    "outputs/local_trust_regression_matrix.json",
    "outputs/local_constitutional_gates.json",
    "outputs/local_toolchain_guard.json",
    "outputs/local_trust_25_year_capstone.json",
    "outputs/release_integrity_bundle/ARTIFACT_HASH_INDEX.json",
    "outputs/release_integrity_bundle/BOUNDARY_AND_SCOPE_LOCK.json",
    "outputs/release_integrity_bundle/CLAIMS_TO_EVIDENCE_SEED.json",
    "outputs/release_integrity_bundle/RELEASE_MANIFEST.json",
    "outputs/release_integrity_bundle/RELEASE_README.md",
    "outputs/release_integrity_bundle/VERIFICATION_COMMANDS.json",
    "outputs/adversarial_local_trust_negative_harness.json",
    "outputs/university_validation_dossier/DOSSIER_MANIFEST.json",
    "outputs/university_validation_dossier/EVIDENCE_ARTIFACT_INDEX.json",
    "outputs/university_validation_dossier/MASTER_CLAIMS_TO_EVIDENCE_INDEX.json",
    "outputs/university_validation_dossier/REVIEWER_VERIFICATION_COMMANDS.json",
    "outputs/university_validation_dossier/SCOPE_AND_EXCLUSIONS_LOCK.json",
    "outputs/university_validation_dossier/UNIVERSITY_HANDOFF_README.md",
    "outputs/university_validation_dossier/VALIDATION_QUESTIONS.json",
    "outputs/phq_formal_architecture_assurance.json",
    "outputs/recovery_critical_inventory.json",
    "outputs/r1_recovery_drill.json",
    "outputs/r2_software_bill_of_materials.json",
    "outputs/r2_deterministic_build_manifest.json",
    "outputs/r2_offline_verification.json",
    "outputs/r3_operational_custody_assurance.json",
    "sbp_lex/runtime/approved_runtime_baselines.json",
    "runtime_artifacts/measured_startup/measurement.anchor.json",
    "runtime_artifacts/measured_startup/startup.attestation.json",
    "README.md",
    "BASELINE_LOCK.md",
    "DESKTOP_V1_OPERATOR_RELEASE_LOCK.md",
)


class IVVPError(RuntimeError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"ivvp_failed:{reason}")


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def file_sha256(path: Path) -> str:
    digest = sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise IVVPError("evidence_read_failed") from exc
    return digest.hexdigest()


def read_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        if not raw or len(raw) > 64 * 1024 * 1024: raise ValueError
        value = loads_strict_json(raw.decode("utf-8"))
    except Exception as exc:
        raise IVVPError(f"{label}_invalid") from exc
    if not isinstance(value, dict): raise IVVPError(f"{label}_invalid")
    return value


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(canonical_bytes(value))


def seal(payload: Mapping[str, Any]) -> dict[str, Any]:
    copied = json.loads(json.dumps(payload))
    return {"payload": copied, "payload_digest": generate_digest(copied), "integrity_signature": sign_payload({"integrity_domain": R4_DOMAIN, "payload": copied})}


def unseal(value: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"payload", "payload_digest", "integrity_signature"}: raise IVVPError(f"{label}_schema_invalid")
    payload = value.get("payload")
    if not isinstance(payload, Mapping): raise IVVPError(f"{label}_payload_invalid")
    copied = json.loads(json.dumps(payload))
    if value.get("payload_digest") != generate_digest(copied): raise IVVPError(f"{label}_digest_invalid")
    if not verify_signature({"integrity_domain": R4_DOMAIN, "payload": copied}, value.get("integrity_signature", {})): raise IVVPError(f"{label}_signature_invalid")
    return copied
