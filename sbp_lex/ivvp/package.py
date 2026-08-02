from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence

from sbp_lex.custody.assurance import build_profile, validate_profile
from sbp_lex.custody.common import atomic_json as write_custody_json
from sbp_lex.api.schema_validation import loads_strict_json
from sbp_lex.formal.assurance import (
    validate_artifact as validate_formal_artifact,
    write_artifact as write_formal_artifact,
)
from sbp_lex.local_trust.manifest import repository_root_from
from sbp_lex.local_trust.paths import resolve_local_trust_path
from sbp_lex.persistence.integrity_store import (
    DEFAULT_STORE_PATH,
    resolve_integrity_store_path,
)
from sbp_lex.recovery.common import atomic_json as write_recovery_json
from sbp_lex.recovery.inventory import (
    DEFAULT_ARTIFACT_SPECS,
    build_inventory,
)
from sbp_lex.recovery.recovery_drill import run_recovery_drill
from sbp_lex.runtime.measured_startup import (
    DEFAULT_STATE_ROOT,
    approved_baseline,
    configured_baseline_path,
    load_baseline_store,
    validate_baseline_store,
    verify_startup_attestation,
)
from sbp_lex.security.pqc import (
    generate_digest,
    trusted_signing_key_fingerprint,
)
from sbp_lex.supply_chain.assurance import build_bundle as build_r2_bundle
from sbp_lex.supply_chain.provenance import collect_repository_provenance

from .common import (
    DESKTOP_SCOPE,
    EVIDENCE_PATHS,
    REPOSITORY_IDENTITY,
    R4_VERSION,
    IVVPError,
    file_sha256,
    seal,
    write_json,
)

DEFAULT_PACKAGE = Path("validation_package")


def _recognized_existing_package(path: Path) -> bool:
    manifest_path = path / "PACKAGE_MANIFEST.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        return False
    try:
        raw = manifest_path.read_bytes()
        if not raw or len(raw) > 64 * 1024 * 1024:
            return False
        wrapper = loads_strict_json(raw.decode("utf-8"))
    except Exception:
        return False
    if not isinstance(wrapper, Mapping) or set(wrapper) != {
        "payload",
        "payload_digest",
        "integrity_signature",
    }:
        return False
    payload = wrapper.get("payload")
    return (
        isinstance(payload, Mapping)
        and payload.get("manifest_version") == R4_VERSION
        and payload.get("desktop_scope") == DESKTOP_SCOPE
        and payload.get("repository_identity") == REPOSITORY_IDENTITY
        and payload.get("package_status") == "R4_IVVP_READY"
        and isinstance(payload.get("package_files"), list)
    )


def _identity(root: Path) -> dict[str, Any]:
    repository = collect_repository_provenance(root)
    baseline = approved_baseline(
        validate_baseline_store(load_baseline_store(configured_baseline_path()))
    )
    value = {
        "identity_version": R4_VERSION, "repository_name": "SBP-LEX Dual V6 Desktop V1",
        "canonical_designation": "SBP_LEX_DUAL_V6_DESKTOP_V1",
        "repository_identity": REPOSITORY_IDENTITY, "repository_commit": repository["repository_commit"],
        "git_tree_identity": repository["repository_tree"], "repository_digest": repository["repository_digest"],
        "trusted_repository_anchor_commit": repository["trusted_repository_anchor_commit"],
        "trusted_repository_anchor_tree": repository["trusted_repository_anchor_tree"],
        "trusted_signing_key_fingerprint": trusted_signing_key_fingerprint(),
        "measured_baseline_identifier": baseline["baseline_identifier"], "measurement_digest": baseline["measurement_digest"],
        "runtime_identity": baseline["runtime_identity"], "desktop_scope": DESKTOP_SCOPE,
    }
    value["identity_digest"] = generate_digest(value)
    return value


def _claims(identity: Mapping[str, Any]) -> dict[str, Any]:
    specs = [
        ("CLAIM_H7_EXECUTION_INTEGRITY", "H7 enforces deterministic capability lifecycle and execution integrity.", "sbp_lex/execution/capability.py", "H7_DETERMINISTIC_EXECUTION_INTEGRITY_REPORT.md", "tests/test_h7_deterministic_execution_integrity.py"),
        ("CLAIM_PHQ_FORMAL_ASSURANCE", "PHQ provides detached formal architectural verification without authority.", "sbp_lex/formal/verifier.py", "PHQ_FORMAL_DETERMINISTIC_ARCHITECTURE_REPORT.md", "tests/test_phq_formal_deterministic_architecture.py"),
        ("CLAIM_R1_RECOVERY", "R1 provides fail-closed canonical backup and staged restore assurance.", "sbp_lex/recovery/restore.py", "R1_CANONICAL_BACKUP_RECOVERY_RESTORE_INTEGRITY_REPORT.md", "tests/test_r1_canonical_backup_recovery.py"),
        ("CLAIM_R2_SUPPLY_CHAIN", "R2 verifies repository, dependency, build, and artefact provenance offline.", "sbp_lex/supply_chain/provenance.py", "R2_SUPPLY_CHAIN_BUILD_PROVENANCE_REPORT.md", "tests/test_r2_supply_chain_build_provenance.py"),
        ("CLAIM_R3_CUSTODY", "R3 provides deterministic external-custody and recovery-media assurance records.", "sbp_lex/custody/assurance.py", "R3_EXTERNAL_CUSTODY_OPERATIONAL_RECOVERY_REPORT.md", "tests/test_r3_external_custody_recovery.py"),
        ("CLAIM_DOUBLE_TRIPLE_HANDOVER", "The Double Triple gate requires one complete suite, three fresh linkage runs, and source, evidence, and repository-bound package assurance.", "sbp_lex/assurance/double_triple.py", "DOUBLE_TRIPLE_PRE_HANDOVER_ASSURANCE_REPORT.md", "tests/test_double_triple_assurance.py"),
        ("CLAIM_LOCAL_TRUST", "Local Trust protected evidence currently validates with no unexplained changes.", "sbp_lex/local_trust/evidence_chain_validator.py", "PHASE_18_7D_LOCAL_EVIDENCE_CHAIN_REPORT.md", "tests/test_phase_18_7d_local_evidence_chain.py"),
        ("CLAIM_CONSTITUTIONAL_GATES", "Constitutional Gates enforce the declared local assurance conditions.", "sbp_lex/local_trust/constitutional_gates.py", "PHASE_18_7E_2_CONSTITUTIONAL_ENFORCEMENT_GATES_REPORT.md", "tests/test_phase_18_7e_2_constitutional_enforcement_gates.py"),
        ("CLAIM_TOOLCHAIN_GUARD", "Toolchain Guard validates the approved local toolchain and dependencies.", "sbp_lex/local_trust/toolchain_guard.py", "PHASE_18_7E_3_TOOLCHAIN_GUARD_REPORT.md", "tests/test_phase_18_7e_3_toolchain_guard.py"),
        ("CLAIM_RELEASE_INTEGRITY", "Release Integrity validates the bounded release evidence bundle.", "sbp_lex/local_trust/release_integrity.py", "PHASE_18_7F_RELEASE_INTEGRITY_PACKAGE_REPORT.md", "tests/test_phase_18_7f_release_integrity_package.py"),
        ("CLAIM_CAPSTONE", "The Local Trust capstone validates against its bound evidence.", "sbp_lex/local_trust/local_trust_capstone.py", "PHASE_18_7E_4_25_YEAR_LOCAL_TRUST_CAPSTONE_REPORT.md", "tests/test_phase_18_7e_4_local_trust_capstone.py"),
        ("CLAIM_RUNTIME_REPLAY", "Recorded runtime execution passes and deterministic replay has zero mismatches.", "main.py", "RUNTIME_REPLAY_EVIDENCE.json", "tests/test_adversarial_runtime.py"),
    ]
    claims = [{"claim_identifier": cid, "engineering_claim": claim, "implementation_reference": impl, "verification_source": test, "supporting_reports": [report], "supporting_tests": [test], "evidence_status": "SUPPORTED"} for cid, claim, impl, report, test in specs]
    return {"register_version": R4_VERSION, "repository_commit": identity["repository_commit"], "measured_baseline_identifier": identity["measured_baseline_identifier"], "runtime_identity": identity["runtime_identity"], "claims": claims, "claims_digest": generate_digest({"claims": claims})}


def _traceability(identity: Mapping[str, Any]) -> dict[str, Any]:
    entries = [
        ("H7", "H7_DETERMINISTIC_EXECUTION_INTEGRITY_REPORT.md", "targeted tests and report hash"),
        ("PHQ", "phq_formal_architecture_assurance.json", "formal assurance validation"),
        ("R1", "r1_recovery_drill.json", "recovery drill and package validation"),
        ("R2", "r2_offline_verification.json", "offline supply-chain validation"),
        ("R3", "r3_operational_custody_assurance.json", "custody profile validation"),
        ("DOUBLE_TRIPLE", "DOUBLE_TRIPLE_PRE_HANDOVER_ASSURANCE_REPORT.md", "complete suite, three fresh linkage runs, and terminal repository-bound package gate"),
        ("LOCAL_TRUST", "local_evidence_chain.json", "evidence-chain compare"),
        ("CONSTITUTIONAL_GATES", "local_constitutional_gates.json", "constitutional gate validation"),
        ("TOOLCHAIN_GUARD", "local_toolchain_guard.json", "toolchain validation"),
        ("RELEASE_INTEGRITY", "RELEASE_MANIFEST.json", "release-integrity validation"),
        ("CAPSTONE", "local_trust_25_year_capstone.json", "capstone validation"),
        ("RUNTIME_REPLAY", "RUNTIME_REPLAY_EVIDENCE.json", "signed recorded runtime and replay result"),
    ]
    items = [{"evidence_identifier": f"EVIDENCE_{layer}", "assurance_layer": layer, "originating_report": report, "verification_method": method, "current_status": "VERIFIED"} for layer, report, method in entries]
    return {"traceability_version": R4_VERSION, "repository_commit": identity["repository_commit"], "measured_baseline_identifier": identity["measured_baseline_identifier"], "runtime_identity": identity["runtime_identity"], "evidence_items": items, "traceability_digest": generate_digest({"evidence_items": items})}


def _commands() -> dict[str, Any]:
    commands = [
        ("ivvp_verify", "python -m sbp_lex.ivvp.verifier validation_package --expected-signer-fingerprint EXPECTED_64_HEX_FROM_SEPARATE_CHANNEL", "R4_IVVP_VALID"),
        ("measured_startup", "python -m sbp_lex.runtime.measured_startup validate", "MEASURED_STARTUP_APPROVED"),
        ("local_trust", "python -m sbp_lex.local_trust.manifest validate", "LOCAL_TRUST_VALID"),
        ("evidence_compare", "python -m sbp_lex.local_trust.evidence_chain compare", "changed_evidence_items=0"),
        ("constitutional_gates", "python -m sbp_lex.local_trust.constitutional_gates validate", "CONSTITUTIONAL_GATES_PASS"),
        ("toolchain_guard", "python -m sbp_lex.local_trust.toolchain_guard validate", "TOOLCHAIN_GUARD_PASS"),
        ("release_integrity", "python -m sbp_lex.local_trust.release_integrity validate", "RELEASE_INTEGRITY_PASS"),
        ("capstone", "python -m sbp_lex.local_trust.local_trust_capstone validate", "LOCAL_TRUST_CAPSTONE_PASS"),
        ("r2_offline", "python -m sbp_lex.supply_chain.offline_verify", "R2_SUPPLY_CHAIN_ASSURANCE_PASS"),
        ("r3_custody", "python -m sbp_lex.custody.assurance validate", "R3_CUSTODY_ASSURANCE_PASS"),
        ("double_triple_handover", "scripts\\run_double_triple_assurance.bat", "DOUBLE_TRIPLE_HANDOVER_ASSURANCE_PASS"),
    ]
    records = [{"command_identifier": cid, "command": command, "expected_output": output, "mutates_tracked_repository_state": False} for cid, command, output in commands]
    return {"command_pack_version": R4_VERSION, "commands": records, "command_pack_digest": generate_digest({"commands": records})}


def collect_runtime_replay(
    root: Path,
    identity: Mapping[str, Any],
) -> dict[str, Any]:
    def run(*args: str) -> tuple[dict[str, Any], str]:
        completed = subprocess.run([sys.executable, "main.py", *args], cwd=root, capture_output=True, text=True, check=False, timeout=120)
        if completed.returncode != 0: raise IVVPError("runtime_evidence_collection_failed")
        try: value = json.loads(completed.stdout)
        except json.JSONDecodeError as exc: raise IVVPError("runtime_evidence_invalid") from exc
        return value, generate_digest({"stdout": completed.stdout})
    def current_attestation() -> dict[str, Any]:
        path = _measured_state_root() / "startup.attestation.json"
        try:
            value = loads_strict_json(path.read_text("utf-8"))
        except Exception as exc:
            raise IVVPError("runtime_startup_attestation_unavailable") from exc
        if (
            not isinstance(value, dict)
            or not verify_startup_attestation(value)
        ):
            raise IVVPError("runtime_startup_attestation_invalid")
        return value

    runtime, runtime_digest = run()
    runtime_attestation = current_attestation()
    replay, replay_digest = run("replay")
    replay_attestation = current_attestation()
    if runtime.get("decision") != "ALLOW" or runtime.get("execution_result") != "EXECUTE" or runtime.get("convergence_matched") is not True: raise IVVPError("runtime_result_failed")
    if replay.get("matched") is not True or replay.get("mismatches") != []: raise IVVPError("replay_result_failed")
    expected = {
        "measured_runtime_identity": identity["runtime_identity"],
        "approved_runtime_baseline": identity["measured_baseline_identifier"],
        "runtime_measurement_digest": identity["measurement_digest"],
        "measured_startup_status": "MEASURED_STARTUP_APPROVED",
    }
    for source in (runtime, replay):
        if any(source.get(key) != value for key, value in expected.items()):
            raise IVVPError("runtime_measured_startup_linkage_failed")
        if (
            not isinstance(source.get("startup_attestation_digest"), str)
            or len(source["startup_attestation_digest"]) != 64
            or not isinstance(source.get("measured_startup_sequence"), int)
            or isinstance(source["measured_startup_sequence"], bool)
            or source["measured_startup_sequence"] <= 0
        ):
            raise IVVPError("runtime_measured_startup_linkage_failed")
    if replay["measured_startup_sequence"] <= runtime["measured_startup_sequence"]:
        raise IVVPError("runtime_replay_startup_sequence_invalid")
    if (
        generate_digest(runtime_attestation)
        != runtime["startup_attestation_digest"]
        or generate_digest(replay_attestation)
        != replay["startup_attestation_digest"]
    ):
        raise IVVPError("runtime_startup_attestation_linkage_failed")
    return {
        "evidence_version": R4_VERSION,
        "runtime_result": "PASS",
        "runtime_decision": runtime["decision"],
        "execution_result": runtime["execution_result"],
        "convergence_matched": True,
        "runtime_output_digest": runtime_digest,
        "runtime_identity": runtime["measured_runtime_identity"],
        "measured_baseline_identifier": runtime["approved_runtime_baseline"],
        "measurement_digest": runtime["runtime_measurement_digest"],
        "runtime_startup_attestation_digest": runtime["startup_attestation_digest"],
        "runtime_startup_sequence": runtime["measured_startup_sequence"],
        "runtime_startup_attestation": runtime_attestation,
        "replay_result": "PASS",
        "replay_count": replay["replay_count"],
        "replay_matched": True,
        "replay_mismatches": 0,
        "replay_output_digest": replay_digest,
        "replay_runtime_identity": replay["measured_runtime_identity"],
        "replay_measured_baseline_identifier": replay["approved_runtime_baseline"],
        "replay_measurement_digest": replay["runtime_measurement_digest"],
        "replay_startup_attestation_digest": replay["startup_attestation_digest"],
        "replay_startup_sequence": replay["measured_startup_sequence"],
        "replay_startup_attestation": replay_attestation,
    }


def _copy_evidence(
    root: Path,
    stage: Path,
    *,
    evidence_sources: Mapping[str, Path],
) -> list[dict[str, Any]]:
    records = []
    for relative in EVIDENCE_PATHS:
        if relative in evidence_sources:
            source = evidence_sources[relative]
        elif relative == "sbp_lex/runtime/approved_runtime_baselines.json":
            source = configured_baseline_path()
        else:
            source = resolve_local_trust_path(root, relative)
        if source.is_symlink() or not source.is_file(): raise IVVPError(f"missing_evidence:{relative}")
        destination = stage / "evidence" / relative; destination.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(source, destination)
        records.append({"evidence_identifier": "FILE_" + relative.upper().replace("/", "_").replace(".", "_"), "source_path": relative, "package_path": destination.relative_to(stage).as_posix(), "sha256": file_sha256(destination), "size_bytes": destination.stat().st_size, "status": "PRESENT"})
    records.sort(key=lambda item: item["package_path"])
    return records


def _measured_state_root() -> Path:
    configured = os.environ.get(
        "SBP_LEX_MEASURED_STARTUP_STATE_ROOT",
        str(DEFAULT_STATE_ROOT),
    )
    return Path(configured).resolve(strict=False)


def _recovery_source_overrides(
    root: Path,
    formal_path: Path,
) -> dict[str, Path]:
    state_root = _measured_state_root()
    values = {
        "security.integrity_ledger": resolve_integrity_store_path(
            DEFAULT_STORE_PATH,
        ),
        "measured.baseline_store": configured_baseline_path(),
        "measured.rollback_anchor": state_root / "measurement.anchor.json",
        "measured.startup_attestation": state_root / "startup.attestation.json",
        "formal.phq_assurance": formal_path,
    }
    overrides: dict[str, Path] = {}
    by_name = {spec.logical_name: spec for spec in DEFAULT_ARTIFACT_SPECS}
    for logical_name, source in values.items():
        overrides[by_name[logical_name].source_path] = source
    integrity = values["security.integrity_ledger"]
    overrides[
        by_name["security.integrity_checkpoint"].source_path
    ] = integrity.with_suffix(integrity.suffix + ".checkpoint.json")
    for spec in DEFAULT_ARTIFACT_SPECS:
        if (
            spec.source_path.startswith("outputs/")
            and spec.source_path not in overrides
        ):
            overrides[spec.source_path] = resolve_local_trust_path(
                root, spec.source_path,
            )
    return overrides


def _generate_current_evidence(
    root: Path,
    generation_root: Path,
) -> dict[str, Path]:
    outputs = generation_root / "outputs"
    formal_relative = Path(
        "outputs/phq_formal_architecture_assurance.json",
    )
    redirected_formal = resolve_local_trust_path(root, formal_relative)
    repository_formal = (root / formal_relative).resolve(strict=False)
    if redirected_formal != repository_formal:
        if redirected_formal.is_symlink() or not redirected_formal.is_file():
            raise IVVPError("redirected_formal_evidence_missing")
        try:
            formal_value = loads_strict_json(
                redirected_formal.read_text("utf-8"),
            )
        except Exception as exc:
            raise IVVPError("redirected_formal_evidence_invalid") from exc
        if not isinstance(formal_value, Mapping):
            raise IVVPError("redirected_formal_evidence_invalid")
        validate_formal_artifact(formal_value, root)
        formal_path = redirected_formal
    else:
        formal_path = outputs / formal_relative.name
        write_formal_artifact(formal_path, root)

    recovery_inventory_path = outputs / "recovery_critical_inventory.json"
    recovery_inventory = build_inventory(
        root,
        source_overrides=_recovery_source_overrides(root, formal_path),
    )
    write_recovery_json(recovery_inventory_path, recovery_inventory)

    recovery_drill_path = outputs / "r1_recovery_drill.json"
    recovery_drill = run_recovery_drill(
        generation_root / "r1_recovery_drill_workspace",
    )
    write_recovery_json(recovery_drill_path, recovery_drill)

    artifact_sources = {
        "outputs/phq_formal_architecture_assurance.json": formal_path,
        "outputs/recovery_critical_inventory.json": recovery_inventory_path,
        "outputs/r1_recovery_drill.json": recovery_drill_path,
    }
    r2_sbom_path = outputs / "r2_software_bill_of_materials.json"
    r2_manifest_path = outputs / "r2_deterministic_build_manifest.json"
    r2_verification_path = outputs / "r2_offline_verification.json"
    build_r2_bundle(
        root,
        sbom_path=r2_sbom_path,
        manifest_path=r2_manifest_path,
        verification_path=r2_verification_path,
        artifact_sources=artifact_sources,
    )

    r3_path = outputs / "r3_operational_custody_assurance.json"
    r3 = build_profile(
        root,
        baseline_path=configured_baseline_path(),
        r2_manifest_path=r2_manifest_path,
    )
    write_custody_json(r3_path, r3)
    validate_profile(
        r3,
        root,
        baseline_path=configured_baseline_path(),
        r2_manifest_path=r2_manifest_path,
    )
    artifact_sources.update({
        "outputs/r2_software_bill_of_materials.json": r2_sbom_path,
        "outputs/r2_deterministic_build_manifest.json": r2_manifest_path,
        "outputs/r2_offline_verification.json": r2_verification_path,
        "outputs/r3_operational_custody_assurance.json": r3_path,
        "runtime_artifacts/measured_startup/measurement.anchor.json":
            _measured_state_root() / "measurement.anchor.json",
        "runtime_artifacts/measured_startup/startup.attestation.json":
            _measured_state_root() / "startup.attestation.json",
    })
    return artifact_sources


def _documents(identity: Mapping[str, Any]) -> dict[str, str]:
    common = f"Repository commit: `{identity['repository_commit']}`\n\nTrusted repository anchor: `{identity['trusted_repository_anchor_commit']}`\n\nTrusted ML-DSA signer fingerprint: `{identity['trusted_signing_key_fingerprint']}`\n\nMeasured baseline: `{identity['measured_baseline_identifier']}`\n\nRuntime identity: `{identity['runtime_identity']}`\n"
    return {
        "INDEPENDENT_VERIFICATION_GUIDE.md": "# Independent Verification Guide\n\nThis package is a detached technical evidence set. Obtain both the base64-encoded trusted ML-DSA public verification key and its SHA-256 fingerprint through a separate authenticated channel; never establish trust from values supplied only inside this package. Configure `SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY`, then pass the separately obtained fingerprint to the verifier. Verify `PACKAGE_MANIFEST.json` first, then review identity, claims, traceability, evidence inventory, and recorded runtime/replay evidence. Expected validation status is `R4_IVVP_VALID`. Results establish implemented engineering evidence, not certification or mathematical proof.\n\n" + common,
        "QUICK_START.md": "# Assessor Quick Start\n\nExpected duration: 10-20 minutes.\n\n1. Obtain the base64-encoded trusted ML-DSA public key and its SHA-256 fingerprint through a separate authenticated channel.\n2. Set `SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY` to that public key; do not copy the key from this package.\n3. Run `python -m sbp_lex.ivvp.verifier validation_package --expected-signer-fingerprint EXPECTED_64_HEX_FROM_SEPARATE_CHANNEL` after replacing the fingerprint placeholder.\n4. Confirm `R4_IVVP_VALID`.\n5. Review claims and traceability; unsupported claims must never be treated as verified.\n6. If repository access is available, repeat verification with `--repository-root PATH_TO_CANONICAL_CHECKOUT` to recompute tracked artifacts from the bound Git commit.\n\n" + common,
        "VALIDATION_SUMMARY.md": "# Validation Summary\n\nExecutive reviewers: the package provides bounded identity and evidence status.\n\nEngineers: use hashes, commands, and traceability to reproduce validation.\n\nResearchers: PHQ is detached formal verification, not a claim of universal proof.\n\nUniversity assessors: limitations and assumptions remain explicit; no certification is claimed.\n\n" + common,
    }


def _package_file_inventory(stage: Path) -> list[dict[str, Any]]:
    records = []
    for path in sorted(stage.rglob("*"), key=lambda item: item.relative_to(stage).as_posix()):
        if path.is_file() and path.name != "PACKAGE_MANIFEST.json": records.append({"path": path.relative_to(stage).as_posix(), "sha256": file_sha256(path), "size_bytes": path.stat().st_size})
    return records


def _safe_package_target(root: Path, destination: Path) -> Path:
    repository = root.resolve()
    selected = destination if destination.is_absolute() else repository / destination
    target = selected.resolve(strict=False)
    filesystem_root = Path(target.anchor)
    if (
        target == filesystem_root
        or target == repository
        or repository.is_relative_to(target)
    ):
        raise IVVPError("unsafe_package_destination")
    if selected.is_symlink() or target.is_symlink():
        raise IVVPError("package_destination_symlink")
    if target.exists():
        if (
            not target.is_dir()
            or not _recognized_existing_package(target)
        ):
            raise IVVPError("unrecognized_existing_package_destination")
    return target


def build_package(
    root: Path,
    destination: Path = DEFAULT_PACKAGE,
) -> dict[str, Any]:
    target = _safe_package_target(root, destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    stage = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
    stage.mkdir()
    previous: Path | None = None
    try:
        identity = _identity(root)
        runtime_record = collect_runtime_replay(root, identity)
        with tempfile.TemporaryDirectory(
            prefix="sbp-lex-r4-evidence-",
        ) as temporary:
            evidence_sources = _generate_current_evidence(
                root, Path(temporary),
            )
            evidence = _copy_evidence(
                root,
                stage,
                evidence_sources=evidence_sources,
            )
        claims = _claims(identity); traceability = _traceability(identity); commands = _commands()
        write_json(stage / "REPOSITORY_IDENTITY.json", identity); write_json(stage / "ENGINEERING_CLAIMS_REGISTER.json", claims); write_json(stage / "EVIDENCE_TRACEABILITY_INDEX.json", traceability); write_json(stage / "VERIFICATION_COMMANDS.json", commands)
        write_json(stage / "RUNTIME_REPLAY_EVIDENCE.json", runtime_record)
        inventory = {"inventory_version": R4_VERSION, "repository_commit": identity["repository_commit"], "measured_baseline_identifier": identity["measured_baseline_identifier"], "runtime_identity": identity["runtime_identity"], "evidence": evidence, "evidence_inventory_digest": generate_digest({"evidence": evidence})}; write_json(stage / "EVIDENCE_INVENTORY.json", inventory)
        for name, text in _documents(identity).items(): (stage / name).write_text(text, encoding="utf-8", newline="\n")
        files = _package_file_inventory(stage)
        manifest_payload = {"manifest_version": R4_VERSION, "desktop_scope": DESKTOP_SCOPE, "repository_identity": REPOSITORY_IDENTITY, "repository_commit": identity["repository_commit"], "git_tree_identity": identity["git_tree_identity"], "trusted_repository_anchor_commit": identity["trusted_repository_anchor_commit"], "trusted_repository_anchor_tree": identity["trusted_repository_anchor_tree"], "trusted_signing_key_fingerprint": identity["trusted_signing_key_fingerprint"], "measured_baseline_identifier": identity["measured_baseline_identifier"], "runtime_identity": identity["runtime_identity"], "identity_digest": identity["identity_digest"], "claims_digest": claims["claims_digest"], "traceability_digest": traceability["traceability_digest"], "evidence_inventory_digest": inventory["evidence_inventory_digest"], "package_files": files, "package_status": "R4_IVVP_READY"}
        manifest_payload["package_identity"] = generate_digest(manifest_payload); write_json(stage / "PACKAGE_MANIFEST.json", seal(manifest_payload))
        from .verifier import verify_package
        result = verify_package(stage, repository_root=root)
        if target.exists():
            previous = target.with_name(
                f".{target.name}.{uuid.uuid4().hex}.previous"
            )
            os.replace(target, previous)
        try:
            os.replace(stage, target)
        except OSError:
            if previous is not None and previous.exists():
                os.replace(previous, target)
                previous = None
            raise
        if previous is not None:
            shutil.rmtree(previous)
            previous = None
        return result
    except Exception:
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=True)
        if (
            previous is not None
            and previous.exists()
            and not target.exists()
        ):
            os.replace(previous, target)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build deterministic Desktop V1 IVVP"); parser.add_argument("command", choices=("build", "validate", "show")); parser.add_argument("--path", type=Path, default=DEFAULT_PACKAGE); args = parser.parse_args(argv); root = repository_root_from()
    if args.command == "build": result = build_package(root, args.path)
    else:
        from .verifier import verify_package
        result = verify_package(root / args.path, repository_root=root)
    print("R4_IVVP_VALID")
    if args.command in {"build", "show"}: print(f"package_identity={result['package_identity']}"); print(f"evidence_items={result['evidence_items']}"); print(f"claims={result['claims']}")
    return 0


if __name__ == "__main__": raise SystemExit(main())
