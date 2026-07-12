from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence

from sbp_lex.local_trust.manifest import repository_root_from
from sbp_lex.runtime.measured_startup import approved_baseline, load_baseline_store, validate_baseline_store
from sbp_lex.security.pqc import generate_digest
from sbp_lex.supply_chain.provenance import collect_repository_provenance

from .common import DESKTOP_SCOPE, REPOSITORY_IDENTITY, R4_VERSION, IVVPError, file_sha256, seal, write_json

DEFAULT_PACKAGE = Path("validation_package")
EVIDENCE_PATHS = (
    "reports/H7_DETERMINISTIC_EXECUTION_INTEGRITY_REPORT.md",
    "reports/PHQ_FORMAL_DETERMINISTIC_ARCHITECTURE_REPORT.md",
    "reports/R1_CANONICAL_BACKUP_RECOVERY_RESTORE_INTEGRITY_REPORT.md",
    "reports/R2_SUPPLY_CHAIN_BUILD_PROVENANCE_REPORT.md",
    "reports/R3_EXTERNAL_CUSTODY_OPERATIONAL_RECOVERY_REPORT.md",
    "reports/PHASE_18_7E_2_CONSTITUTIONAL_ENFORCEMENT_GATES_REPORT.md",
    "reports/PHASE_18_7D_LOCAL_EVIDENCE_CHAIN_REPORT.md",
    "reports/PHASE_18_7E_3_TOOLCHAIN_GUARD_REPORT.md",
    "reports/PHASE_18_7E_4_25_YEAR_LOCAL_TRUST_CAPSTONE_REPORT.md",
    "reports/PHASE_18_7F_RELEASE_INTEGRITY_PACKAGE_REPORT.md",
    "outputs/local_trust_root_manifest.json",
    "outputs/local_evidence_chain.json",
    "outputs/local_constitutional_gates.json",
    "outputs/local_toolchain_guard.json",
    "outputs/local_trust_25_year_capstone.json",
    "outputs/release_integrity_bundle/RELEASE_MANIFEST.json",
    "outputs/adversarial_local_trust_negative_harness.json",
    "outputs/phq_formal_architecture_assurance.json",
    "outputs/recovery_critical_inventory.json",
    "outputs/r1_recovery_drill.json",
    "outputs/r2_software_bill_of_materials.json",
    "outputs/r2_deterministic_build_manifest.json",
    "outputs/r2_offline_verification.json",
    "outputs/r3_operational_custody_assurance.json",
    "sbp_lex/runtime/approved_runtime_baselines.json",
    "README.md",
    "BASELINE_LOCK.md",
    "DESKTOP_V1_OPERATOR_RELEASE_LOCK.md",
)


def _identity(root: Path) -> dict[str, Any]:
    repository = collect_repository_provenance(root)
    baseline = approved_baseline(validate_baseline_store(load_baseline_store(root / "sbp_lex/runtime/approved_runtime_baselines.json")))
    value = {
        "identity_version": R4_VERSION, "repository_name": "SBP-LEX Dual V6 Desktop V1",
        "canonical_designation": "SBP_LEX_DUAL_V6_DESKTOP_V1",
        "repository_identity": REPOSITORY_IDENTITY, "repository_commit": repository["repository_commit"],
        "git_tree_identity": repository["repository_tree"], "repository_digest": repository["repository_digest"],
        "measured_baseline_identifier": baseline["baseline_identifier"], "measurement_digest": baseline["measurement_digest"],
        "runtime_identity": baseline["runtime_identity"], "desktop_scope": DESKTOP_SCOPE,
    }
    value["identity_digest"] = generate_digest(value)
    return value


def _claims(identity: Mapping[str, Any]) -> dict[str, Any]:
    specs = [
        ("CLAIM_H7_EXECUTION_INTEGRITY", "H7 enforces deterministic capability lifecycle and execution integrity.", "sbp_lex/execution", "H7_DETERMINISTIC_EXECUTION_INTEGRITY_REPORT.md", "tests/test_h7_deterministic_execution_integrity.py"),
        ("CLAIM_PHQ_FORMAL_ASSURANCE", "PHQ provides detached formal architectural verification without authority.", "sbp_lex/formal", "PHQ_FORMAL_DETERMINISTIC_ARCHITECTURE_REPORT.md", "tests/test_phq_formal_deterministic_architecture.py"),
        ("CLAIM_R1_RECOVERY", "R1 provides fail-closed canonical backup and staged restore assurance.", "sbp_lex/recovery", "R1_CANONICAL_BACKUP_RECOVERY_RESTORE_INTEGRITY_REPORT.md", "tests/test_r1_canonical_backup_recovery.py"),
        ("CLAIM_R2_SUPPLY_CHAIN", "R2 verifies repository, dependency, build, and artefact provenance offline.", "sbp_lex/supply_chain", "R2_SUPPLY_CHAIN_BUILD_PROVENANCE_REPORT.md", "tests/test_r2_supply_chain_build_provenance.py"),
        ("CLAIM_R3_CUSTODY", "R3 provides deterministic external-custody and recovery-media assurance records.", "sbp_lex/custody", "R3_EXTERNAL_CUSTODY_OPERATIONAL_RECOVERY_REPORT.md", "tests/test_r3_external_custody_recovery.py"),
        ("CLAIM_LOCAL_TRUST", "Local Trust protected evidence currently validates with no unexplained changes.", "sbp_lex/local_trust", "PHASE_18_7D_LOCAL_EVIDENCE_CHAIN_REPORT.md", "tests/test_phase_18_7d_local_evidence_chain.py"),
        ("CLAIM_CONSTITUTIONAL_GATES", "Constitutional Gates enforce the declared local assurance conditions.", "sbp_lex/local_trust/constitutional_gates.py", "PHASE_18_7E_2_CONSTITUTIONAL_ENFORCEMENT_GATES_REPORT.md", "tests/test_phase_18_7e_2_constitutional_gates.py"),
        ("CLAIM_TOOLCHAIN_GUARD", "Toolchain Guard validates the approved local toolchain and dependencies.", "sbp_lex/local_trust/toolchain_guard.py", "PHASE_18_7E_3_TOOLCHAIN_GUARD_REPORT.md", "tests/test_phase_18_7e_3_toolchain_guard.py"),
        ("CLAIM_RELEASE_INTEGRITY", "Release Integrity validates the bounded release evidence bundle.", "sbp_lex/local_trust/release_integrity.py", "PHASE_18_7F_RELEASE_INTEGRITY_PACKAGE_REPORT.md", "tests/test_phase_18_7f_release_integrity_package.py"),
        ("CLAIM_CAPSTONE", "The Local Trust capstone validates against its bound evidence.", "sbp_lex/local_trust/local_trust_capstone.py", "PHASE_18_7E_4_25_YEAR_LOCAL_TRUST_CAPSTONE_REPORT.md", "tests/test_phase_18_7e_4_local_trust_capstone.py"),
        ("CLAIM_RUNTIME_REPLAY", "Recorded runtime execution passes and deterministic replay has zero mismatches.", "main.py", "RUNTIME_REPLAY_EVIDENCE.json", "tests/test_replay.py"),
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
        ("ivvp_verify", "python -m sbp_lex.ivvp.verifier validation_package", "R4_IVVP_VALID"),
        ("measured_startup", "python -m sbp_lex.runtime.measured_startup validate", "MEASURED_STARTUP_APPROVED"),
        ("local_trust", "python -m sbp_lex.local_trust.manifest validate", "LOCAL_TRUST_VALID"),
        ("evidence_compare", "python -m sbp_lex.local_trust.evidence_chain compare", "changed_evidence_items=0"),
        ("constitutional_gates", "python -m sbp_lex.local_trust.constitutional_gates validate", "CONSTITUTIONAL_GATES_PASS"),
        ("toolchain_guard", "python -m sbp_lex.local_trust.toolchain_guard validate", "TOOLCHAIN_GUARD_PASS"),
        ("release_integrity", "python -m sbp_lex.local_trust.release_integrity validate", "RELEASE_INTEGRITY_PASS"),
        ("capstone", "python -m sbp_lex.local_trust.local_trust_capstone validate", "LOCAL_TRUST_CAPSTONE_PASS"),
        ("r2_offline", "python -m sbp_lex.supply_chain.offline_verify", "R2_SUPPLY_CHAIN_ASSURANCE_PASS"),
        ("r3_custody", "python -m sbp_lex.custody.assurance validate", "R3_CUSTODY_ASSURANCE_PASS"),
    ]
    records = [{"command_identifier": cid, "command": command, "expected_output": output, "mutates_tracked_repository_state": False} for cid, command, output in commands]
    return {"command_pack_version": R4_VERSION, "commands": records, "command_pack_digest": generate_digest({"commands": records})}


def collect_runtime_replay(root: Path) -> dict[str, Any]:
    def run(*args: str) -> tuple[dict[str, Any], str]:
        completed = subprocess.run([sys.executable, "main.py", *args], cwd=root, capture_output=True, text=True, check=False, timeout=120)
        if completed.returncode != 0: raise IVVPError("runtime_evidence_collection_failed")
        try: value = json.loads(completed.stdout)
        except json.JSONDecodeError as exc: raise IVVPError("runtime_evidence_invalid") from exc
        return value, generate_digest({"stdout": completed.stdout})
    runtime, runtime_digest = run(); replay, replay_digest = run("replay")
    if runtime.get("decision") != "ALLOW" or runtime.get("execution_result") != "EXECUTE" or runtime.get("convergence_matched") is not True: raise IVVPError("runtime_result_failed")
    if replay.get("matched") is not True or replay.get("mismatches") != []: raise IVVPError("replay_result_failed")
    return {"evidence_version": R4_VERSION, "runtime_result": "PASS", "runtime_decision": runtime["decision"], "execution_result": runtime["execution_result"], "convergence_matched": True, "runtime_output_digest": runtime_digest, "replay_result": "PASS", "replay_count": replay["replay_count"], "replay_matched": True, "replay_mismatches": 0, "replay_output_digest": replay_digest}


def _copy_evidence(root: Path, stage: Path) -> list[dict[str, Any]]:
    records = []
    for relative in EVIDENCE_PATHS:
        source = root / relative
        if source.is_symlink() or not source.is_file(): raise IVVPError(f"missing_evidence:{relative}")
        destination = stage / "evidence" / relative; destination.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(source, destination)
        records.append({"evidence_identifier": "FILE_" + relative.upper().replace("/", "_").replace(".", "_"), "source_path": relative, "package_path": destination.relative_to(stage).as_posix(), "sha256": file_sha256(destination), "size_bytes": destination.stat().st_size, "status": "PRESENT"})
    records.sort(key=lambda item: item["package_path"])
    return records


def _documents(identity: Mapping[str, Any]) -> dict[str, str]:
    common = f"Repository commit: `{identity['repository_commit']}`\n\nMeasured baseline: `{identity['measured_baseline_identifier']}`\n\nRuntime identity: `{identity['runtime_identity']}`\n"
    return {
        "INDEPENDENT_VERIFICATION_GUIDE.md": "# Independent Verification Guide\n\nThis package is a detached technical evidence set. Verify `PACKAGE_MANIFEST.json` first, then review identity, claims, traceability, evidence inventory, and recorded runtime/replay evidence. Expected validation status is `R4_IVVP_VALID`. Results establish implemented engineering evidence, not certification or mathematical proof.\n\n" + common,
        "QUICK_START.md": "# Assessor Quick Start\n\nExpected duration: 10-20 minutes.\n\n1. Confirm the identity fields below.\n2. Run `python -m sbp_lex.ivvp.verifier validation_package`.\n3. Confirm `R4_IVVP_VALID`.\n4. Review claims and traceability; unsupported claims must never be treated as verified.\n5. If repository access is available, run the non-mutating command pack in order.\n\n" + common,
        "VALIDATION_SUMMARY.md": "# Validation Summary\n\nExecutive reviewers: the package provides bounded identity and evidence status.\n\nEngineers: use hashes, commands, and traceability to reproduce validation.\n\nResearchers: PHQ is detached formal verification, not a claim of universal proof.\n\nUniversity assessors: limitations and assumptions remain explicit; no certification is claimed.\n\n" + common,
    }


def _package_file_inventory(stage: Path) -> list[dict[str, Any]]:
    records = []
    for path in sorted(stage.rglob("*"), key=lambda item: item.relative_to(stage).as_posix()):
        if path.is_file() and path.name != "PACKAGE_MANIFEST.json": records.append({"path": path.relative_to(stage).as_posix(), "sha256": file_sha256(path), "size_bytes": path.stat().st_size})
    return records


def build_package(root: Path, destination: Path = DEFAULT_PACKAGE, *, runtime_evidence: Mapping[str, Any] | None = None) -> dict[str, Any]:
    target = destination if destination.is_absolute() else root / destination
    stage = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
    if stage.exists(): shutil.rmtree(stage)
    stage.mkdir(parents=True)
    try:
        identity = _identity(root); claims = _claims(identity); traceability = _traceability(identity); commands = _commands(); evidence = _copy_evidence(root, stage)
        write_json(stage / "REPOSITORY_IDENTITY.json", identity); write_json(stage / "ENGINEERING_CLAIMS_REGISTER.json", claims); write_json(stage / "EVIDENCE_TRACEABILITY_INDEX.json", traceability); write_json(stage / "VERIFICATION_COMMANDS.json", commands)
        runtime_record = dict(runtime_evidence) if runtime_evidence is not None else collect_runtime_replay(root); write_json(stage / "RUNTIME_REPLAY_EVIDENCE.json", runtime_record)
        inventory = {"inventory_version": R4_VERSION, "repository_commit": identity["repository_commit"], "measured_baseline_identifier": identity["measured_baseline_identifier"], "runtime_identity": identity["runtime_identity"], "evidence": evidence, "evidence_inventory_digest": generate_digest({"evidence": evidence})}; write_json(stage / "EVIDENCE_INVENTORY.json", inventory)
        for name, text in _documents(identity).items(): (stage / name).write_text(text, encoding="utf-8", newline="\n")
        files = _package_file_inventory(stage)
        manifest_payload = {"manifest_version": R4_VERSION, "desktop_scope": DESKTOP_SCOPE, "repository_identity": REPOSITORY_IDENTITY, "repository_commit": identity["repository_commit"], "git_tree_identity": identity["git_tree_identity"], "measured_baseline_identifier": identity["measured_baseline_identifier"], "runtime_identity": identity["runtime_identity"], "identity_digest": identity["identity_digest"], "claims_digest": claims["claims_digest"], "traceability_digest": traceability["traceability_digest"], "evidence_inventory_digest": inventory["evidence_inventory_digest"], "package_files": files, "package_status": "R4_IVVP_READY"}
        manifest_payload["package_identity"] = generate_digest(manifest_payload); write_json(stage / "PACKAGE_MANIFEST.json", seal(manifest_payload))
        from .verifier import verify_package
        result = verify_package(stage, repository_root=root)
        if target.exists(): shutil.rmtree(target)
        os.replace(stage, target)
        return result
    except Exception:
        shutil.rmtree(stage, ignore_errors=True); raise


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
