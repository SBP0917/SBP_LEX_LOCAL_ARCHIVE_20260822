from __future__ import annotations

import argparse
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence

from sbp_lex.runtime.measured_startup import approved_baseline, validate_baseline_store
from sbp_lex.security.pqc import generate_digest
from sbp_lex.supply_chain.common import unseal as unseal_r2
from sbp_lex.custody.common import unseal as unseal_r3

from .common import DESKTOP_SCOPE, REPOSITORY_IDENTITY, R4_VERSION, IVVPError, file_sha256, read_json, unseal


def _load(package: Path, name: str) -> dict[str, Any]:
    path = package / name
    if path.is_symlink() or not path.is_file(): raise IVVPError(f"missing_package_file:{name}")
    return read_json(path, label=name.lower().replace(".", "_"))


def _identity(value: Mapping[str, Any]) -> None:
    digest = value.get("identity_digest"); core = {key: item for key, item in value.items() if key != "identity_digest"}
    if digest != generate_digest(core): raise IVVPError("repository_identity_digest_invalid")
    if value.get("repository_identity") != REPOSITORY_IDENTITY or value.get("desktop_scope") != DESKTOP_SCOPE: raise IVVPError("foreign_repository_identity")
    for key in ("repository_commit", "git_tree_identity"):
        if not isinstance(value.get(key), str) or len(value[key]) != 40: raise IVVPError("repository_identity_invalid")
    for key in ("repository_digest", "measurement_digest", "runtime_identity"):
        if not isinstance(value.get(key), str) or len(value[key]) != 64: raise IVVPError("repository_identity_invalid")


def verify_package(package_root: Path, *, repository_root: Path | None = None) -> dict[str, Any]:
    package = package_root.resolve()
    if package.is_symlink() or not package.is_dir(): raise IVVPError("validation_package_missing")
    for path in package.rglob("*"):
        if path.is_symlink(): raise IVVPError("validation_package_symlink")
    manifest_wrapper = _load(package, "PACKAGE_MANIFEST.json"); manifest = unseal(manifest_wrapper, label="package_manifest")
    package_identity = manifest.get("package_identity"); core = {key: item for key, item in manifest.items() if key != "package_identity"}
    if package_identity != generate_digest(core) or manifest.get("manifest_version") != R4_VERSION or manifest.get("package_status") != "R4_IVVP_READY": raise IVVPError("package_manifest_invalid")
    if manifest.get("repository_identity") != REPOSITORY_IDENTITY or manifest.get("desktop_scope") != DESKTOP_SCOPE: raise IVVPError("foreign_validation_package")
    expected_files = {"PACKAGE_MANIFEST.json"}
    records = manifest.get("package_files")
    if not isinstance(records, list) or not records: raise IVVPError("package_file_inventory_missing")
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, Mapping) or record.get("path") in seen: raise IVVPError("duplicate_package_file")
        relative = str(record.get("path", "")); path = (package / relative).resolve(strict=False)
        if not path.is_relative_to(package) or not path.is_file() or path.is_symlink(): raise IVVPError(f"missing_package_file:{relative}")
        if record.get("sha256") != file_sha256(path) or record.get("size_bytes") != path.stat().st_size: raise IVVPError(f"substituted_package_file:{relative}")
        seen.add(relative); expected_files.add(relative)
    actual_files = {path.relative_to(package).as_posix() for path in package.rglob("*") if path.is_file()}
    if actual_files != expected_files: raise IVVPError("unexpected_package_file")
    identity = _load(package, "REPOSITORY_IDENTITY.json"); _identity(identity)
    for key in ("repository_commit", "git_tree_identity", "measured_baseline_identifier", "runtime_identity", "identity_digest"):
        if manifest.get(key) != identity.get(key): raise IVVPError(f"identity_consistency_mismatch:{key}")
    claims = _load(package, "ENGINEERING_CLAIMS_REGISTER.json")
    claim_items = claims.get("claims")
    if not isinstance(claim_items, list) or not claim_items or claims.get("claims_digest") != generate_digest({"claims": claim_items}): raise IVVPError("claims_register_invalid")
    claim_ids: set[str] = set(); evidence_basenames = {Path(item).name for item in seen if item.startswith("evidence/")}
    required_claim_fields = {"claim_identifier", "engineering_claim", "implementation_reference", "verification_source", "supporting_reports", "supporting_tests", "evidence_status"}
    for claim in claim_items:
        if not isinstance(claim, Mapping) or set(claim) != required_claim_fields or claim.get("claim_identifier") in claim_ids: raise IVVPError("claim_traceability_invalid")
        claim_ids.add(str(claim["claim_identifier"]))
        if claim.get("evidence_status") not in {"SUPPORTED", "UNSUPPORTED"}: raise IVVPError("claim_status_invalid")
        if claim.get("evidence_status") == "SUPPORTED" and (not claim.get("supporting_reports") or not claim.get("supporting_tests")): raise IVVPError("claim_without_evidence")
        for report in claim.get("supporting_reports", []):
            if report != "RUNTIME_REPLAY_EVIDENCE.json" and Path(report).name not in evidence_basenames: raise IVVPError(f"broken_report_link:{report}")
    if claims.get("repository_commit") != identity["repository_commit"] or claims.get("measured_baseline_identifier") != identity["measured_baseline_identifier"] or claims.get("runtime_identity") != identity["runtime_identity"]: raise IVVPError("claims_identity_mismatch")
    trace = _load(package, "EVIDENCE_TRACEABILITY_INDEX.json"); trace_items = trace.get("evidence_items")
    if not isinstance(trace_items, list) or trace.get("traceability_digest") != generate_digest({"evidence_items": trace_items}): raise IVVPError("traceability_invalid")
    for item in trace_items:
        if item.get("current_status") != "VERIFIED" or not item.get("evidence_identifier") or not item.get("verification_method"): raise IVVPError("broken_traceability")
        report = item.get("originating_report")
        if report != "RUNTIME_REPLAY_EVIDENCE.json" and Path(str(report)).name not in evidence_basenames: raise IVVPError(f"broken_traceability:{report}")
    inventory = _load(package, "EVIDENCE_INVENTORY.json"); evidence = inventory.get("evidence")
    if not isinstance(evidence, list) or inventory.get("evidence_inventory_digest") != generate_digest({"evidence": evidence}): raise IVVPError("evidence_inventory_invalid")
    for record in evidence:
        path = package / str(record.get("package_path"))
        if record.get("status") != "PRESENT" or not path.is_file() or record.get("sha256") != file_sha256(path) or record.get("size_bytes") != path.stat().st_size: raise IVVPError(f"stale_or_substituted_evidence:{record.get('package_path')}")
    if manifest.get("claims_digest") != claims["claims_digest"] or manifest.get("traceability_digest") != trace["traceability_digest"] or manifest.get("evidence_inventory_digest") != inventory["evidence_inventory_digest"]: raise IVVPError("manifest_traceability_binding_invalid")
    baseline_store = read_json(package / "evidence/sbp_lex/runtime/approved_runtime_baselines.json", label="baseline_store"); baseline = approved_baseline(validate_baseline_store(baseline_store))
    if baseline["baseline_identifier"] != identity["measured_baseline_identifier"] or baseline["runtime_identity"] != identity["runtime_identity"] or baseline["measurement_digest"] != identity["measurement_digest"]: raise IVVPError("stale_measured_identity")
    r2 = unseal_r2(read_json(package / "evidence/outputs/r2_deterministic_build_manifest.json", label="r2_manifest"), label="r2_manifest")
    if r2["build_provenance"]["measured_baseline_identifier"] != identity["measured_baseline_identifier"] or r2["build_provenance"]["runtime_identity"] != identity["runtime_identity"]: raise IVVPError("stale_r2_evidence")
    r3 = unseal_r3(read_json(package / "evidence/outputs/r3_operational_custody_assurance.json", label="r3_profile"), label="custody_assurance_profile")
    if r3["measured_baseline_identifier"] != identity["measured_baseline_identifier"] or r3["runtime_identity"] != identity["runtime_identity"]: raise IVVPError("stale_r3_evidence")
    runtime = _load(package, "RUNTIME_REPLAY_EVIDENCE.json")
    if runtime.get("runtime_result") != "PASS" or runtime.get("replay_result") != "PASS" or runtime.get("replay_matched") is not True or runtime.get("replay_mismatches") != 0: raise IVVPError("runtime_replay_evidence_failed")
    commands = _load(package, "VERIFICATION_COMMANDS.json"); command_items = commands.get("commands")
    if not isinstance(command_items, list) or commands.get("command_pack_digest") != generate_digest({"commands": command_items}) or any(item.get("mutates_tracked_repository_state") is not False for item in command_items): raise IVVPError("verification_command_pack_invalid")
    if repository_root is not None:
        result = subprocess.run(["git", "merge-base", "--is-ancestor", identity["repository_commit"], "HEAD"], cwd=repository_root, capture_output=True, check=False)
        if result.returncode != 0: raise IVVPError("foreign_or_rewritten_repository")
        tree = subprocess.run(["git", "rev-parse", f"{identity['repository_commit']}^{{tree}}"], cwd=repository_root, capture_output=True, text=True, check=False)
        if tree.returncode != 0 or tree.stdout.strip() != identity["git_tree_identity"]: raise IVVPError("repository_tree_mismatch")
    return {"status": "R4_IVVP_VALID", "package_identity": package_identity, "evidence_items": len(evidence), "claims": len(claim_items), "traceability_items": len(trace_items)}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify detached Desktop V1 IVVP"); parser.add_argument("package", nargs="?", type=Path, default=Path("validation_package")); parser.add_argument("--repository-root", type=Path); args = parser.parse_args(argv)
    result = verify_package(args.package, repository_root=args.repository_root)
    print("R4_IVVP_VALID"); print(f"package_identity={result['package_identity']}"); print(f"evidence_items={result['evidence_items']}"); print(f"claims={result['claims']}")
    return 0


if __name__ == "__main__": raise SystemExit(main())
