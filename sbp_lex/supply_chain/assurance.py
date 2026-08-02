from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from sbp_lex.local_trust.critical_paths import CRITICAL_FILE_PATHS, TRUSTED_OUTPUT_PATHS, TRUSTED_REPORT_PATHS
from sbp_lex.local_trust.manifest import repository_root_from
from sbp_lex.security.pqc import generate_digest

from .common import DESKTOP_SCOPE, R2_VERSION, SupplyChainError, atomic_json, read_json, seal, unseal
from .provenance import (
    artifact_records,
    collect_build_provenance,
    collect_dependency_provenance,
    collect_repository_provenance,
    validate_artifact_records,
    validate_build_provenance,
    validate_dependency_provenance,
    validate_repository_provenance,
)

DEFAULT_SBOM = Path("outputs/r2_software_bill_of_materials.json")
DEFAULT_MANIFEST = Path("outputs/r2_deterministic_build_manifest.json")
DEFAULT_VERIFICATION = Path("outputs/r2_offline_verification.json")
SELF_AUTHENTICATING_OUTPUTS = frozenset({str(DEFAULT_SBOM), str(DEFAULT_MANIFEST), str(DEFAULT_VERIFICATION)})
VALIDATION_EVIDENCE_PATHS = (
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
)
MANIFEST_PAYLOAD_FIELDS = frozenset({
    "manifest_version",
    "assurance_version",
    "desktop_scope",
    "repository_provenance",
    "dependency_digest",
    "dependency_count",
    "build_provenance",
    "artefact_inventory",
    "artefact_inventory_digest",
    "validation_evidence_bindings",
    "validation_identity",
    "network_required_for_verification",
    "canonical_payload_contains_timestamp",
    "manifest_status",
    "supply_chain_identity",
})


def canonical_artifact_paths() -> tuple[str, ...]:
    paths = (
        set(CRITICAL_FILE_PATHS)
        | set(TRUSTED_REPORT_PATHS)
        | set(TRUSTED_OUTPUT_PATHS)
        | set(VALIDATION_EVIDENCE_PATHS)
    )
    return tuple(sorted(path for path in paths if path not in SELF_AUTHENTICATING_OUTPUTS))


def build_manifest_payload(
    root: Path,
    sbom: Mapping[str, Any],
    *,
    artifact_sources: Mapping[str, Path] | None = None,
) -> dict[str, Any]:
    repository = collect_repository_provenance(root)
    build = collect_build_provenance(
        root, repository, artifact_sources=artifact_sources,
    )
    artifacts = artifact_records(
        root,
        canonical_artifact_paths(),
        artifact_sources=artifact_sources,
        require_repository_tracking=True,
    )
    validation_bindings = {
        record["path"]: record["sha256"]
        for record in artifacts
        if record["creation_relationship"] == "GENERATED_EVIDENCE"
    }
    payload: dict[str, Any] = {
        "manifest_version": "R2_DESKTOP_V1_DETERMINISTIC_BUILD_MANIFEST_V1",
        "assurance_version": R2_VERSION,
        "desktop_scope": DESKTOP_SCOPE,
        "repository_provenance": repository,
        "dependency_digest": sbom["dependency_digest"],
        "dependency_count": sbom["dependency_count"],
        "build_provenance": build,
        "artefact_inventory": artifacts,
        "artefact_inventory_digest": generate_digest({"artefacts": artifacts}),
        "validation_evidence_bindings": validation_bindings,
        "validation_identity": generate_digest({"validation_evidence_bindings": validation_bindings}),
        "network_required_for_verification": False,
        "canonical_payload_contains_timestamp": False,
        "manifest_status": "SUPPLY_CHAIN_PROVENANCE_APPROVED",
    }
    payload["supply_chain_identity"] = generate_digest(payload)
    return payload


def validate_manifest_payload(
    payload: Mapping[str, Any], sbom: Mapping[str, Any], root: Path,
    *, verify_installed: bool = True,
    artifact_sources: Mapping[str, Path] | None = None,
) -> dict[str, Any]:
    if set(payload) != MANIFEST_PAYLOAD_FIELDS:
        raise SupplyChainError("manifest_schema_invalid")
    if payload.get("manifest_version") != "R2_DESKTOP_V1_DETERMINISTIC_BUILD_MANIFEST_V1":
        raise SupplyChainError("manifest_version_invalid")
    if (
        payload.get("assurance_version") != R2_VERSION
        or payload.get("desktop_scope") != DESKTOP_SCOPE
        or payload.get("manifest_status")
        != "SUPPLY_CHAIN_PROVENANCE_APPROVED"
    ):
        raise SupplyChainError("manifest_scope_invalid")
    identity = payload.get("supply_chain_identity")
    core = {key: value for key, value in payload.items() if key != "supply_chain_identity"}
    if identity != generate_digest(core):
        raise SupplyChainError("supply_chain_identity_mismatch")
    repository = payload.get("repository_provenance")
    build = payload.get("build_provenance")
    if not isinstance(repository, Mapping) or not isinstance(build, Mapping):
        raise SupplyChainError("provenance_link_missing")
    validate_repository_provenance(repository, root)
    validate_dependency_provenance(sbom, verify_installed=verify_installed)
    if payload.get("dependency_digest") != sbom.get("dependency_digest") or payload.get("dependency_count") != sbom.get("dependency_count"):
        raise SupplyChainError("sbom_link_mismatch")
    validate_build_provenance(
        build,
        root,
        repository,
        artifact_sources=artifact_sources,
    )
    artifacts = payload.get("artefact_inventory")
    validate_artifact_records(
        artifacts,
        root,
        artifact_sources=artifact_sources,
        require_repository_tracking=True,
    )
    if payload.get("artefact_inventory_digest") != generate_digest({"artefacts": artifacts}):
        raise SupplyChainError("artifact_inventory_digest_mismatch")
    expected_bindings = {
        item["path"]: item["sha256"]
        for item in artifacts
        if item["creation_relationship"] == "GENERATED_EVIDENCE"
    }
    if payload.get("validation_evidence_bindings") != expected_bindings:
        raise SupplyChainError("validation_evidence_link_mismatch")
    if payload.get("validation_identity") != generate_digest({"validation_evidence_bindings": expected_bindings}):
        raise SupplyChainError("validation_identity_mismatch")
    if payload.get("network_required_for_verification") is not False or payload.get("canonical_payload_contains_timestamp") is not False:
        raise SupplyChainError("offline_determinism_policy_invalid")
    return {
        "repository": "VERIFIED",
        "dependencies": "VERIFIED",
        "build": "VERIFIED",
        "artefacts": "VERIFIED",
        "runtime_linkage": "VERIFIED",
        "validation_evidence": "VERIFIED",
    }


def validate_bundle(
    root: Path,
    *, sbom_path: Path = DEFAULT_SBOM,
    manifest_path: Path = DEFAULT_MANIFEST,
    verification_path: Path | None = DEFAULT_VERIFICATION,
    verify_installed: bool = True,
    artifact_sources: Mapping[str, Path] | None = None,
) -> dict[str, Any]:
    sbom = read_json(root / sbom_path, label="r2_sbom")
    sealed_manifest = read_json(root / manifest_path, label="r2_manifest")
    payload = unseal(sealed_manifest, label="r2_manifest")
    links = validate_manifest_payload(
        payload,
        sbom,
        root,
        verify_installed=verify_installed,
        artifact_sources=artifact_sources,
    )
    if verification_path is not None:
        sealed_result = read_json(root / verification_path, label="r2_verification")
        result = unseal(sealed_result, label="r2_verification")
        expected = {
            "verification_version": "R2_DESKTOP_V1_OFFLINE_VERIFICATION_V1",
            "desktop_scope": DESKTOP_SCOPE,
            "manifest_digest": sealed_manifest["payload_digest"],
            "supply_chain_identity": payload["supply_chain_identity"],
            "link_results": links,
            "network_used": False,
            "verification_status": "R2_SUPPLY_CHAIN_ASSURANCE_PASS",
        }
        if result != expected:
            raise SupplyChainError("offline_verification_result_stale")
    return {
        "status": "R2_SUPPLY_CHAIN_ASSURANCE_PASS",
        "manifest_digest": sealed_manifest["payload_digest"],
        "supply_chain_identity": payload["supply_chain_identity"],
        "dependency_count": sbom["dependency_count"],
        "artefact_count": len(payload["artefact_inventory"]),
        "links": links,
    }


def build_bundle(
    root: Path,
    *, sbom_path: Path = DEFAULT_SBOM,
    manifest_path: Path = DEFAULT_MANIFEST,
    verification_path: Path = DEFAULT_VERIFICATION,
    artifact_sources: Mapping[str, Path] | None = None,
) -> dict[str, Any]:
    sbom = collect_dependency_provenance(root)
    payload = build_manifest_payload(
        root,
        sbom,
        artifact_sources=artifact_sources,
    )
    sealed_manifest = seal(payload)
    atomic_json(root / sbom_path, sbom)
    atomic_json(root / manifest_path, sealed_manifest)
    links = validate_manifest_payload(
        payload,
        sbom,
        root,
        artifact_sources=artifact_sources,
    )
    verification = seal({
        "verification_version": "R2_DESKTOP_V1_OFFLINE_VERIFICATION_V1",
        "desktop_scope": DESKTOP_SCOPE,
        "manifest_digest": sealed_manifest["payload_digest"],
        "supply_chain_identity": payload["supply_chain_identity"],
        "link_results": links,
        "network_used": False,
        "verification_status": "R2_SUPPLY_CHAIN_ASSURANCE_PASS",
    })
    atomic_json(root / verification_path, verification)
    return validate_bundle(
        root,
        sbom_path=sbom_path,
        manifest_path=manifest_path,
        verification_path=verification_path,
        artifact_sources=artifact_sources,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Desktop V1 deterministic supply-chain assurance")
    parser.add_argument("command", choices=("build", "validate", "show"))
    parser.add_argument("--sbom", type=Path, default=DEFAULT_SBOM)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--verification", type=Path, default=DEFAULT_VERIFICATION)
    args = parser.parse_args(argv)
    root = repository_root_from()
    if args.command == "build":
        result = build_bundle(root, sbom_path=args.sbom, manifest_path=args.manifest, verification_path=args.verification)
    else:
        result = validate_bundle(root, sbom_path=args.sbom, manifest_path=args.manifest, verification_path=args.verification)
    print(result["status"])
    if args.command in {"build", "show"}:
        print(f"dependencies={result['dependency_count']}")
        print(f"artefacts={result['artefact_count']}")
        print(f"manifest_digest={result['manifest_digest']}")
        print(f"supply_chain_identity={result['supply_chain_identity']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
