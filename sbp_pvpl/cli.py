from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path

from sbp_pvpl.artifact import inspect_proof_artifact
from sbp_pvpl.boundary_checker import run_boundary_check
from sbp_pvpl.bundle import build_proof_bundle, bundle_to_dict, validate_proof_bundle, write_proof_bundle
from sbp_pvpl.evidence_collector import collect_local_evidence
from sbp_pvpl.manifest import build_proof_manifest
from sbp_pvpl.report_writer import write_proof_report
from sbp_pvpl.summary import build_private_proof_summary
from sbp_pvpl.verifier import verify_local_proof_bundle_file


DEFAULT_PROOF_PATHS = {
    "university_dossier_manifest": "outputs/university_validation_dossier/DOSSIER_MANIFEST.json",
    "release_manifest": "outputs/release_integrity_bundle/RELEASE_MANIFEST.json",
    "local_trust_manifest": "outputs/local_trust_root_manifest.json",
}


def build_local_proof_summary(runtime_root: str = ".") -> dict[str, object]:
    root = Path(runtime_root)
    artifacts = [
        inspect_proof_artifact(artifact_id, root / relative_path)
        for artifact_id, relative_path in DEFAULT_PROOF_PATHS.items()
    ]
    manifest = build_proof_manifest(artifacts)
    bundle = build_proof_bundle(manifest)
    return {
        "manifest": asdict(manifest),
        "bundle_validation": validate_proof_bundle(bundle),
        "summary": build_private_proof_summary(bundle),
    }


def build_manifest_file(runtime_root: str, output_path: str) -> dict[str, object]:
    manifest = build_proof_manifest(runtime_root=runtime_root)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(manifest), indent=2, sort_keys=True, default=str), encoding="utf-8")
    return {"status": manifest.status.value, "manifest_path": str(path), "manifest_digest": manifest.manifest_digest, "runtime_authority": "NONE"}


def build_bundle_file(runtime_root: str, output_path: str) -> dict[str, object]:
    manifest = build_proof_manifest(runtime_root=runtime_root)
    bundle = build_proof_bundle(manifest)
    path = write_proof_bundle(bundle, output_path)
    return {"status": validate_proof_bundle(bundle)["status"], "bundle_path": str(path), "bundle_digest": bundle.bundle_digest, "runtime_authority": "NONE"}


def main() -> int:
    parser = argparse.ArgumentParser(description="SBP-LEX PVPL-V1 local proof skeleton")
    parser.add_argument("--runtime-root", default=".", help="Path to repository root")
    parser.add_argument("--summary", action="store_true", help="Build local proof summary")
    parser.add_argument("--collect-evidence", action="store_true", help="Collect local evidence metadata")
    parser.add_argument("--build-manifest", action="store_true", help="Write local proof manifest JSON")
    parser.add_argument("--build-bundle", action="store_true", help="Write local proof bundle JSON")
    parser.add_argument("--verify-bundle", action="store_true", help="Verify local proof bundle JSON")
    parser.add_argument("--write-report", action="store_true", help="Write reviewer-readable local proof report")
    parser.add_argument("--boundary-check", action="store_true", help="Run PVPL runtime-detachment boundary check")
    parser.add_argument("--out", default="runtime_artifacts/pvpl_02/proof_bundle.json", help="Output path")
    parser.add_argument("--bundle", default="runtime_artifacts/pvpl_02/proof_bundle.json", help="Proof bundle path")
    args = parser.parse_args()
    if args.summary:
        print(json.dumps(build_local_proof_summary(args.runtime_root), indent=2, sort_keys=True, default=str))
        return 0
    if args.collect_evidence:
        entries = collect_local_evidence(args.runtime_root)
        print(json.dumps({"status": "PROOF_OK", "evidence_count": len(entries), "evidence_entries": entries, "runtime_authority": "NONE"}, indent=2, sort_keys=True, default=str))
        return 0
    if args.build_manifest:
        print(json.dumps(build_manifest_file(args.runtime_root, args.out), indent=2, sort_keys=True, default=str))
        return 0
    if args.build_bundle:
        print(json.dumps(build_bundle_file(args.runtime_root, args.out), indent=2, sort_keys=True, default=str))
        return 0
    if args.verify_bundle:
        print(json.dumps(verify_local_proof_bundle_file(args.bundle, args.runtime_root), indent=2, sort_keys=True, default=str))
        return 0
    if args.write_report:
        path = write_proof_report(args.bundle, args.out, args.runtime_root)
        print(json.dumps({"status": "PROOF_OK", "proof_report_path": str(path), "runtime_authority": "NONE"}, indent=2, sort_keys=True))
        return 0
    if args.boundary_check:
        print(json.dumps(run_boundary_check(args.runtime_root), indent=2, sort_keys=True, default=str))
        return 0
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
