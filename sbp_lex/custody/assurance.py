from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Mapping, Sequence

from sbp_lex.local_trust.manifest import repository_root_from
from sbp_lex.runtime.measured_startup import approved_baseline, load_baseline_store, validate_baseline_store
from sbp_lex.security.pqc import generate_digest
from sbp_lex.supply_chain.common import read_json as read_r2_json, unseal as unseal_r2

from .common import DESKTOP_SCOPE, R3_VERSION, CustodyError, atomic_json, read_json, seal, unseal

DEFAULT_OUTPUT = Path("outputs/r3_operational_custody_assurance.json")


def build_profile(root: Path) -> dict[str, Any]:
    baseline = approved_baseline(validate_baseline_store(load_baseline_store(root / "sbp_lex/runtime/approved_runtime_baselines.json")))
    r2 = unseal_r2(read_r2_json(root / "outputs/r2_deterministic_build_manifest.json", label="r2_manifest"), label="r2_manifest")
    payload = {
        "profile_version": "R3_OPERATIONAL_CUSTODY_ASSURANCE_PROFILE_V1",
        "custody_version": R3_VERSION,
        "desktop_scope": DESKTOP_SCOPE,
        "repository_commit": r2["repository_provenance"]["repository_commit"],
        "r2_supply_chain_identity": r2["supply_chain_identity"],
        "measured_baseline_identifier": baseline["baseline_identifier"],
        "runtime_identity": baseline["runtime_identity"],
        "controls": [
            "OFF_HOST_SEALED_EXPORT_IMPORT", "PUBLIC_ONLY_EXTERNAL_KEY_CUSTODY",
            "RECOVERY_KEY_SEPARATION", "DUAL_CONTROL_PREPARATION",
            "RECOVERY_MEDIA_LIFECYCLE", "SIGNED_CUSTODY_CHAIN",
            "FAIL_CLOSED_CONTINUITY_VERIFICATION",
        ],
        "private_key_material_present": False,
        "cloud_service_required": False,
        "distributed_authority_introduced": False,
        "operational_status": "R3_CUSTODY_ASSURANCE_READY",
    }
    payload["profile_digest"] = generate_digest(payload)
    return seal(payload)


def validate_profile(value: Mapping[str, Any], root: Path) -> dict[str, Any]:
    payload = unseal(value, label="custody_assurance_profile")
    digest = payload.get("profile_digest"); core = {key: item for key, item in payload.items() if key != "profile_digest"}
    if digest != generate_digest(core) or payload.get("desktop_scope") != DESKTOP_SCOPE:
        raise CustodyError("custody_profile_digest_invalid")
    if payload.get("private_key_material_present") is not False or payload.get("cloud_service_required") is not False or payload.get("distributed_authority_introduced") is not False:
        raise CustodyError("custody_profile_boundary_invalid")
    baseline = approved_baseline(validate_baseline_store(load_baseline_store(root / "sbp_lex/runtime/approved_runtime_baselines.json")))
    if payload.get("measured_baseline_identifier") != baseline["baseline_identifier"] or payload.get("runtime_identity") != baseline["runtime_identity"]:
        raise CustodyError("custody_profile_runtime_linkage_invalid")
    if payload.get("operational_status") != "R3_CUSTODY_ASSURANCE_READY": raise CustodyError("custody_profile_status_invalid")
    return payload


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Desktop V1 operational custody assurance")
    parser.add_argument("command", choices=("build", "validate", "show")); parser.add_argument("--path", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv); root = repository_root_from(); path = root / args.path
    if args.command == "build": atomic_json(path, build_profile(root))
    payload = validate_profile(read_json(path, label="custody_profile"), root)
    print("R3_CUSTODY_ASSURANCE_PASS")
    if args.command in {"build", "show"}:
        print(f"baseline={payload['measured_baseline_identifier']}"); print(f"runtime_identity={payload['runtime_identity']}"); print(f"profile_digest={payload['profile_digest']}")
    return 0


if __name__ == "__main__": raise SystemExit(main())
