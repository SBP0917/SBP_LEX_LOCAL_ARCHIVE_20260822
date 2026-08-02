from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Mapping, Sequence

from sbp_lex.local_trust.manifest import repository_root_from
from sbp_lex.runtime.measured_startup import (
    approved_baseline,
    configured_baseline_path,
    load_baseline_store,
    validate_baseline_store,
)
from sbp_lex.security.pqc import generate_digest
from sbp_lex.supply_chain.common import read_json as read_r2_json, unseal as unseal_r2

from .common import DESKTOP_SCOPE, R3_VERSION, CustodyError, atomic_json, read_json, seal, unseal

DEFAULT_OUTPUT = Path("outputs/r3_operational_custody_assurance.json")
DEFAULT_R2_MANIFEST = Path("outputs/r2_deterministic_build_manifest.json")


def _rooted(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def build_profile(
    root: Path,
    *,
    baseline_path: Path | None = None,
    r2_manifest_path: Path = DEFAULT_R2_MANIFEST,
) -> dict[str, Any]:
    selected_baseline = baseline_path or configured_baseline_path()
    baseline = approved_baseline(
        validate_baseline_store(load_baseline_store(selected_baseline))
    )
    r2 = unseal_r2(
        read_r2_json(
            _rooted(root, r2_manifest_path),
            label="r2_manifest",
        ),
        label="r2_manifest",
    )
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


def validate_profile(
    value: Mapping[str, Any],
    root: Path,
    *,
    baseline_path: Path | None = None,
    r2_manifest_path: Path = DEFAULT_R2_MANIFEST,
) -> dict[str, Any]:
    payload = unseal(value, label="custody_assurance_profile")
    digest = payload.get("profile_digest"); core = {key: item for key, item in payload.items() if key != "profile_digest"}
    if digest != generate_digest(core) or payload.get("desktop_scope") != DESKTOP_SCOPE:
        raise CustodyError("custody_profile_digest_invalid")
    if payload.get("private_key_material_present") is not False or payload.get("cloud_service_required") is not False or payload.get("distributed_authority_introduced") is not False:
        raise CustodyError("custody_profile_boundary_invalid")
    selected_baseline = baseline_path or configured_baseline_path()
    baseline = approved_baseline(
        validate_baseline_store(load_baseline_store(selected_baseline))
    )
    if payload.get("measured_baseline_identifier") != baseline["baseline_identifier"] or payload.get("runtime_identity") != baseline["runtime_identity"]:
        raise CustodyError("custody_profile_runtime_linkage_invalid")
    r2 = unseal_r2(
        read_r2_json(
            _rooted(root, r2_manifest_path),
            label="r2_manifest",
        ),
        label="r2_manifest",
    )
    repository = r2.get("repository_provenance")
    if not isinstance(repository, Mapping):
        raise CustodyError("custody_profile_r2_linkage_invalid")
    if (
        payload.get("repository_commit")
        != repository.get("repository_commit")
        or payload.get("r2_supply_chain_identity")
        != r2.get("supply_chain_identity")
    ):
        raise CustodyError("custody_profile_r2_linkage_invalid")
    if payload.get("operational_status") != "R3_CUSTODY_ASSURANCE_READY": raise CustodyError("custody_profile_status_invalid")
    return payload


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Desktop V1 operational custody assurance")
    parser.add_argument("command", choices=("build", "validate", "show")); parser.add_argument("--path", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv); root = repository_root_from(); path = root / args.path
    if args.command == "build":
        atomic_json(path, build_profile(root))
    payload = validate_profile(read_json(path, label="custody_profile"), root)
    print("R3_CUSTODY_ASSURANCE_PASS")
    if args.command in {"build", "show"}:
        print(f"baseline={payload['measured_baseline_identifier']}"); print(f"runtime_identity={payload['runtime_identity']}"); print(f"profile_digest={payload['profile_digest']}")
    return 0


if __name__ == "__main__": raise SystemExit(main())
