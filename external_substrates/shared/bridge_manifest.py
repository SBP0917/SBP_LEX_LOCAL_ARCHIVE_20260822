from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from external_substrates.shared.bridge_validator import validate_bridge_package_chain
from external_substrates.shared.digest import digest_mapping
from external_substrates.shared.freshness import utc_timestamp
from external_substrates.shared.signing import sign_payload, verify_signature
from external_substrates.shared.validation import contains_prohibited_authority


def _digest_body(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value) for key, value in manifest.items() if key not in {"manifest_digest", "manifest_signature"}}


def _signature_body(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value) for key, value in manifest.items() if key != "manifest_signature"}


def build_bridge_manifest(
    skg_package: dict,
    dtn_package: dict,
    pre_context_package: dict,
) -> dict:
    valid, failures = validate_bridge_package_chain(skg_package, dtn_package, pre_context_package)
    manifest: dict[str, Any] = {
        "manifest_type": "skg_dtn_bridge_manifest",
        "request_fingerprint": pre_context_package.get("request_fingerprint"),
        "skg_digest": skg_package.get("digest"),
        "dtn_digest": dtn_package.get("digest"),
        "pre_context_digest": pre_context_package.get("digest"),
        "package_chain": ["SKG", "DTN", "PRE_CONTEXT"],
        "bridge_status": "VALIDATED" if valid else "REJECTED",
        "validation_failures": failures,
        "created_at": pre_context_package.get("timestamp") or utc_timestamp(),
        "authority_boundary": "READINESS_METADATA_ONLY",
    }
    manifest["manifest_digest"] = digest_mapping(_digest_body(manifest))
    manifest["manifest_signature"] = sign_payload(_signature_body(manifest))
    return manifest


def validate_bridge_manifest(manifest: dict) -> tuple[bool, list[str]]:
    failures: list[str] = []
    required = {
        "manifest_type",
        "request_fingerprint",
        "skg_digest",
        "dtn_digest",
        "pre_context_digest",
        "package_chain",
        "bridge_status",
        "validation_failures",
        "created_at",
        "manifest_digest",
        "manifest_signature",
    }
    if not isinstance(manifest, Mapping):
        return False, ["invalid_bridge_manifest"]
    if not required.issubset(manifest):
        failures.append("bridge_manifest_missing_fields")
    if manifest.get("manifest_type") != "skg_dtn_bridge_manifest":
        failures.append("invalid_manifest_type")
    if manifest.get("package_chain") != ["SKG", "DTN", "PRE_CONTEXT"]:
        failures.append("invalid_package_chain")
    validation_failures = manifest.get("validation_failures")
    if not isinstance(validation_failures, list):
        failures.append("invalid_validation_failures")
    else:
        expected_status = "VALIDATED" if not validation_failures else "REJECTED"
        if manifest.get("bridge_status") != expected_status:
            failures.append("bridge_status_mismatch")
    if contains_prohibited_authority(manifest):
        failures.append("bridge_manifest_contains_authority")
    if manifest.get("manifest_digest") != digest_mapping(_digest_body(manifest)):
        failures.append("manifest_digest_invalid")
    if not verify_signature(_signature_body(manifest), str(manifest.get("manifest_signature", ""))):
        failures.append("manifest_signature_invalid")
    return not failures, failures

