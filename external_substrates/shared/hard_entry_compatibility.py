from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from external_substrates.shared.bridge_validator import validate_pre_context_package_for_bridge
from external_substrates.shared.digest import digest_mapping
from external_substrates.shared.signing import sign_payload, verify_signature
from external_substrates.shared.validation import contains_prohibited_authority


def _digest_body(preview: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value) for key, value in preview.items() if key not in {"preview_digest", "preview_signature"}}


def _signature_body(preview: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value) for key, value in preview.items() if key != "preview_signature"}


def build_hard_entry_preview(pre_context_package: dict) -> dict:
    valid, failures = validate_pre_context_package_for_bridge(pre_context_package)
    signals = pre_context_package.get("signals", {})
    preview: dict[str, Any] = {
        "preview_type": "external_hard_entry_compatibility_preview",
        "request_fingerprint": pre_context_package.get("request_fingerprint"),
        "package_type": pre_context_package.get("package_type"),
        "package_version": pre_context_package.get("package_version"),
        "package_digest": pre_context_package.get("digest"),
        "timestamp": pre_context_package.get("timestamp"),
        "nonce": pre_context_package.get("nonce"),
        "signal_types": sorted(signals) if isinstance(signals, Mapping) else [],
        "source_summary": deepcopy(pre_context_package.get("source_summary", {})),
        "bridge_validation_status": "VALIDATED" if valid else "REJECTED",
        "validation_failures": failures,
        "authority_boundary": "MANUAL_HARD_ENTRY_VALIDATION_REQUIRED",
    }
    preview["preview_digest"] = digest_mapping(_digest_body(preview))
    preview["preview_signature"] = sign_payload(_signature_body(preview))
    return preview


def validate_hard_entry_preview(preview: dict) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if not isinstance(preview, Mapping):
        return False, ["invalid_hard_entry_preview"]
    required = {
        "preview_type",
        "request_fingerprint",
        "package_digest",
        "timestamp",
        "nonce",
        "signal_types",
        "source_summary",
        "bridge_validation_status",
        "validation_failures",
        "preview_digest",
        "preview_signature",
    }
    if not required.issubset(preview):
        failures.append("hard_entry_preview_missing_fields")
    if preview.get("preview_type") != "external_hard_entry_compatibility_preview":
        failures.append("invalid_preview_type")
    if contains_prohibited_authority(preview):
        failures.append("hard_entry_preview_contains_authority")
    if preview.get("preview_digest") != digest_mapping(_digest_body(preview)):
        failures.append("preview_digest_invalid")
    if not verify_signature(_signature_body(preview), str(preview.get("preview_signature", ""))):
        failures.append("preview_signature_invalid")
    return not failures, failures

