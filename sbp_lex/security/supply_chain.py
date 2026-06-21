from __future__ import annotations

import hashlib
from typing import Any, Mapping

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

MANIFEST_TYPE = "SBP_LEX_V1_TRUSTED_BUILD_MANIFEST"
VALIDATION_TOOL_ID = "SBP_LEX_V1_PINNED_MANIFEST_VALIDATOR"


def _artifact_digest(value: bytes | str) -> str:
    raw = value if isinstance(value, bytes) else value.encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def build_supply_chain_manifest(artifacts: Mapping[str, bytes | str]) -> dict[str, Any]:
    payload = {
        "manifest_type": MANIFEST_TYPE,
        "validation_tool_id": VALIDATION_TOOL_ID,
        "artifacts": {name: _artifact_digest(value) for name, value in sorted(artifacts.items())},
    }
    return {
        "payload": payload,
        "manifest_digest": generate_digest(payload),
        "signature": sign_payload(payload),
    }


def validate_supply_chain_manifest(
    manifest: Mapping[str, Any],
    artifacts: Mapping[str, bytes | str],
    *,
    trusted_manifest_digest: str,
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    payload = manifest.get("payload", {}) if isinstance(manifest, Mapping) else {}
    if not isinstance(payload, Mapping):
        return False, ["supply_chain_compromise_detected:manifest_shape"]
    if manifest.get("manifest_digest") != trusted_manifest_digest:
        failures.append("supply_chain_compromise_detected:manifest_pin")
    if manifest.get("manifest_digest") != generate_digest(dict(payload)):
        failures.append("supply_chain_compromise_detected:manifest_digest")
    if not verify_signature(payload, manifest.get("signature", {})):
        failures.append("supply_chain_compromise_detected:manifest_signature")
    if payload.get("manifest_type") != MANIFEST_TYPE:
        failures.append("supply_chain_compromise_detected:manifest_type")
    if payload.get("validation_tool_id") != VALIDATION_TOOL_ID:
        failures.append("supply_chain_compromise_detected:validation_tool")
    expected = {name: _artifact_digest(value) for name, value in sorted(artifacts.items())}
    if payload.get("artifacts") != expected:
        failures.append("supply_chain_compromise_detected:artifact_substitution")
    return not failures, sorted(set(failures))
