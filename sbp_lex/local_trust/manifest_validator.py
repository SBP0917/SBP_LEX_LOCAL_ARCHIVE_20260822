from __future__ import annotations

import hmac
from pathlib import Path
from typing import Any, Mapping

from sbp_lex.local_trust.git_provenance import current_git_commit

LOCAL_TRUST_VALID = "LOCAL_TRUST_VALID"
LOCAL_TRUST_INVALID = "LOCAL_TRUST_INVALID"
LOCAL_TRUST_INCOMPLETE = "LOCAL_TRUST_INCOMPLETE"
LOCAL_TRUST_STALE = "LOCAL_TRUST_STALE"
LOCAL_TRUST_DIRTY = "LOCAL_TRUST_DIRTY"

FORBIDDEN_KEYS = {
    "execution_permission",
    "governance_result",
    "external_governance_result",
    "runtime_authority",
    "allow_execution",
}
FORBIDDEN_KEY_VALUES = {
    ("decision", "ALLOW"),
    ("decision", "DENY"),
    ("decision", "ESCALATE"),
    ("execution_result", "EXECUTE"),
}

REQUIRED_SECTIONS = {
    "manifest_type",
    "manifest_version",
    "created_at",
    "repository_root",
    "repository_root_digest_scope",
    "git_branch",
    "git_commit",
    "git_status_short",
    "working_tree_clean",
    "python_executable",
    "python_version",
    "command_provenance",
    "critical_file_hashes",
    "trusted_report_hashes",
    "trusted_output_hashes",
    "test_baseline",
    "runtime_baseline",
    "replay_baseline",
    "phase_baseline",
    "manifest_payload_digest",
    "manifest_digest",
    "manifest_signature",
    "signature_mode",
}


def validate_local_trust_manifest(
    manifest: Mapping[str, Any],
    *,
    repository_root: Path | None = None,
    clean_required: bool = False,
    current_validation: bool = False,
) -> dict[str, Any]:
    from sbp_lex.local_trust.manifest import (
        LOCAL_TRUST_SIGNATURE_MODE,
        canonicalise_manifest,
        hash_manifest_payload,
        manifest_digest_for,
        manifest_signature_for,
    )

    failures: list[str] = []
    if not isinstance(manifest, Mapping):
        return {"local_trust_status": LOCAL_TRUST_INVALID, "validation_failures": ["manifest_not_mapping"]}

    missing = sorted(REQUIRED_SECTIONS - set(manifest))
    if missing:
        failures.extend(f"missing_required_section:{section}" for section in missing)
        return {"local_trust_status": LOCAL_TRUST_INCOMPLETE, "validation_failures": failures}

    if manifest.get("manifest_type") != "local_trust_root_manifest":
        failures.append("invalid_manifest_type")
    if manifest.get("signature_mode") != LOCAL_TRUST_SIGNATURE_MODE:
        failures.append("invalid_signature_mode")

    try:
        canonicalise_manifest(manifest)
    except (TypeError, ValueError) as exc:
        failures.append(f"canonicalisation_failed:{exc}")

    expected_payload_digest = hash_manifest_payload(manifest)
    if not hmac.compare_digest(str(manifest.get("manifest_payload_digest")), expected_payload_digest):
        failures.append("manifest_payload_digest_mismatch")

    expected_signature = manifest_signature_for(expected_payload_digest)
    if not hmac.compare_digest(str(manifest.get("manifest_signature")), expected_signature):
        failures.append("manifest_signature_mismatch")

    expected_manifest_digest = manifest_digest_for(expected_payload_digest, expected_signature)
    if not hmac.compare_digest(str(manifest.get("manifest_digest")), expected_manifest_digest):
        failures.append("manifest_digest_mismatch")

    failures.extend(_forbidden_failures(manifest))

    if failures:
        return {"local_trust_status": LOCAL_TRUST_INVALID, "validation_failures": sorted(set(failures))}

    if current_validation and repository_root is not None:
        current_commit = current_git_commit(repository_root)
        if current_commit and manifest.get("git_commit") != current_commit:
            return {"local_trust_status": LOCAL_TRUST_STALE, "validation_failures": ["git_commit_stale"]}

    if clean_required and manifest.get("working_tree_clean") is not True:
        return {"local_trust_status": LOCAL_TRUST_DIRTY, "validation_failures": ["working_tree_dirty"]}

    if not manifest.get("critical_file_hashes"):
        return {"local_trust_status": LOCAL_TRUST_INCOMPLETE, "validation_failures": ["critical_file_hashes_missing"]}

    return {"local_trust_status": LOCAL_TRUST_VALID, "validation_failures": []}


def _forbidden_failures(value: Any, path: str = "$") -> list[str]:
    failures: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            next_path = f"{path}.{key_text}"
            if key_text in FORBIDDEN_KEYS:
                failures.append(f"forbidden_authority_key:{next_path}")
            if isinstance(item, str) and (key_text, item) in FORBIDDEN_KEY_VALUES:
                failures.append(f"forbidden_authority_value:{next_path}")
            failures.extend(_forbidden_failures(item, next_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            failures.extend(_forbidden_failures(item, f"{path}[{index}]"))
    return failures
