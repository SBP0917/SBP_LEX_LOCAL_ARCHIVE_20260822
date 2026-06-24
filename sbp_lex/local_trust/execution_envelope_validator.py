from __future__ import annotations

import hmac
from pathlib import Path
from typing import Any, Mapping

from sbp_lex.local_trust.git_provenance import current_git_commit

EXECUTION_ENV_VALID = "EXECUTION_ENV_VALID"
EXECUTION_ENV_INVALID = "EXECUTION_ENV_INVALID"
EXECUTION_ENV_INCOMPLETE = "EXECUTION_ENV_INCOMPLETE"
EXECUTION_ENV_STALE = "EXECUTION_ENV_STALE"
EXECUTION_ENV_DIRTY = "EXECUTION_ENV_DIRTY"

COMMAND_STATUSES = {
    "COMMAND_PASS",
    "COMMAND_FAIL",
    "COMMAND_NOT_RUN",
    "COMMAND_SKIPPED",
    "COMMAND_TIMEOUT",
    "COMMAND_ERROR",
}

REQUIRED_SECTIONS = {
    "envelope_type",
    "envelope_version",
    "created_at",
    "repository_root",
    "git_commit",
    "git_branch",
    "working_tree_clean",
    "bound_local_trust_manifest_digest",
    "bound_local_trust_manifest_path",
    "python_executable",
    "python_version",
    "working_directory",
    "shell_type_if_available",
    "path_digest_or_path_summary",
    "command_results",
    "runtime_result_summary",
    "replay_result_summary",
    "envelope_payload_digest",
    "envelope_digest",
    "envelope_signature",
    "signature_mode",
}

REQUIRED_COMMAND_FIELDS = {
    "command_id",
    "command_text",
    "command_args",
    "started_at",
    "finished_at",
    "duration_ms",
    "exit_code",
    "stdout_digest",
    "stderr_digest",
    "stdout_excerpt",
    "stderr_excerpt",
    "working_directory",
    "python_executable_if_python_command",
    "command_status",
}

FORBIDDEN_KEYS = {
    "execution_permission",
    "governance_result",
    "runtime_authority",
    "allow_execution",
    "external_allow",
    "external_deny",
    "external_escalate",
    "external_" + "governance_result",
}


def validate_execution_envelope(
    envelope: Mapping[str, Any],
    *,
    repository_root: Path | None = None,
    clean_required: bool = False,
    current_validation: bool = False,
) -> dict[str, Any]:
    from sbp_lex.local_trust.execution_envelope import (
        ENVELOPE_SIGNATURE_MODE,
        envelope_digest_for,
        envelope_signature_for,
        hash_envelope_payload,
    )
    from sbp_lex.local_trust.manifest import canonicalise_manifest

    failures: list[str] = []
    if not isinstance(envelope, Mapping):
        return {"verification_status": EXECUTION_ENV_INVALID, "validation_failures": ["envelope_not_mapping"]}

    missing = sorted(REQUIRED_SECTIONS - set(envelope))
    if missing:
        failures.extend(f"missing_required_section:{section}" for section in missing)
        return {"verification_status": EXECUTION_ENV_INCOMPLETE, "validation_failures": failures}

    if envelope.get("envelope_type") != "local_execution_environment_trust_envelope":
        failures.append("invalid_envelope_type")
    if envelope.get("signature_mode") != ENVELOPE_SIGNATURE_MODE:
        failures.append("invalid_signature_mode")
    if envelope.get("bound_local_trust_manifest_digest") in (None, "", "LOCAL_TRUST_MANIFEST_MISSING"):
        failures.append("local_trust_manifest_missing")
    if envelope.get("bound_local_trust_manifest_digest") == "LOCAL_TRUST_MANIFEST_INVALID":
        failures.append("local_trust_manifest_invalid")

    try:
        canonicalise_manifest(envelope)
    except (TypeError, ValueError) as exc:
        failures.append(f"canonicalisation_failed:{exc}")

    expected_payload_digest = hash_envelope_payload(envelope)
    if not hmac.compare_digest(str(envelope.get("envelope_payload_digest")), expected_payload_digest):
        failures.append("envelope_payload_digest_mismatch")

    expected_signature = envelope_signature_for(expected_payload_digest)
    if not hmac.compare_digest(str(envelope.get("envelope_signature")), expected_signature):
        failures.append("envelope_signature_mismatch")

    expected_envelope_digest = envelope_digest_for(expected_payload_digest, expected_signature)
    if not hmac.compare_digest(str(envelope.get("envelope_digest")), expected_envelope_digest):
        failures.append("envelope_digest_mismatch")

    failures.extend(_command_result_failures(envelope.get("command_results")))
    failures.extend(_forbidden_failures(envelope))

    if failures:
        incomplete_markers = {"local_trust_manifest_missing", "local_trust_manifest_invalid"}
        status = EXECUTION_ENV_INCOMPLETE if any(item in incomplete_markers for item in failures) else EXECUTION_ENV_INVALID
        return {"verification_status": status, "validation_failures": sorted(set(failures))}

    if current_validation and repository_root is not None:
        current_commit = current_git_commit(repository_root)
        if current_commit and envelope.get("git_commit") != current_commit:
            return {"verification_status": EXECUTION_ENV_STALE, "validation_failures": ["git_commit_stale"]}

    if clean_required and envelope.get("working_tree_clean") is not True:
        return {"verification_status": EXECUTION_ENV_DIRTY, "validation_failures": ["working_tree_dirty"]}

    return {"verification_status": EXECUTION_ENV_VALID, "validation_failures": []}


def _command_result_failures(value: Any) -> list[str]:
    failures: list[str] = []
    if not isinstance(value, list):
        return ["command_results_not_list"]
    for index, record in enumerate(value):
        if not isinstance(record, Mapping):
            failures.append(f"command_result_not_mapping:{index}")
            continue
        missing = sorted(REQUIRED_COMMAND_FIELDS - set(record))
        failures.extend(f"command_result_missing_field:{index}:{field}" for field in missing)
        if record.get("command_status") not in COMMAND_STATUSES:
            failures.append(f"command_result_invalid_status:{index}")
    return failures


def _forbidden_failures(value: Any, path: str = "$") -> list[str]:
    failures: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            next_path = f"{path}.{key_text}"
            if key_text in FORBIDDEN_KEYS:
                failures.append(f"forbidden_authority_key:{next_path}")
            failures.extend(_forbidden_failures(item, next_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            failures.extend(_forbidden_failures(item, f"{path}[{index}]"))
    return failures
