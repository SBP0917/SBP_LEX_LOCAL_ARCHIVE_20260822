from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from external_substrates.shared.digest import digest_mapping
from external_substrates.shared.signing import verify_signature
from external_substrates.shared.validation import contains_prohibited_authority

BRIDGE_PACKAGE_VERSION = "1.0"


def _append(failures: list[str], reason: str) -> None:
    if reason not in failures:
        failures.append(reason)


def _contains_key(value: Any, key_name: str) -> bool:
    if isinstance(value, Mapping):
        return any(key == key_name or _contains_key(item, key_name) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return any(_contains_key(item, key_name) for item in value)
    return False


def _digest_body(package: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value) for key, value in package.items() if key not in {"digest", "signature"}}


def _signature_body(package: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value) for key, value in package.items() if key != "signature"}


def _validate_integrity(package: Mapping[str, Any], failures: list[str]) -> None:
    digest = package.get("digest")
    if not isinstance(digest, str) or not digest:
        _append(failures, "missing_digest")
    elif digest != digest_mapping(_digest_body(package)):
        _append(failures, "digest_invalid")
    signature = package.get("signature")
    if not isinstance(signature, str) or not signature:
        _append(failures, "missing_signature")
    elif not verify_signature(_signature_body(package), signature):
        _append(failures, "signature_invalid")


def _validate_external_authority(package: Mapping[str, Any], failures: list[str]) -> None:
    if _contains_key(package, "execution_permission"):
        _append(failures, "external_package_contains_execution_permission")
    if _contains_key(package, "governance_result"):
        _append(failures, "external_package_contains_governance_result")
    if contains_prohibited_authority(package):
        _append(failures, "external_package_contains_forbidden_authority")


def _validate_common(
    package: Mapping[str, Any],
    *,
    request_reason: str,
    failures: list[str],
) -> None:
    if not isinstance(package.get("request_fingerprint"), str) or not package.get("request_fingerprint"):
        _append(failures, request_reason)
    if not isinstance(package.get("timestamp"), str) or not package.get("timestamp"):
        _append(failures, "missing_timestamp")
    if "source_records" not in package and "source_summary" not in package:
        _append(failures, "missing_source_evidence")
    if package.get("freshness_valid") is not True:
        _append(failures, "stale_package")
    if package.get("consistency_valid") is not True:
        _append(failures, "inconsistent_package")
    _validate_external_authority(package, failures)
    _validate_integrity(package, failures)


def validate_skg_package_for_bridge(skg_package: dict) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if not isinstance(skg_package, Mapping):
        return False, ["invalid_skg_package"]
    _validate_common(skg_package, request_reason="missing_skg_request_fingerprint", failures=failures)
    return not failures, failures


def validate_dtn_package_for_bridge(
    dtn_package: dict,
    skg_package: dict | None = None,
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if not isinstance(dtn_package, Mapping):
        return False, ["invalid_dtn_package"]
    _validate_common(dtn_package, request_reason="missing_dtn_request_fingerprint", failures=failures)
    constraint_digest = dtn_package.get("skg_constraint_digest")
    if not isinstance(constraint_digest, str) or not constraint_digest:
        _append(failures, "dtn_missing_skg_constraint_digest")
    if skg_package is not None:
        if dtn_package.get("request_fingerprint") != skg_package.get("request_fingerprint"):
            _append(failures, "request_fingerprint_mismatch")
        if constraint_digest != skg_package.get("digest"):
            _append(failures, "dtn_skg_constraint_digest_mismatch")
    return not failures, failures


def validate_pre_context_package_for_bridge(
    pre_context_package: dict,
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if not isinstance(pre_context_package, Mapping):
        return False, ["invalid_pre_context_package"]
    required = {
        "package_version": "missing_package_version",
        "skg_package_digest": "missing_skg_package_digest",
        "dtn_package_digest": "missing_dtn_package_digest",
        "signals": "missing_signals",
        "source_summary": "missing_source_summary",
        "nonce": "missing_nonce",
    }
    if pre_context_package.get("package_type") != "external_pre_context_signal_package":
        _append(failures, "invalid_package_type")
    if pre_context_package.get("package_version") != BRIDGE_PACKAGE_VERSION:
        _append(failures, "protocol_downgrade_rejected")
    _validate_common(
        pre_context_package,
        request_reason="missing_pre_context_request_fingerprint",
        failures=failures,
    )
    for field, reason in required.items():
        value = pre_context_package.get(field)
        if field not in pre_context_package or value is None or value == "":
            _append(failures, reason)
    return not failures, failures


def validate_bridge_package_chain(
    skg_package: dict,
    dtn_package: dict,
    pre_context_package: dict,
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    for _, package_failures in (
        validate_skg_package_for_bridge(skg_package),
        validate_dtn_package_for_bridge(dtn_package, skg_package),
        validate_pre_context_package_for_bridge(pre_context_package),
    ):
        for reason in package_failures:
            _append(failures, reason)

    skg_request = skg_package.get("request_fingerprint") if isinstance(skg_package, Mapping) else None
    dtn_request = dtn_package.get("request_fingerprint") if isinstance(dtn_package, Mapping) else None
    pre_request = pre_context_package.get("request_fingerprint") if isinstance(pre_context_package, Mapping) else None
    if not (skg_request == dtn_request == pre_request):
        _append(failures, "request_fingerprint_mismatch")
    if isinstance(dtn_package, Mapping) and dtn_package.get("skg_constraint_digest") != skg_package.get("digest"):
        _append(failures, "dtn_skg_constraint_digest_mismatch")
    if isinstance(pre_context_package, Mapping):
        if pre_context_package.get("skg_package_digest") != skg_package.get("digest"):
            _append(failures, "pre_context_skg_digest_mismatch")
        if pre_context_package.get("dtn_package_digest") != dtn_package.get("digest"):
            _append(failures, "pre_context_dtn_digest_mismatch")
    return not failures, failures
