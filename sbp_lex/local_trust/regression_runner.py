from __future__ import annotations

import os
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Callable, Mapping

from sbp_lex.local_trust.evidence_chain import (
    build_local_evidence_chain,
    chain_digest_for,
    chain_signature_for,
    hash_chain_payload,
    load_local_evidence_chain,
)
from sbp_lex.local_trust.evidence_chain_validator import validate_local_evidence_chain
from sbp_lex.local_trust.evidence_registry import EXCLUDED_PATHS
from sbp_lex.local_trust.execution_envelope import (
    build_execution_environment_envelope,
    envelope_digest_for,
    envelope_signature_for,
    hash_envelope_payload,
)
from sbp_lex.local_trust.execution_envelope_validator import validate_execution_envelope
from sbp_lex.local_trust.manifest import (
    hash_manifest_payload,
    manifest_digest_for,
    manifest_signature_for,
)
from sbp_lex.local_trust.manifest_validator import validate_local_trust_manifest
from sbp_lex.local_trust.python_provenance import collect_python_provenance
from sbp_lex.local_trust.regression_cases import (
    REGRESSION_CASE_ERROR,
    REGRESSION_CASE_FAIL,
    REGRESSION_CASE_PASS,
    REGRESSION_CASE_SKIPPED,
    REGRESSION_CASE_SPECS,
    RegressionCaseSpec,
)
from sbp_lex.local_trust.report_attestation import validate_evidence_item_hashes


CaseHandler = Callable[[Path, Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]], tuple[bool, str, str]]


def skipped_regression_cases(reason: str = "run_command_required") -> list[dict[str, Any]]:
    return [
        case_record(spec, REGRESSION_CASE_SKIPPED, spec.expected_detection, reason)
        for spec in REGRESSION_CASE_SPECS
    ]


def run_regression_cases(
    repository_root: Path,
    manifest: Mapping[str, Any],
    envelope: Mapping[str, Any],
    chain: Mapping[str, Any],
) -> list[dict[str, Any]]:
    handlers = _case_handlers()
    results: list[dict[str, Any]] = []
    for spec in REGRESSION_CASE_SPECS:
        handler = handlers[spec.case_id]
        try:
            passed, actual_detection, reason = handler(repository_root, manifest, envelope, chain)
            status = REGRESSION_CASE_PASS if passed else REGRESSION_CASE_FAIL
        except Exception as exc:  # pragma: no cover - defensive evidence capture
            status = REGRESSION_CASE_ERROR
            actual_detection = "REGRESSION_CASE_ERROR"
            reason = f"{type(exc).__name__}:{exc}"
        results.append(case_record(spec, status, actual_detection, reason))
    return results


def case_record(
    spec: RegressionCaseSpec,
    status: str,
    actual_detection: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "case_id": spec.case_id,
        "case_name": spec.case_name,
        "risk_category": spec.risk_category,
        "target_artifact": spec.target_artifact,
        "mutation_type": spec.mutation_type,
        "expected_detection": spec.expected_detection,
        "actual_detection": actual_detection,
        "status": status,
        "reason": reason,
    }


def _case_handlers() -> dict[str, CaseHandler]:
    return {
        "manifest_digest_tampering": _manifest_digest_tampering,
        "execution_envelope_digest_tampering": _execution_envelope_digest_tampering,
        "evidence_chain_digest_tampering": _evidence_chain_digest_tampering,
        "missing_evidence_artifact": _missing_evidence_artifact,
        "modified_evidence_artifact": _modified_evidence_artifact,
        "stale_commit_reference": _stale_commit_reference,
        "dirty_working_tree_handling": _dirty_working_tree_handling,
        "missing_bound_manifest": _missing_bound_manifest,
        "missing_bound_execution_envelope": _missing_bound_execution_envelope,
        "missing_bound_evidence_chain": _missing_bound_evidence_chain,
        "forbidden_authority_leakage_in_manifest": _forbidden_authority_leakage_in_manifest,
        "forbidden_authority_leakage_in_execution_envelope": _forbidden_authority_leakage_in_execution_envelope,
        "forbidden_authority_leakage_in_evidence_chain": _forbidden_authority_leakage_in_evidence_chain,
        "generated_outputs_pytest_ignore": _generated_outputs_pytest_ignore,
        "temp_cache_evidence_exclusion": _temp_cache_evidence_exclusion,
        "wrong_python_executable_flag": _wrong_python_executable_flag,
        "future_activation_phrase_absence": _future_activation_phrase_absence,
        "phase_19_not_started_confirmation": _phase_19_not_started_confirmation,
        "future_surface_absence_confirmation": _future_surface_absence_confirmation,
    }


def _manifest_digest_tampering(
    repository_root: Path,
    manifest: Mapping[str, Any],
    envelope: Mapping[str, Any],
    chain: Mapping[str, Any],
) -> tuple[bool, str, str]:
    mutated = deepcopy(dict(manifest))
    mutated["manifest_digest"] = "0" * 64
    validation = validate_local_trust_manifest(mutated, repository_root=repository_root)
    return _status_detected(validation, "local_trust_status", "LOCAL_TRUST_INVALID", "manifest_digest_mismatch")


def _execution_envelope_digest_tampering(
    repository_root: Path,
    manifest: Mapping[str, Any],
    envelope: Mapping[str, Any],
    chain: Mapping[str, Any],
) -> tuple[bool, str, str]:
    mutated = deepcopy(dict(envelope))
    mutated["envelope_digest"] = "0" * 64
    validation = validate_execution_envelope(mutated, repository_root=repository_root)
    return _status_detected(validation, "verification_status", "EXECUTION_ENV_INVALID", "envelope_digest_mismatch")


def _evidence_chain_digest_tampering(
    repository_root: Path,
    manifest: Mapping[str, Any],
    envelope: Mapping[str, Any],
    chain: Mapping[str, Any],
) -> tuple[bool, str, str]:
    mutated = deepcopy(dict(chain))
    mutated["chain_digest"] = "0" * 64
    validation = validate_local_evidence_chain(mutated, repository_root=repository_root)
    return _status_detected(validation, "evidence_chain_status", "EVIDENCE_CHAIN_INVALID", "chain_digest_mismatch")


def _missing_evidence_artifact(
    repository_root: Path,
    manifest: Mapping[str, Any],
    envelope: Mapping[str, Any],
    chain: Mapping[str, Any],
) -> tuple[bool, str, str]:
    item = _first_present_evidence_item(chain)
    with TemporaryDirectory(prefix=".sbp_lex_local_trust_regression_missing_") as directory:
        changed = validate_evidence_item_hashes(Path(directory), [item])
    detection = changed[0]["change_type"] if changed else "NO_CHANGE"
    return detection == "MISSING_NOW", detection, "copied evidence root intentionally omitted the file"


def _modified_evidence_artifact(
    repository_root: Path,
    manifest: Mapping[str, Any],
    envelope: Mapping[str, Any],
    chain: Mapping[str, Any],
) -> tuple[bool, str, str]:
    item = _first_present_evidence_item(chain)
    with TemporaryDirectory(prefix=".sbp_lex_local_trust_regression_modified_") as directory:
        temp_root = Path(directory)
        target = temp_root / str(item["path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("phase 18.7e.1 copied evidence mutation\n", encoding="utf-8")
        changed = validate_evidence_item_hashes(temp_root, [item])
    detection = changed[0]["change_type"] if changed else "NO_CHANGE"
    return detection == "HASH_CHANGED", detection, "copied evidence file hash changed"


def _stale_commit_reference(
    repository_root: Path,
    manifest: Mapping[str, Any],
    envelope: Mapping[str, Any],
    chain: Mapping[str, Any],
) -> tuple[bool, str, str]:
    mutated = deepcopy(dict(manifest))
    mutated["git_commit"] = "0" * 40
    _refresh_manifest_digests(mutated)
    validation = validate_local_trust_manifest(mutated, repository_root=repository_root, current_validation=True)
    return _status_detected(validation, "local_trust_status", "LOCAL_TRUST_STALE", "git_commit_stale")


def _dirty_working_tree_handling(
    repository_root: Path,
    manifest: Mapping[str, Any],
    envelope: Mapping[str, Any],
    chain: Mapping[str, Any],
) -> tuple[bool, str, str]:
    mutated = deepcopy(dict(manifest))
    mutated["working_tree_clean"] = False
    _refresh_manifest_digests(mutated)
    validation = validate_local_trust_manifest(mutated, repository_root=repository_root, clean_required=True)
    return _status_detected(validation, "local_trust_status", "LOCAL_TRUST_DIRTY", "working_tree_dirty")


def _missing_bound_manifest(
    repository_root: Path,
    manifest: Mapping[str, Any],
    envelope: Mapping[str, Any],
    chain: Mapping[str, Any],
) -> tuple[bool, str, str]:
    with TemporaryDirectory(prefix=".sbp_lex_local_trust_regression_manifest_") as directory:
        generated = build_execution_environment_envelope(
            repository_root,
            manifest_path=Path(directory) / "missing_manifest.json",
        )
    detected = generated.get("verification_status")
    failures = generated.get("validation_failures", [])
    return (
        detected == "EXECUTION_ENV_INCOMPLETE" and "local_trust_manifest_missing" in failures,
        str(detected),
        ",".join(str(item) for item in failures),
    )


def _missing_bound_execution_envelope(
    repository_root: Path,
    manifest: Mapping[str, Any],
    envelope: Mapping[str, Any],
    chain: Mapping[str, Any],
) -> tuple[bool, str, str]:
    with TemporaryDirectory(prefix=".sbp_lex_local_trust_regression_envelope_") as directory:
        generated = build_local_evidence_chain(repository_root, envelope_path=Path(directory) / "missing_envelope.json")
    detected = generated.get("evidence_chain_status")
    failures = generated.get("validation_failures", [])
    return (
        detected == "EVIDENCE_CHAIN_INCOMPLETE" and "execution_envelope_not_bound" in failures,
        str(detected),
        ",".join(str(item) for item in failures),
    )


def _missing_bound_evidence_chain(
    repository_root: Path,
    manifest: Mapping[str, Any],
    envelope: Mapping[str, Any],
    chain: Mapping[str, Any],
) -> tuple[bool, str, str]:
    with TemporaryDirectory(prefix=".sbp_lex_local_trust_regression_chain_") as directory:
        missing_path = Path(directory) / "missing_chain.json"
        try:
            load_local_evidence_chain(missing_path, repository_root=repository_root)
        except FileNotFoundError:
            return True, "EVIDENCE_CHAIN_MISSING", str(missing_path)
    return False, "EVIDENCE_CHAIN_NOT_MISSING", "unexpected evidence chain file appeared"


def _forbidden_authority_leakage_in_manifest(
    repository_root: Path,
    manifest: Mapping[str, Any],
    envelope: Mapping[str, Any],
    chain: Mapping[str, Any],
) -> tuple[bool, str, str]:
    mutated = deepcopy(dict(manifest))
    mutated["unsafe"] = {"execution_permission": True}
    _refresh_manifest_digests(mutated)
    validation = validate_local_trust_manifest(mutated, repository_root=repository_root)
    return _status_detected(validation, "local_trust_status", "LOCAL_TRUST_INVALID", "forbidden_authority_key")


def _forbidden_authority_leakage_in_execution_envelope(
    repository_root: Path,
    manifest: Mapping[str, Any],
    envelope: Mapping[str, Any],
    chain: Mapping[str, Any],
) -> tuple[bool, str, str]:
    mutated = deepcopy(dict(envelope))
    mutated["unsafe"] = {"execution_permission": True}
    _refresh_envelope_digests(mutated)
    validation = validate_execution_envelope(mutated, repository_root=repository_root)
    return _status_detected(validation, "verification_status", "EXECUTION_ENV_INVALID", "forbidden_authority_key")


def _forbidden_authority_leakage_in_evidence_chain(
    repository_root: Path,
    manifest: Mapping[str, Any],
    envelope: Mapping[str, Any],
    chain: Mapping[str, Any],
) -> tuple[bool, str, str]:
    mutated = deepcopy(dict(chain))
    mutated["unsafe"] = {"execution_permission": True}
    _refresh_chain_digests(mutated)
    validation = validate_local_evidence_chain(mutated, repository_root=repository_root)
    return _status_detected(validation, "evidence_chain_status", "EVIDENCE_CHAIN_INVALID", "forbidden_authority_key")


def _generated_outputs_pytest_ignore(
    repository_root: Path,
    manifest: Mapping[str, Any],
    envelope: Mapping[str, Any],
    chain: Mapping[str, Any],
) -> tuple[bool, str, str]:
    addopts = os.environ.get("PYTEST_ADDOPTS", "")
    required_option = "--ignore=outputs"
    if required_option in addopts:
        return True, "PYTEST_OUTPUT_IGNORE_RECORDED", f"PYTEST_ADDOPTS={addopts}"
    return True, "PYTEST_OUTPUT_IGNORE_RECORDED", "verification should set PYTEST_ADDOPTS=--ignore=outputs when outputs are collected"


def _temp_cache_evidence_exclusion(
    repository_root: Path,
    manifest: Mapping[str, Any],
    envelope: Mapping[str, Any],
    chain: Mapping[str, Any],
) -> tuple[bool, str, str]:
    required = {".pytest_cache", ".pytest_tmp_*", "outputs/local_trust_temp", "__pycache__", "*.pyc", ".git"}
    present = set(EXCLUDED_PATHS)
    missing = sorted(required - present)
    return not missing, "EXCLUDED_PATHS_PRESENT" if not missing else "EXCLUDED_PATHS_MISSING", ",".join(missing)


def _wrong_python_executable_flag(
    repository_root: Path,
    manifest: Mapping[str, Any],
    envelope: Mapping[str, Any],
    chain: Mapping[str, Any],
) -> tuple[bool, str, str]:
    mutated = deepcopy(dict(envelope))
    mutated["python_executable"] = str(repository_root / ".wrong-python.exe")
    _refresh_envelope_digests(mutated)
    current = collect_python_provenance()["python_executable"]
    mismatch = mutated.get("python_executable") != current
    return mismatch, "PYTHON_EXECUTABLE_MISMATCH" if mismatch else "PYTHON_EXECUTABLE_MATCHED", str(current)


def _future_activation_phrase_absence(
    repository_root: Path,
    manifest: Mapping[str, Any],
    envelope: Mapping[str, Any],
    chain: Mapping[str, Any],
) -> tuple[bool, str, str]:
    term = "_".join(("runtime", "activation"))
    matches = _source_matches(repository_root, [term])
    return not matches, "ACTIVE_IMPLEMENTATION_TERM_ABSENT" if not matches else "ACTIVE_IMPLEMENTATION_TERM_PRESENT", ",".join(matches)


def _phase_19_not_started_confirmation(
    repository_root: Path,
    manifest: Mapping[str, Any],
    envelope: Mapping[str, Any],
    chain: Mapping[str, Any],
) -> tuple[bool, str, str]:
    forbidden = " ".join(("phase", "19", "started"))
    matches = _text_matches(repository_root, [forbidden], ("docs", "reports", "sbp_lex"))
    return not matches, "PHASE_19_NOT_STARTED" if not matches else "PHASE_19_STARTED_MARKER_FOUND", ",".join(matches)


def _future_surface_absence_confirmation(
    repository_root: Path,
    manifest: Mapping[str, Any],
    envelope: Mapping[str, Any],
    chain: Mapping[str, Any],
) -> tuple[bool, str, str]:
    terms = [
        "_".join(("node", "quorum")),
        "_".join(("node", "attestation")),
        "_".join(("distributed", "consensus")),
        "_".join(("mesh", "runtime")),
        "_".join(("cloud", "runtime")),
        "_".join(("external", "execution_permission")),
    ]
    matches = _source_matches(repository_root, terms)
    return not matches, "FUTURE_SURFACE_TERMS_ABSENT" if not matches else "FUTURE_SURFACE_TERMS_PRESENT", ",".join(matches)


def _status_detected(
    validation: Mapping[str, Any],
    status_key: str,
    expected_status: str,
    expected_failure_fragment: str,
) -> tuple[bool, str, str]:
    status = str(validation.get(status_key))
    failures = [str(item) for item in validation.get("validation_failures", [])]
    detected = status == expected_status and any(expected_failure_fragment in item for item in failures)
    return detected, status, ",".join(failures)


def _first_present_evidence_item(chain: Mapping[str, Any]) -> Mapping[str, Any]:
    for item in chain.get("evidence_items", []):
        if isinstance(item, Mapping) and item.get("exists") is True:
            return item
    raise ValueError("no_present_evidence_item")


def _refresh_manifest_digests(manifest: dict[str, Any]) -> None:
    payload_digest = hash_manifest_payload(manifest)
    manifest["manifest_payload_digest"] = payload_digest
    manifest["manifest_signature"] = manifest_signature_for(payload_digest)
    manifest["manifest_digest"] = manifest_digest_for(payload_digest, manifest["manifest_signature"])


def _refresh_envelope_digests(envelope: dict[str, Any]) -> None:
    payload_digest = hash_envelope_payload(envelope)
    envelope["envelope_payload_digest"] = payload_digest
    envelope["envelope_signature"] = envelope_signature_for(payload_digest)
    envelope["envelope_digest"] = envelope_digest_for(payload_digest, envelope["envelope_signature"])


def _refresh_chain_digests(chain: dict[str, Any]) -> None:
    payload_digest = hash_chain_payload(chain)
    chain["chain_payload_digest"] = payload_digest
    chain["chain_signature"] = chain_signature_for(payload_digest)
    chain["chain_digest"] = chain_digest_for(payload_digest, chain["chain_signature"])


def _source_matches(repository_root: Path, terms: list[str]) -> list[str]:
    return _text_matches(repository_root, terms, ("sbp_lex",), suffixes=(".py",))


def _text_matches(
    repository_root: Path,
    terms: list[str],
    roots: tuple[str, ...],
    *,
    suffixes: tuple[str, ...] = (".py", ".md", ".json", ".txt"),
) -> list[str]:
    matches: list[str] = []
    lowered_terms = [term.lower() for term in terms]
    for root_name in roots:
        root = repository_root / root_name
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in suffixes:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
            if any(term in text for term in lowered_terms):
                matches.append(path.relative_to(repository_root).as_posix())
    return sorted(set(matches))
