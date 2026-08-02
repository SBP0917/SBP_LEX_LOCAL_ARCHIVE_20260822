from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import re
import sys
import threading
import uuid
from collections import deque
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from sbp_lex.api.schema_validation import loads_strict_json
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

MEASUREMENT_VERSION = "H8_DESKTOP_V1_MEASUREMENT_V1"
BASELINE_STORE_VERSION = "H8_DESKTOP_V1_BASELINE_STORE_V1"
BASELINE_RECORD_VERSION = "H8_DESKTOP_V1_BASELINE_RECORD_V1"
STARTUP_ATTESTATION_VERSION = "H8_DESKTOP_V1_STARTUP_ATTESTATION_V2"
ANCHOR_VERSION = "H8_DESKTOP_V1_MEASUREMENT_ANCHOR_V2"
RUNTIME_IDENTITY_VERSION = "H8_DESKTOP_V1_RUNTIME_IDENTITY_V2"
MEASUREMENT_DOMAIN = "SBP_LEX_DESKTOP_V1_MEASURED_STARTUP"
BASELINE_STATUSES = frozenset({"PENDING", "APPROVED", "RETIRED"})
DRIFT_CLASSES = frozenset({"approved", "warning", "critical", "unknown"})
MAX_BASELINES = 32
MAX_MEASURED_FILES = 2048
MAX_FAILURES = 128
MAX_EVENTS = 256
MAX_BASELINE_BYTES = 4_194_304
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASELINE_PATH = Path(__file__).with_name("approved_runtime_baselines.json")
DEFAULT_STATE_ROOT = (REPOSITORY_ROOT / "runtime_artifacts" / "measured_startup").resolve()
STARTUP_ATTESTATION_FIELDS = frozenset({
    "attestation_version", "startup_sequence", "startup_timestamp_evidence",
    "approved_baseline_identifier", "baseline_store_digest", "runtime_identity",
    "measurement_digest",
})
ANCHOR_FIELDS = frozenset({
    "anchor_version", "baseline_generation", "baseline_store_digest",
    "approved_baseline_identifier", "startup_sequence", "last_attestation_digest",
})

PUBLIC_ENVIRONMENT_NAMES = (
    "SBP_LEX_API_SECURITY_MODE", "SBP_LEX_REQUIRE_API_TOKEN",
    "SBP_LEX_MAX_API_BODY_BYTES", "SBP_LEX_MAX_REPLAY_COUNT",
    "SBP_LEX_SECURITY_STATE_STORE", "SBP_LEX_INTEGRITY_STORE",
    "SBP_LEX_TRANSPORT_PROFILE", "SBP_LEX_ALLOWED_TRANSPORT_PROFILES",
    "SBP_LEX_PROXY_MODE", "SBP_LEX_TRUSTED_PROXY_ADDRESSES",
    "SBP_LEX_TRUSTED_PROXY_NETWORKS", "SBP_LEX_MAX_FORWARD_HOPS",
    "SBP_LEX_REQUIRED_PROXY_IDENTITY", "SBP_LEX_ENABLE_REMOTE_TRANSPORT",
    "SBP_LEX_TLS_ENABLED", "SBP_LEX_BIND_ADDRESS", "SBP_LEX_TLS_CERT_FILE",
    "SBP_LEX_TLS_KEY_FILE", "SBP_LEX_TLS_CA_FILE",
    "SBP_LEX_TLS_REQUIRED_SERVICE_IDENTITY",
    "SBP_LEX_TLS_REQUIRED_CERTIFICATE_PURPOSE",
    "SBP_LEX_REVOKED_CERTIFICATE_FINGERPRINTS",
    "SBP_LEX_ADMISSION_REQUESTS_PER_WINDOW",
    "SBP_LEX_ADMISSION_AUTH_FAILURES_PER_WINDOW",
    "SBP_LEX_ADMISSION_MAX_CONCURRENT_TRAVERSALS",
    "SBP_LEX_ADMISSION_MAX_CONCURRENT_REPLAYS",
    "SBP_LEX_ADMISSION_MAX_CONCURRENT_CONNECTORS",
    "SBP_LEX_ADMISSION_MAX_EVENT_SUBSCRIBERS",
    "SBP_LEX_ADMISSION_MAX_EXPORTS",
    "SBP_LEX_ADMISSION_MAX_TRACKED_IDENTITIES",
    "SBP_LEX_ADMISSION_RETENTION_SECONDS",
    "SBP_LEX_ADMISSION_COOLDOWN_SECONDS",
    "SBP_LEX_ADMISSION_WINDOW_SECONDS",
    "SBP_LEX_APPROVED_RUNTIME_BASELINE_PATH",
    "SBP_LEX_MEASURED_STARTUP_STATE_ROOT",
    "SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY",
    "SBP_LEX_EXPECTED_SIGNER_FINGERPRINT",
    "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT",
    "PYTHONOPTIMIZE", "PYTHONCASEOK", "PYTHONUSERBASE",
    "PYTHONNOUSERSITE", "PYTHONSAFEPATH",
    "PYTEST_ADDOPTS", "PYTEST_PLUGINS",
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
)
SECRET_ENVIRONMENT_NAMES = (
    "SBP_LEX_API_TOKEN", "SBP_LEX_SIGNING_SECRET", "SBP_LEX_API_PRINCIPALS",
)


def configured_baseline_path() -> Path:
    """Return the active baseline store without freezing an import-time path."""
    return Path(
        os.environ.get(
            "SBP_LEX_APPROVED_RUNTIME_BASELINE_PATH",
            str(DEFAULT_BASELINE_PATH),
        )
    ).resolve(strict=False)


class MeasuredStartupError(RuntimeError):
    def __init__(self, reason: str, drift_class: str = "unknown") -> None:
        self.reason = reason
        self.drift_class = drift_class
        super().__init__(f"measured_startup_failed:{drift_class}:{reason}")


@dataclass(frozen=True)
class MeasurementPolicy:
    category_patterns: Mapping[str, tuple[str, ...]]
    required_paths: tuple[str, ...]
    public_environment_names: tuple[str, ...] = PUBLIC_ENVIRONMENT_NAMES
    secret_environment_names: tuple[str, ...] = SECRET_ENVIRONMENT_NAMES
    dependency_file: str = "requirements.txt"


DEFAULT_MEASUREMENT_POLICY = MeasurementPolicy(
    category_patterns={
        "software": (
            "main.py", "sbp_lex/**/*.py",
            "external_substrates/shared/*.py",
            "external_substrates/skg/*.py",
            "external_substrates/dtn/*.py",
        ),
        "configuration": (
            ".env.example", "VERSION", "requirements.txt", "pytest.ini", "sbp_lex/config/*.py",
        ),
        "policy": (
            "sbp_lex/**/*policy*.py", "sbp_lex/**/*rules*.py",
            "sbp_lex/config/security_config.py", "sbp_lex/config/thresholds.py",
            "sbp_lex/execution/execution_gate.py",
            "sbp_lex/execution/hard_entry_gate.py",
        ),
        "schema": (
            "sbp_lex/**/*.schema.json",
            "external_substrates/**/*.schema.json", "fixtures/**/*.schema.json",
            "sbp_lex/api/schema_validation.py",
        ),
        "trust_store": (
            "sbp_lex/security/pqc.py",
            "sbp_lex/security/pqc_provider.py",
            "sbp_lex/security/pqc_policy.py",
            "sbp_lex/local_trust/signing.py",
            "sbp_lex/local_trust/paths.py",
            "sbp_lex/supply_chain/provenance.py",
            "sbp_lex/ivvp/verifier.py",
        ),
        "documentation": (
            "BASELINE_LOCK.md", "DESKTOP_V1_OPERATOR_RELEASE_LOCK.md",
            "DEPLOYMENT_SECURITY.md", "docs/LOCAL_TRUST_ROOT_MANIFEST.md",
            "docs/LOCAL_EXECUTION_ENVIRONMENT_TRUST_ENVELOPE.md",
            "docs/STARTUP_EXECUTION_LINKAGE_ASSURANCE.md",
            "docs/DOUBLE_TRIPLE_HANDOVER_ASSURANCE.md",
            "docs/UNIVERSITY_HANDOVER_REGENERATION.md",
        ),
        "assurance": (
            "scripts/run_tests.bat", "scripts/run_tests.sh",
            "scripts/run_linkage_assurance.bat",
            "scripts/run_linkage_assurance.sh",
            "scripts/run_double_triple_assurance.bat",
            "scripts/run_double_triple_assurance.sh",
            "scripts/finalize_university_handover.bat",
            "scripts/finalize_university_handover.ps1",
            "sbp_lex/assurance/__init__.py",
            "sbp_lex/assurance/double_triple.py",
            "sbp_lex/assurance/handover_regeneration.py",
            "tests/test_double_triple_assurance.py",
            "tests/test_university_handover_regeneration.py",
            "tests/test_h7_deterministic_execution_integrity.py",
            "tests/test_h8_measured_startup_runtime_identity.py",
            "tests/test_phq_formal_deterministic_architecture.py",
            "tests/test_r1_canonical_backup_recovery.py",
            "tests/test_r2_supply_chain_build_provenance.py",
            "tests/test_r3_external_custody_recovery.py",
            "tests/test_r4_independent_verification_package.py",
            "tests/test_phase_18_7b_local_trust_manifest.py",
        ),
    },
    required_paths=(
        "main.py", "requirements.txt", "pytest.ini", "VERSION",
        "scripts/run_tests.bat", "scripts/run_tests.sh",
        "scripts/run_linkage_assurance.bat",
        "scripts/run_linkage_assurance.sh",
        "scripts/run_double_triple_assurance.bat",
        "scripts/run_double_triple_assurance.sh",
        "scripts/finalize_university_handover.bat",
        "scripts/finalize_university_handover.ps1",
        "docs/STARTUP_EXECUTION_LINKAGE_ASSURANCE.md",
        "docs/DOUBLE_TRIPLE_HANDOVER_ASSURANCE.md",
        "docs/UNIVERSITY_HANDOVER_REGENERATION.md",
        "sbp_lex/assurance/__init__.py",
        "sbp_lex/assurance/double_triple.py",
        "sbp_lex/assurance/handover_regeneration.py",
        "sbp_lex/runtime/canonical_runtime.py", "sbp_lex/runtime/measured_startup.py",
        "sbp_lex/runtime/schemas/startup_attestation.schema.json",
        "sbp_lex/security/pqc.py", "sbp_lex/security/pqc_provider.py",
        "sbp_lex/security/pqc_policy.py", "sbp_lex/config/environment.py",
        "external_substrates/shared/external_boundary.py",
        "external_substrates/shared/source_crypto.py",
        "external_substrates/shared/source_trust_store.py",
        "external_substrates/shared/external_replay_store.py",
        "sbp_lex/api/server.py", "sbp_lex/api/access_control.py",
        "sbp_lex/execution/execution_gate.py", "sbp_lex/execution/capability.py",
        "sbp_lex/execution/capability_store.py",
        "sbp_lex/execution/schemas/execution_capability.schema.json",
        "sbp_lex/execution/schemas/execution_traversal_authority.schema.json",
        "sbp_lex/execution/schemas/adapter_completion_evidence.schema.json",
        "sbp_lex/execution/schemas/post_execution_attestation.schema.json",
        "sbp_lex/execution/schemas/capability_lifecycle_record.schema.json",
        "sbp_lex/pipeline/dual_runner.py",
        "sbp_lex/formal/assurance.py", "sbp_lex/formal/verifier.py",
        "sbp_lex/formal/schemas/formal_state.schema.json",
        "sbp_lex/formal/schemas/lineage_node.schema.json",
        "sbp_lex/formal/schemas/transition_record.schema.json",
        "sbp_lex/local_trust/signing.py", "sbp_lex/local_trust/paths.py",
        "sbp_lex/supply_chain/provenance.py", "sbp_lex/ivvp/verifier.py",
        "sbp_lex/recovery/__init__.py",
        "sbp_lex/recovery/common.py",
        "sbp_lex/recovery/inventory.py",
        "sbp_lex/recovery/manifest.py",
        "sbp_lex/recovery/backup.py",
        "sbp_lex/recovery/restore.py",
        "sbp_lex/recovery/recovery_drill.py",
        "sbp_lex/recovery/schemas/recovery_inventory.schema.json",
        "sbp_lex/recovery/schemas/sealed_backup_manifest.schema.json",
        "tests/test_h7_deterministic_execution_integrity.py",
        "tests/test_h8_measured_startup_runtime_identity.py",
        "tests/test_phq_formal_deterministic_architecture.py",
        "tests/test_r1_canonical_backup_recovery.py",
        "tests/test_r2_supply_chain_build_provenance.py",
        "tests/test_r3_external_custody_recovery.py",
        "tests/test_r4_independent_verification_package.py",
        "tests/test_phase_18_7b_local_trust_manifest.py",
        "tests/test_double_triple_assurance.py",
        "tests/test_university_handover_regeneration.py",
    ),
)


@dataclass(frozen=True)
class DriftFinding:
    drift_class: str
    reason: str
    component: str

    def as_payload(self) -> dict[str, str]:
        return {
            "drift_class": self.drift_class,
            "reason": self.reason,
            "component": self.component,
        }


class MeasurementEventBuffer:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: deque[dict[str, Any]] = deque(maxlen=MAX_EVENTS)
        self._sequence = 0

    def record(self, event_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        safe = {
            str(key)[:64]: generate_digest({"domain": MEASUREMENT_DOMAIN, "value": value})
            for key, value in sorted(dict(payload).items())[:16]
        }
        with self._lock:
            self._sequence += 1
            event = {
                "sequence": self._sequence,
                "event_type": event_type[:64],
                "evidence": safe,
            }
            self._events.append(event)
            return dict(event)

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self._events]

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self._sequence = 0


MEASUREMENT_EVENTS = MeasurementEventBuffer()


def _relative(root: Path, path: Path) -> str:
    resolved = path.resolve(strict=False)
    if not resolved.is_relative_to(root):
        raise MeasuredStartupError("measurement_path_escape", "unknown")
    return resolved.relative_to(root).as_posix()


def _file_record(root: Path, path: Path) -> dict[str, Any]:
    relative = _relative(root, path)
    if path.is_symlink():
        raise MeasuredStartupError(f"measured_file_symlink:{relative}", "unknown")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise MeasuredStartupError(f"measurement_read_failed:{relative}", "unknown") from exc
    return {"path": relative, "sha256": sha256(raw).hexdigest(), "size_bytes": len(raw)}


def _collect_category(root: Path, patterns: Sequence[str]) -> list[dict[str, Any]]:
    paths: dict[str, Path] = {}
    for pattern in patterns:
        for path in root.glob(pattern):
            if path.is_file() and "__pycache__" not in path.parts:
                paths[_relative(root, path)] = path
    if len(paths) > MAX_MEASURED_FILES:
        raise MeasuredStartupError("measured_file_cardinality_exceeded", "unknown")
    return [_file_record(root, paths[key]) for key in sorted(paths)]


def _environment_records(
    environ: Mapping[str, str], policy: MeasurementPolicy,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for name in sorted(policy.public_environment_names):
        value = environ.get(name)
        records.append({
            "name": name,
            "state": "ABSENT" if value is None else "PRESENT",
            "value": None if value is None else value,
            "sensitive": False,
        })
    for name in sorted(policy.secret_environment_names):
        value = environ.get(name)
        records.append({
            "name": name,
            "state": "ABSENT" if value is None else "PRESENT",
            "value_digest": None if value is None else generate_digest({
                "domain": "H8_SECRET_CONFIGURATION_MEASUREMENT", "name": name, "value": value,
            }),
            "value_length": 0 if value is None else len(value),
            "sensitive": True,
        })
    return records


_REQUIREMENT_NAME = re.compile(r"^([A-Za-z0-9_.-]+)")


def _dependency_records(root: Path, policy: MeasurementPolicy) -> list[dict[str, Any]]:
    path = root / policy.dependency_file
    if path.is_symlink():
        raise MeasuredStartupError("dependency_file_symlink", "unknown")
    if not path.is_file():
        raise MeasuredStartupError("dependency_file_missing", "unknown")
    records: list[dict[str, Any]] = []
    for raw_line in path.read_text("utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _REQUIREMENT_NAME.match(line)
        if not match:
            raise MeasuredStartupError("dependency_requirement_invalid", "unknown")
        name = match.group(1)
        try:
            version = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise MeasuredStartupError(f"dependency_missing:{name}", "critical") from exc
        records.append({"name": name.lower(), "declared": line, "installed_version": version})
    return sorted(records, key=lambda item: item["name"])


def _executable_record() -> dict[str, Any]:
    executable = Path(sys.executable).resolve(strict=False)
    try:
        digest = sha256(executable.read_bytes()).hexdigest()
    except OSError as exc:
        raise MeasuredStartupError("python_executable_measurement_failed", "unknown") from exc
    return {
        "path": str(executable),
        "sha256": digest,
        "python_version": platform.python_version(),
        "implementation": platform.python_implementation(),
        "architecture": platform.machine(),
    }


def measure_runtime(
    repository_root: Path | str = REPOSITORY_ROOT, *,
    policy: MeasurementPolicy = DEFAULT_MEASUREMENT_POLICY,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    root = Path(repository_root).resolve()
    for required in policy.required_paths:
        candidate = root / required
        path = candidate.resolve(strict=False)
        if (
            candidate.is_symlink()
            or not path.is_relative_to(root)
            or not path.is_file()
        ):
            raise MeasuredStartupError(f"required_measurement_missing:{required}", "unknown")
    categories = {
        category: _collect_category(root, patterns)
        for category, patterns in sorted(policy.category_patterns.items())
    }
    scoped_paths = {
        str(record["path"])
        for records in categories.values()
        for record in records
    }
    scoped_paths.add(policy.dependency_file)
    unscoped = sorted(set(policy.required_paths) - scoped_paths)
    if unscoped:
        raise MeasuredStartupError(
            f"required_measurement_unscoped:{unscoped[0]}",
            "unknown",
        )
    environment = _environment_records(os.environ if environ is None else environ, policy)
    dependencies = _dependency_records(root, policy)
    executable = _executable_record()
    category_digests = {
        category: generate_digest(records) for category, records in sorted(categories.items())
    }
    category_digests["environment"] = generate_digest(environment)
    category_digests["dependencies"] = generate_digest(dependencies)
    category_digests["executable"] = generate_digest(executable)
    payload = {
        "measurement_version": MEASUREMENT_VERSION,
        "categories": categories,
        "environment": environment,
        "dependencies": dependencies,
        "executable": executable,
        "category_digests": category_digests,
    }
    return {**payload, "measurement_digest": generate_digest(payload)}


def runtime_identity_for(measurement: Mapping[str, Any], baseline_identifier: str) -> str:
    digests = measurement.get("category_digests")
    if (
        not isinstance(digests, Mapping)
        or not digests
        or any(
            not isinstance(name, str) or not _is_digest(digest)
            for name, digest in digests.items()
        )
    ):
        raise MeasuredStartupError("measurement_category_digests_invalid", "unknown")
    bound_digests = {
        str(name): digest
        for name, digest in sorted(digests.items())
    }
    return generate_digest({
        "identity_version": RUNTIME_IDENTITY_VERSION,
        "approved_baseline_identifier": baseline_identifier,
        "category_digests": bound_digests,
    })


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def _parse_aware_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None


def _validate_measurement_contract(measurement: Mapping[str, Any]) -> None:
    if set(measurement) != {
        "measurement_version", "categories", "environment", "dependencies",
        "executable", "category_digests", "measurement_digest",
    }:
        raise MeasuredStartupError(
            "baseline_measurement_schema_invalid", "unknown",
        )
    if measurement.get("measurement_version") != MEASUREMENT_VERSION:
        raise MeasuredStartupError(
            "baseline_measurement_version_invalid", "unknown",
        )
    categories = measurement.get("categories")
    category_digests = measurement.get("category_digests")
    if (
        not isinstance(categories, Mapping)
        or not categories
        or any(
            not isinstance(name, str) or not isinstance(records, list)
            for name, records in categories.items()
        )
        or not isinstance(measurement.get("environment"), list)
        or not isinstance(measurement.get("dependencies"), list)
        or not isinstance(measurement.get("executable"), Mapping)
        or not isinstance(category_digests, Mapping)
        or not category_digests
        or any(
            not isinstance(name, str) or not _is_digest(digest)
            for name, digest in category_digests.items()
        )
        or not _is_digest(measurement.get("measurement_digest"))
    ):
        raise MeasuredStartupError(
            "baseline_measurement_structure_invalid", "unknown",
        )
    expected_digest_names = set(categories) | {
        "environment", "dependencies", "executable",
    }
    if set(category_digests) != expected_digest_names:
        raise MeasuredStartupError(
            "baseline_category_digest_contract_invalid", "unknown",
        )
    total_files = 0
    for category, records in categories.items():
        if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", category) is None:
            raise MeasuredStartupError(
                "baseline_category_name_invalid", "unknown",
            )
        paths: list[str] = []
        for record in records:
            if not isinstance(record, Mapping) or set(record) != {
                "path", "sha256", "size_bytes",
            }:
                raise MeasuredStartupError(
                    "baseline_file_measurement_invalid", "unknown",
                )
            path = record.get("path")
            size = record.get("size_bytes")
            if (
                not isinstance(path, str)
                or not path
                or "\\" in path
                or PurePosixPath(path).is_absolute()
                or ".." in PurePosixPath(path).parts
                or PurePosixPath(path).as_posix() != path
                or not _is_digest(record.get("sha256"))
                or not isinstance(size, int)
                or isinstance(size, bool)
                or size < 0
            ):
                raise MeasuredStartupError(
                    "baseline_file_measurement_invalid", "unknown",
                )
            paths.append(path)
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise MeasuredStartupError(
                "baseline_file_measurement_order_invalid", "unknown",
            )
        total_files += len(records)
    if total_files > MAX_MEASURED_FILES:
        raise MeasuredStartupError(
            "baseline_file_measurement_cardinality_invalid", "unknown",
        )
    environment = measurement["environment"]
    environment_names: list[str] = []
    public_environment_names: list[str] = []
    secret_environment_names: list[str] = []
    sensitive_block_started = False
    for record in environment:
        if not isinstance(record, Mapping):
            raise MeasuredStartupError(
                "baseline_environment_measurement_invalid", "unknown",
            )
        name = record.get("name")
        state = record.get("state")
        sensitive = record.get("sensitive")
        if (
            not isinstance(name, str)
            or not name
            or state not in {"ABSENT", "PRESENT"}
            or not isinstance(sensitive, bool)
        ):
            raise MeasuredStartupError(
                "baseline_environment_measurement_invalid", "unknown",
            )
        if sensitive is False:
            if sensitive_block_started:
                raise MeasuredStartupError(
                    "baseline_environment_measurement_order_invalid",
                    "unknown",
                )
            if (
                set(record) != {"name", "state", "value", "sensitive"}
                or (
                    state == "ABSENT"
                    and record.get("value") is not None
                )
                or (
                    state == "PRESENT"
                    and not isinstance(record.get("value"), str)
                )
            ):
                raise MeasuredStartupError(
                    "baseline_environment_measurement_invalid", "unknown",
                )
            public_environment_names.append(name)
        else:
            sensitive_block_started = True
            length = record.get("value_length")
            digest = record.get("value_digest")
            if (
                set(record) != {
                    "name", "state", "value_digest",
                    "value_length", "sensitive",
                }
                or not isinstance(length, int)
                or isinstance(length, bool)
                or length < 0
                or (
                    state == "ABSENT"
                    and (digest is not None or length != 0)
                )
                or (
                    state == "PRESENT"
                    and (not _is_digest(digest))
                )
            ):
                raise MeasuredStartupError(
                    "baseline_environment_measurement_invalid", "unknown",
                )
            secret_environment_names.append(name)
        environment_names.append(name)
    if (
        public_environment_names != sorted(public_environment_names)
        or secret_environment_names != sorted(secret_environment_names)
        or len(environment_names) != len(set(environment_names))
    ):
        raise MeasuredStartupError(
            "baseline_environment_measurement_order_invalid", "unknown",
        )
    dependency_names: list[str] = []
    for record in measurement["dependencies"]:
        if (
            not isinstance(record, Mapping)
            or set(record) != {"name", "declared", "installed_version"}
            or not isinstance(record.get("name"), str)
            or re.fullmatch(
                r"[a-z0-9][a-z0-9_.-]{0,127}",
                str(record.get("name", "")),
            ) is None
            or not isinstance(record.get("declared"), str)
            or not record.get("declared")
            or not isinstance(record.get("installed_version"), str)
            or not record.get("installed_version")
        ):
            raise MeasuredStartupError(
                "baseline_dependency_measurement_invalid", "unknown",
            )
        dependency_names.append(str(record["name"]))
    if (
        dependency_names != sorted(dependency_names)
        or len(dependency_names) != len(set(dependency_names))
    ):
        raise MeasuredStartupError(
            "baseline_dependency_measurement_order_invalid", "unknown",
        )
    executable = measurement["executable"]
    if (
        set(executable) != {
            "path", "sha256", "python_version",
            "implementation", "architecture",
        }
        or not isinstance(executable.get("path"), str)
        or not executable.get("path")
        or not _is_digest(executable.get("sha256"))
        or any(
            not isinstance(executable.get(field), str)
            or not executable.get(field)
            for field in (
                "python_version", "implementation", "architecture",
            )
        )
    ):
        raise MeasuredStartupError(
            "baseline_executable_measurement_invalid", "unknown",
        )
    expected_category_digests = {
        name: generate_digest(records)
        for name, records in categories.items()
    }
    expected_category_digests.update({
        "environment": generate_digest(measurement["environment"]),
        "dependencies": generate_digest(measurement["dependencies"]),
        "executable": generate_digest(measurement["executable"]),
    })
    if dict(category_digests) != expected_category_digests:
        raise MeasuredStartupError(
            "baseline_category_digest_mismatch", "unknown",
        )
    measurement_payload = {
        key: value
        for key, value in measurement.items()
        if key != "measurement_digest"
    }
    if measurement["measurement_digest"] != generate_digest(
        measurement_payload
    ):
        raise MeasuredStartupError(
            "baseline_measurement_corrupted", "unknown",
        )


def baseline_record(
    identifier: str, measurement: Mapping[str, Any], *, sequence: int,
    status: str = "PENDING", created_at: str | None = None,
    approval_reference: str | None = None,
    prior_baseline_identifier: str | None = None,
) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Z0-9][A-Z0-9_.-]{7,127}", identifier):
        raise MeasuredStartupError("baseline_identifier_invalid", "unknown")
    if (
        status not in BASELINE_STATUSES
        or not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence <= 0
    ):
        raise MeasuredStartupError("baseline_record_invalid", "unknown")
    if status == "APPROVED" and (
        not isinstance(approval_reference, str) or not approval_reference.strip()
    ):
        raise MeasuredStartupError("approved_baseline_missing_approval", "unknown")
    if approval_reference is not None and (
        not isinstance(approval_reference, str) or not approval_reference.strip()
    ):
        raise MeasuredStartupError("baseline_approval_reference_invalid", "unknown")
    if prior_baseline_identifier is not None and (
        not isinstance(prior_baseline_identifier, str)
        or re.fullmatch(
            r"[A-Z0-9][A-Z0-9_.-]{7,127}", prior_baseline_identifier,
        ) is None
    ):
        raise MeasuredStartupError("prior_baseline_identifier_invalid", "unknown")
    timestamp = created_at or datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat()
    if _parse_aware_timestamp(timestamp) is None:
        raise MeasuredStartupError("baseline_created_at_invalid", "unknown")
    if not isinstance(measurement, Mapping):
        raise MeasuredStartupError(
            "baseline_measurement_schema_invalid", "unknown",
        )
    _validate_measurement_contract(measurement)
    measured = json.loads(json.dumps(measurement))
    return {
        "baseline_record_version": BASELINE_RECORD_VERSION,
        "baseline_identifier": identifier,
        "sequence": sequence,
        "status": status,
        "created_at": timestamp,
        "approval_reference": approval_reference,
        "prior_baseline_identifier": prior_baseline_identifier,
        "measurement": measured,
        "measurement_digest": measured.get("measurement_digest"),
        "runtime_identity": runtime_identity_for(measured, identifier),
    }


def _store_wrapper(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = json.loads(json.dumps(payload))
    return {
        "payload": value,
        "payload_digest": generate_digest(value),
        "integrity_signature": sign_payload({"integrity_domain": MEASUREMENT_DOMAIN, "payload": value}),
    }


def create_baseline_store(initial: Mapping[str, Any]) -> dict[str, Any]:
    payload = {
        "baseline_store_version": BASELINE_STORE_VERSION,
        "generation": 1,
        "baselines": [json.loads(json.dumps(initial))],
    }
    return _store_wrapper(payload)


def validate_baseline_store(store: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(store, Mapping) or set(store) != {"payload", "payload_digest", "integrity_signature"}:
        raise MeasuredStartupError("baseline_store_schema_invalid", "unknown")
    payload = store.get("payload")
    if not isinstance(payload, Mapping) or set(payload) != {"baseline_store_version", "generation", "baselines"}:
        raise MeasuredStartupError("baseline_store_payload_invalid", "unknown")
    if payload.get("baseline_store_version") != BASELINE_STORE_VERSION:
        raise MeasuredStartupError("baseline_store_version_invalid", "unknown")
    if store.get("payload_digest") != generate_digest(payload) or not verify_signature(
        {"integrity_domain": MEASUREMENT_DOMAIN, "payload": dict(payload)},
        store.get("integrity_signature", {}),
    ):
        raise MeasuredStartupError("baseline_store_integrity_invalid", "unknown")
    generation = payload.get("generation")
    baselines = payload.get("baselines")
    if (
        not isinstance(generation, int)
        or isinstance(generation, bool)
        or generation <= 0
        or not isinstance(baselines, list)
    ):
        raise MeasuredStartupError("baseline_store_generation_invalid", "unknown")
    if not baselines or len(baselines) > MAX_BASELINES:
        raise MeasuredStartupError("baseline_store_cardinality_invalid", "unknown")
    identifiers: set[str] = set()
    approved = 0
    previous_sequence = 0
    previous_created_at: datetime | None = None
    for record in baselines:
        if not isinstance(record, Mapping) or set(record) != {
            "baseline_record_version", "baseline_identifier", "sequence", "status",
            "created_at", "approval_reference", "prior_baseline_identifier",
            "measurement", "measurement_digest", "runtime_identity",
        }:
            raise MeasuredStartupError("baseline_record_schema_invalid", "unknown")
        identifier = record.get("baseline_identifier")
        sequence = record.get("sequence")
        status = record.get("status")
        measurement = record.get("measurement")
        if (
            record.get("baseline_record_version") != BASELINE_RECORD_VERSION
            or not isinstance(identifier, str)
            or re.fullmatch(
                r"[A-Z0-9][A-Z0-9_.-]{7,127}", identifier,
            ) is None
        ):
            raise MeasuredStartupError(
                "baseline_identifier_invalid", "unknown",
            )
        if identifier in identifiers:
            raise MeasuredStartupError("duplicate_baseline_identifier", "unknown")
        if (
            not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or sequence <= previous_sequence
        ):
            raise MeasuredStartupError("baseline_sequence_invalid", "unknown")
        if (
            not isinstance(status, str)
            or status not in BASELINE_STATUSES
            or not isinstance(measurement, Mapping)
        ):
            raise MeasuredStartupError("baseline_record_state_invalid", "unknown")
        created_at = _parse_aware_timestamp(record.get("created_at"))
        if (
            created_at is None
            or (
                previous_created_at is not None
                and created_at < previous_created_at
            )
        ):
            raise MeasuredStartupError("baseline_created_at_invalid", "unknown")
        approval_reference = record.get("approval_reference")
        if (
            approval_reference is not None
            and (
                not isinstance(approval_reference, str)
                or not approval_reference.strip()
            )
        ):
            raise MeasuredStartupError(
                "baseline_approval_reference_invalid", "unknown",
            )
        prior_identifier = record.get("prior_baseline_identifier")
        if prior_identifier is not None and (
            not isinstance(prior_identifier, str)
            or prior_identifier not in identifiers
        ):
            raise MeasuredStartupError(
                "baseline_prior_lineage_invalid", "unknown",
            )
        if (
            status == "APPROVED"
            and sequence > 1
            and prior_identifier is None
        ):
            raise MeasuredStartupError(
                "approved_baseline_prior_lineage_missing", "unknown",
            )
        if record.get("measurement_digest") != measurement.get("measurement_digest"):
            raise MeasuredStartupError("baseline_measurement_digest_mismatch", "unknown")
        _validate_measurement_contract(measurement)
        measurement_payload = {key: value for key, value in measurement.items() if key != "measurement_digest"}
        if measurement.get("measurement_digest") != generate_digest(measurement_payload):
            raise MeasuredStartupError("baseline_measurement_corrupted", "unknown")
        if (
            not _is_digest(record.get("runtime_identity"))
            or record.get("runtime_identity")
            != runtime_identity_for(measurement, identifier)
        ):
            raise MeasuredStartupError("baseline_runtime_identity_mismatch", "unknown")
        if status == "APPROVED":
            approved += 1
            if (
                not isinstance(approval_reference, str)
                or not approval_reference.strip()
            ):
                raise MeasuredStartupError("approved_baseline_missing_approval", "unknown")
        identifiers.add(identifier)
        previous_sequence = sequence
        previous_created_at = created_at
    if approved != 1:
        raise MeasuredStartupError("approved_baseline_cardinality_invalid", "unknown")
    if generation < previous_sequence:
        raise MeasuredStartupError("baseline_generation_rollback", "unknown")
    return json.loads(json.dumps(payload))


def _resign_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    changed = dict(payload)
    changed["generation"] = int(payload["generation"]) + 1
    return _store_wrapper(changed)


def add_pending_baseline(store: Mapping[str, Any], record: Mapping[str, Any]) -> dict[str, Any]:
    payload = validate_baseline_store(store)
    if record.get("status") != "PENDING":
        raise MeasuredStartupError("new_baseline_must_be_pending", "critical")
    identifiers = {item["baseline_identifier"] for item in payload["baselines"]}
    if record.get("baseline_identifier") in identifiers:
        raise MeasuredStartupError("duplicate_baseline_identifier", "critical")
    expected_sequence = max(item["sequence"] for item in payload["baselines"]) + 1
    if record.get("sequence") != expected_sequence:
        raise MeasuredStartupError("baseline_sequence_invalid", "critical")
    payload["baselines"].append(json.loads(json.dumps(record)))
    return _resign_payload(payload)


def approve_pending_baseline(
    store: Mapping[str, Any], identifier: str, *, approval_reference: str,
    retire_approved_identifier: str,
) -> dict[str, Any]:
    if (
        not isinstance(approval_reference, str)
        or not approval_reference.strip()
    ):
        raise MeasuredStartupError("explicit_baseline_approval_required", "critical")
    payload = validate_baseline_store(store)
    records = payload["baselines"]
    pending = next((item for item in records if item["baseline_identifier"] == identifier), None)
    approved = next((item for item in records if item["status"] == "APPROVED"), None)
    if pending is None or pending["status"] != "PENDING":
        raise MeasuredStartupError("pending_baseline_not_found", "critical")
    if approved is None or approved["baseline_identifier"] != retire_approved_identifier:
        raise MeasuredStartupError("approved_baseline_retirement_mismatch", "critical")
    for index, item in enumerate(records):
        if item["baseline_identifier"] == retire_approved_identifier:
            records[index] = {**item, "status": "RETIRED"}
        elif item["baseline_identifier"] == identifier:
            records[index] = {
                **item, "status": "APPROVED", "approval_reference": approval_reference.strip(),
                "prior_baseline_identifier": retire_approved_identifier,
            }
    return _resign_payload(payload)


def _load_json(path: Path, *, maximum: int = MAX_BASELINE_BYTES) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        if not raw or len(raw) > maximum:
            raise ValueError
        value = loads_strict_json(raw.decode("utf-8"))
    except Exception as exc:
        raise MeasuredStartupError(f"measurement_store_corrupted:{path.name}", "unknown") from exc
    if not isinstance(value, dict):
        raise MeasuredStartupError(f"measurement_store_invalid:{path.name}", "unknown")
    return value


def _atomic_write(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > MAX_BASELINE_BYTES:
        raise MeasuredStartupError("measurement_store_capacity_exceeded", "unknown")
    temp = path.with_name(path.name + f".{uuid.uuid4().hex}.tmp")
    try:
        with temp.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except OSError as exc:
        temp.unlink(missing_ok=True)
        raise MeasuredStartupError("measurement_store_write_failed", "unknown") from exc


def write_baseline_store(path: Path | str, store: Mapping[str, Any]) -> Path:
    target = Path(path).resolve(strict=False)
    validate_baseline_store(store)
    _atomic_write(target, store)
    return target


def load_baseline_store(path: Path | str = DEFAULT_BASELINE_PATH) -> dict[str, Any]:
    target = Path(path).resolve(strict=False)
    if not target.is_file():
        raise MeasuredStartupError("approved_baseline_missing", "unknown")
    store = _load_json(target)
    validate_baseline_store(store)
    return store


def approved_baseline(payload: Mapping[str, Any], requested: str | None = None) -> dict[str, Any]:
    approved = [item for item in payload["baselines"] if item["status"] == "APPROVED"]
    if len(approved) != 1:
        raise MeasuredStartupError("approved_baseline_cardinality_invalid", "unknown")
    item = approved[0]
    if requested is not None and requested != item["baseline_identifier"]:
        raise MeasuredStartupError("approved_baseline_identifier_mismatch", "critical")
    return item


def _baseline_descends_from(
    payload: Mapping[str, Any], baseline: Mapping[str, Any], ancestor_identifier: str,
) -> bool:
    by_identifier = {
        str(item["baseline_identifier"]): item
        for item in payload.get("baselines", ())
        if isinstance(item, Mapping) and item.get("baseline_identifier")
    }
    cursor = baseline
    visited: set[str] = set()
    while str(cursor.get("baseline_identifier", "")) != ancestor_identifier:
        identifier = str(cursor.get("baseline_identifier", ""))
        prior_identifier = str(cursor.get("prior_baseline_identifier", ""))
        if not identifier or identifier in visited or not prior_identifier:
            return False
        visited.add(identifier)
        prior = by_identifier.get(prior_identifier)
        if prior is None or int(prior.get("sequence", 0)) >= int(cursor.get("sequence", 0)):
            return False
        cursor = prior
    return True


def compare_measurements(
    current: Mapping[str, Any], expected: Mapping[str, Any],
) -> list[DriftFinding]:
    findings: list[DriftFinding] = []
    current_digests = current.get("category_digests", {})
    expected_digests = expected.get("category_digests", {})
    keys = sorted(set(current_digests) | set(expected_digests))
    for key in keys:
        if current_digests.get(key) != expected_digests.get(key):
            findings.append(DriftFinding("critical", f"{key}_digest_mismatch", key))
    if current.get("measurement_digest") != expected.get("measurement_digest") and not findings:
        findings.append(DriftFinding("critical", "measurement_digest_mismatch", "measurement"))
    return findings[:MAX_FAILURES]


def drift_class_for(findings: Sequence[DriftFinding]) -> str:
    if not findings:
        return "approved"
    if any(item.drift_class == "unknown" for item in findings):
        return "unknown"
    if any(item.drift_class == "critical" for item in findings):
        return "critical"
    return "warning"


def _anchor_wrapper(payload: Mapping[str, Any]) -> dict[str, Any]:
    return _store_wrapper(payload)


def _validate_anchor(anchor: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(anchor, Mapping) or set(anchor) != {"payload", "payload_digest", "integrity_signature"}:
        raise MeasuredStartupError("measurement_anchor_schema_invalid", "unknown")
    payload = anchor.get("payload")
    if (
        not isinstance(payload, Mapping)
        or set(payload) != ANCHOR_FIELDS
        or payload.get("anchor_version") != ANCHOR_VERSION
        or not isinstance(payload.get("baseline_generation"), int)
        or isinstance(payload.get("baseline_generation"), bool)
        or payload.get("baseline_generation", 0) <= 0
        or not isinstance(payload.get("startup_sequence"), int)
        or isinstance(payload.get("startup_sequence"), bool)
        or payload.get("startup_sequence", 0) <= 0
        or any(
            not isinstance(payload.get(field), str)
            or re.fullmatch(r"[0-9a-f]{64}", payload[field]) is None
            for field in (
                "baseline_store_digest", "last_attestation_digest",
            )
        )
        or not isinstance(payload.get("approved_baseline_identifier"), str)
        or not payload.get("approved_baseline_identifier")
    ):
        raise MeasuredStartupError("measurement_anchor_invalid", "unknown")
    if anchor.get("payload_digest") != generate_digest(payload) or not verify_signature(
        {"integrity_domain": MEASUREMENT_DOMAIN, "payload": dict(payload)},
        anchor.get("integrity_signature", {}),
    ):
        raise MeasuredStartupError("measurement_anchor_integrity_invalid", "unknown")
    return json.loads(json.dumps(payload))


def verify_startup_attestation(
    attestation: Mapping[str, Any], anchor_payload: Mapping[str, Any] | None = None,
) -> bool:
    if not isinstance(attestation, Mapping) or set(attestation) != {
        "payload", "payload_digest", "integrity_signature"
    }:
        return False
    payload = attestation.get("payload")
    if (
        not isinstance(payload, Mapping)
        or set(payload) != STARTUP_ATTESTATION_FIELDS
        or payload.get("attestation_version") != STARTUP_ATTESTATION_VERSION
        or not isinstance(payload.get("startup_sequence"), int)
        or isinstance(payload.get("startup_sequence"), bool)
        or payload.get("startup_sequence", 0) <= 0
        or not isinstance(payload.get("approved_baseline_identifier"), str)
        or not payload.get("approved_baseline_identifier")
        or any(
            not isinstance(payload.get(field), str)
            or re.fullmatch(r"[0-9a-f]{64}", payload[field]) is None
            for field in (
                "baseline_store_digest", "runtime_identity", "measurement_digest",
            )
        )
    ):
        return False
    if _parse_aware_timestamp(
        payload.get("startup_timestamp_evidence")
    ) is None:
        return False
    if attestation.get("payload_digest") != generate_digest(payload) or not verify_signature(
        {"integrity_domain": MEASUREMENT_DOMAIN, "payload": dict(payload)},
        attestation.get("integrity_signature", {}),
    ):
        return False
    if anchor_payload is not None:
        anchor_sequence = anchor_payload.get("startup_sequence")
        if (
            not isinstance(anchor_sequence, int)
            or isinstance(anchor_sequence, bool)
            or anchor_sequence < 0
            or payload["startup_sequence"] <= anchor_sequence
        ):
            return False
    return True


class MeasuredStartupService:
    def __init__(
        self, *, repository_root: Path = REPOSITORY_ROOT,
        baseline_path: Path | None = None,
        state_root: Path | None = None,
        policy: MeasurementPolicy = DEFAULT_MEASUREMENT_POLICY,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self.repository_root = repository_root.resolve()
        runtime_environment = os.environ if environ is None else environ
        selected_baseline_path = baseline_path or Path(
            runtime_environment.get(
                "SBP_LEX_APPROVED_RUNTIME_BASELINE_PATH",
                str(DEFAULT_BASELINE_PATH),
            )
        )
        selected_state_root = state_root or Path(
            runtime_environment.get(
                "SBP_LEX_MEASURED_STARTUP_STATE_ROOT",
                str(DEFAULT_STATE_ROOT),
            )
        )
        self.baseline_path = selected_baseline_path.resolve(strict=False)
        self.state_root = selected_state_root.resolve(strict=False)
        self.policy = policy
        self.environ = environ
        self.anchor_path = self.state_root / "measurement.anchor.json"
        self.attestation_path = self.state_root / "startup.attestation.json"
        self.failure_path = self.state_root / "startup.failure.json"
        self._lock = threading.RLock()
        self._validated = False
        self._runtime_identity: str | None = None
        self._baseline_identifier: str | None = None
        self._measurement_digest: str | None = None
        self._startup_attestation_digest: str | None = None
        self._startup_sequence: int | None = None

    def _invalidate_runtime_binding(self) -> None:
        self._validated = False
        self._runtime_identity = None
        self._baseline_identifier = None
        self._measurement_digest = None
        self._startup_attestation_digest = None
        self._startup_sequence = None

    def _anchor(self) -> dict[str, Any] | None:
        if not self.anchor_path.exists():
            return None
        return _validate_anchor(_load_json(self.anchor_path))

    def _persisted_attestation(
        self, anchor: Mapping[str, Any] | None,
    ) -> dict[str, Any] | None:
        attestation_exists = self.attestation_path.exists()
        if anchor is None:
            if attestation_exists:
                raise MeasuredStartupError(
                    "startup_attestation_orphaned", "unknown",
                )
            return None
        if not attestation_exists:
            raise MeasuredStartupError(
                "startup_attestation_missing", "unknown",
            )
        attestation = _load_json(self.attestation_path)
        if not verify_startup_attestation(attestation):
            raise MeasuredStartupError(
                "startup_attestation_integrity_invalid", "unknown",
            )
        if generate_digest(attestation) != anchor.get(
            "last_attestation_digest"
        ):
            raise MeasuredStartupError(
                "startup_attestation_anchor_mismatch", "critical",
            )
        payload = attestation["payload"]
        expected = {
            "startup_sequence": anchor.get("startup_sequence"),
            "approved_baseline_identifier": anchor.get(
                "approved_baseline_identifier"
            ),
            "baseline_store_digest": anchor.get("baseline_store_digest"),
        }
        if any(
            payload.get(field) != value
            for field, value in expected.items()
        ):
            raise MeasuredStartupError(
                "startup_attestation_anchor_binding_invalid", "critical",
            )
        return attestation

    def _failure(self, error: MeasuredStartupError, findings: Sequence[DriftFinding] = ()) -> None:
        payload = {
            "failure_version": "H8_DESKTOP_V1_STARTUP_FAILURE_V1",
            "drift_class": error.drift_class,
            "reason": error.reason,
            "findings": [item.as_payload() for item in findings[:MAX_FAILURES]],
        }
        MEASUREMENT_EVENTS.record("measured_startup_rejected", payload)
        try:
            _atomic_write(self.failure_path, _store_wrapper(payload))
        except Exception:
            pass

    def validate_startup(self, *, startup_time: datetime | None = None, persist: bool = True) -> dict[str, Any]:
        with self._lock:
            findings: list[DriftFinding] = []
            try:
                store = load_baseline_store(self.baseline_path)
                payload = validate_baseline_store(store)
                requested = (self.environ if self.environ is not None else os.environ).get(
                    "SBP_LEX_APPROVED_RUNTIME_BASELINE"
                )
                baseline = approved_baseline(payload, requested)
                anchor = self._anchor() if persist else None
                prior_attestation = (
                    self._persisted_attestation(anchor) if persist else None
                )
                if anchor is not None:
                    generation = int(payload["generation"])
                    anchor_generation = int(anchor.get("baseline_generation", 0))
                    if generation < anchor_generation:
                        raise MeasuredStartupError("baseline_measurement_rollback", "critical")
                    if generation == anchor_generation and store["payload_digest"] != anchor.get("baseline_store_digest"):
                        raise MeasuredStartupError("baseline_measurement_replacement", "critical")
                    if (
                        generation == anchor_generation
                        and baseline["baseline_identifier"]
                        != anchor.get("approved_baseline_identifier")
                    ):
                        raise MeasuredStartupError(
                            "approved_baseline_anchor_replacement", "critical",
                        )
                    if generation > anchor_generation and not _baseline_descends_from(
                        payload, baseline, str(anchor.get("approved_baseline_identifier", "")),
                    ):
                        raise MeasuredStartupError("baseline_update_lineage_invalid", "critical")
                    anchored_baseline = next(
                        (
                            item
                            for item in payload["baselines"]
                            if item["baseline_identifier"]
                            == anchor.get("approved_baseline_identifier")
                        ),
                        None,
                    )
                    if anchored_baseline is None or prior_attestation is None:
                        raise MeasuredStartupError(
                            "anchored_baseline_evidence_missing", "critical",
                        )
                    prior_payload = prior_attestation["payload"]
                    if (
                        prior_payload.get("runtime_identity")
                        != anchored_baseline.get("runtime_identity")
                        or prior_payload.get("measurement_digest")
                        != anchored_baseline.get("measurement_digest")
                    ):
                        raise MeasuredStartupError(
                            "startup_attestation_baseline_binding_invalid",
                            "critical",
                        )
                current = measure_runtime(
                    self.repository_root, policy=self.policy, environ=self.environ,
                )
                findings = compare_measurements(current, baseline["measurement"])
                classification = drift_class_for(findings)
                if classification in {"critical", "unknown"}:
                    raise MeasuredStartupError("runtime_measurement_drift", classification)
                identity = runtime_identity_for(current, baseline["baseline_identifier"])
                if identity != baseline["runtime_identity"]:
                    raise MeasuredStartupError("runtime_identity_mismatch", "critical")
                startup_sequence = int(anchor.get("startup_sequence", 0)) + 1 if anchor else 1
                timestamp_source = startup_time or datetime.now(timezone.utc)
                if (
                    not isinstance(timestamp_source, datetime)
                    or timestamp_source.tzinfo is None
                ):
                    raise MeasuredStartupError(
                        "startup_attestation_timestamp_invalid", "unknown",
                    )
                timestamp = timestamp_source.astimezone(timezone.utc).replace(
                    microsecond=0
                ).isoformat()
                prior_timestamp = (
                    _parse_aware_timestamp(
                        prior_attestation["payload"].get(
                            "startup_timestamp_evidence"
                        )
                    )
                    if prior_attestation is not None
                    else None
                )
                current_timestamp = _parse_aware_timestamp(timestamp)
                if (
                    current_timestamp is None
                    or (
                        prior_timestamp is not None
                        and current_timestamp < prior_timestamp
                    )
                ):
                    raise MeasuredStartupError(
                        "startup_attestation_clock_rollback", "critical",
                    )
                attestation_payload = {
                    "attestation_version": STARTUP_ATTESTATION_VERSION,
                    "startup_sequence": startup_sequence,
                    "startup_timestamp_evidence": timestamp,
                    "approved_baseline_identifier": baseline["baseline_identifier"],
                    "baseline_store_digest": store["payload_digest"],
                    "runtime_identity": identity,
                    "measurement_digest": current["measurement_digest"],
                }
                attestation = _store_wrapper(attestation_payload)
                if not verify_startup_attestation(attestation, anchor):
                    raise MeasuredStartupError("startup_attestation_replay", "critical")
                attestation_digest = generate_digest(attestation)
                if persist:
                    _atomic_write(self.attestation_path, attestation)
                    anchor_payload = {
                        "anchor_version": ANCHOR_VERSION,
                        "baseline_generation": payload["generation"],
                        "baseline_store_digest": store["payload_digest"],
                        "approved_baseline_identifier": baseline["baseline_identifier"],
                        "startup_sequence": startup_sequence,
                        "last_attestation_digest": attestation_digest,
                    }
                    _atomic_write(self.anchor_path, _anchor_wrapper(anchor_payload))
                    self.failure_path.unlink(missing_ok=True)
                self._validated = True
                self._runtime_identity = identity
                self._baseline_identifier = baseline["baseline_identifier"]
                self._measurement_digest = current["measurement_digest"]
                self._startup_attestation_digest = attestation_digest
                self._startup_sequence = startup_sequence
                MEASUREMENT_EVENTS.record("measured_startup_approved", {
                    "runtime_identity": identity,
                    "baseline_identifier": baseline["baseline_identifier"],
                    "attestation_digest": attestation_digest,
                })
                return {
                    "status": "MEASURED_STARTUP_APPROVED",
                    "drift_class": classification,
                    "runtime_identity": identity,
                    "approved_baseline_identifier": baseline["baseline_identifier"],
                    "measurement_digest": current["measurement_digest"],
                    "startup_attestation_digest": attestation_digest,
                    "startup_sequence": startup_sequence,
                }
            except MeasuredStartupError as exc:
                self._invalidate_runtime_binding()
                self._failure(exc, findings)
                raise

    def check_runtime_drift(self) -> dict[str, Any]:
        with self._lock:
            if not self._validated:
                return self.validate_startup()
            try:
                return self._check_runtime_drift_locked()
            except MeasuredStartupError as exc:
                self._invalidate_runtime_binding()
                self._failure(exc)
                raise

    def _check_runtime_drift_locked(self) -> dict[str, Any]:
        store = load_baseline_store(self.baseline_path)
        payload = validate_baseline_store(store)
        baseline = approved_baseline(payload, self._baseline_identifier)
        anchor = self._anchor()
        if anchor is None:
            raise MeasuredStartupError("measurement_anchor_missing", "unknown")
        attestation = self._persisted_attestation(anchor)
        if attestation is None:
            raise MeasuredStartupError(
                "startup_attestation_missing", "unknown",
            )
        if (
            int(payload["generation"]) != int(anchor.get("baseline_generation", 0))
            or store["payload_digest"] != anchor.get("baseline_store_digest")
        ):
            raise MeasuredStartupError("baseline_changed_during_runtime", "critical")
        if (
            anchor.get("approved_baseline_identifier")
            != self._baseline_identifier
            or anchor.get("startup_sequence") != self._startup_sequence
            or anchor.get("last_attestation_digest")
            != self._startup_attestation_digest
        ):
            raise MeasuredStartupError(
                "startup_anchor_changed_during_runtime", "critical",
            )
        attestation_payload = attestation["payload"]
        expected_attestation = {
            "startup_sequence": self._startup_sequence,
            "approved_baseline_identifier": self._baseline_identifier,
            "baseline_store_digest": store["payload_digest"],
            "runtime_identity": self._runtime_identity,
            "measurement_digest": self._measurement_digest,
        }
        if any(
            attestation_payload.get(field) != value
            for field, value in expected_attestation.items()
        ):
            raise MeasuredStartupError(
                "startup_attestation_changed_during_runtime", "critical",
            )
        current = measure_runtime(
            self.repository_root, policy=self.policy, environ=self.environ,
        )
        findings = compare_measurements(current, baseline["measurement"])
        classification = drift_class_for(findings)
        identity = runtime_identity_for(current, baseline["baseline_identifier"])
        if classification in {"critical", "unknown"} or identity != self._runtime_identity:
            error = MeasuredStartupError(
                "runtime_measurement_drift" if classification in {"critical", "unknown"} else "runtime_identity_mismatch",
                "critical" if classification != "unknown" else "unknown",
            )
            raise error
        return self.status()

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "status": (
                    "MEASURED_STARTUP_APPROVED"
                    if self._validated
                    else "MEASURED_STARTUP_NOT_VALIDATED"
                ),
                "runtime_identity": self._runtime_identity,
                "approved_baseline_identifier": self._baseline_identifier,
                "measurement_digest": self._measurement_digest,
                "startup_attestation_digest": (
                    self._startup_attestation_digest
                ),
                "startup_sequence": self._startup_sequence,
            }


_DEFAULT_SERVICE: MeasuredStartupService | None = None
_DEFAULT_SERVICE_LOCK = threading.Lock()


def default_measured_startup_service() -> MeasuredStartupService:
    global _DEFAULT_SERVICE
    if _DEFAULT_SERVICE is None:
        with _DEFAULT_SERVICE_LOCK:
            if _DEFAULT_SERVICE is None:
                _DEFAULT_SERVICE = MeasuredStartupService()
    return _DEFAULT_SERVICE


def ensure_measured_startup() -> dict[str, Any]:
    return default_measured_startup_service().check_runtime_drift()


def reset_measured_startup_for_tests() -> None:
    global _DEFAULT_SERVICE
    with _DEFAULT_SERVICE_LOCK:
        _DEFAULT_SERVICE = None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Desktop V1 measured startup baseline manager")
    parser.add_argument("command", choices=("build-initial", "propose", "approve", "validate", "show", "measure"))
    parser.add_argument("--path", default=str(DEFAULT_BASELINE_PATH))
    parser.add_argument("--identifier")
    parser.add_argument("--approval-reference")
    parser.add_argument("--retire")
    args = parser.parse_args(argv)
    path = Path(args.path).resolve(strict=False)
    if args.command == "measure":
        measured = measure_runtime()
        print(measured["measurement_digest"])
        return 0
    if args.command == "build-initial":
        if path.exists() or not args.identifier or not args.approval_reference:
            raise MeasuredStartupError("initial_baseline_explicit_approval_required", "critical")
        measured = measure_runtime()
        record = baseline_record(
            args.identifier, measured, sequence=1, status="APPROVED",
            approval_reference=args.approval_reference,
        )
        write_baseline_store(path, create_baseline_store(record))
        print("MEASURED_BASELINE_APPROVED")
        print(path)
        return 0
    store = load_baseline_store(path)
    payload = validate_baseline_store(store)
    if args.command == "propose":
        if not args.identifier:
            raise MeasuredStartupError("pending_baseline_identifier_required", "critical")
        sequence = max(item["sequence"] for item in payload["baselines"]) + 1
        record = baseline_record(args.identifier, measure_runtime(), sequence=sequence)
        write_baseline_store(path, add_pending_baseline(store, record))
        print("MEASURED_BASELINE_PENDING")
        return 0
    if args.command == "approve":
        if not args.identifier or not args.retire or not args.approval_reference:
            raise MeasuredStartupError("explicit_baseline_approval_required", "critical")
        updated = approve_pending_baseline(
            store, args.identifier, approval_reference=args.approval_reference,
            retire_approved_identifier=args.retire,
        )
        write_baseline_store(path, updated)
        print("MEASURED_BASELINE_APPROVED")
        return 0
    if args.command == "validate":
        service = MeasuredStartupService(baseline_path=path)
        result = service.validate_startup(persist=False)
        print(result["status"])
        return 0
    if args.command == "show":
        approved = approved_baseline(payload)
        print("MEASURED_BASELINE_VALID")
        print(f"baseline={approved['baseline_identifier']}")
        print(f"runtime_identity={approved['runtime_identity']}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
