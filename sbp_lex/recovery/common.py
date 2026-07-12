from __future__ import annotations

import json
import os
import re
import shutil
import uuid
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any, Iterator, Mapping

from sbp_lex.api.schema_validation import loads_strict_json
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

RECOVERY_VERSION = "R1_DESKTOP_V1_RECOVERY_V1"
RECOVERY_DOMAIN = "SBP_LEX_DESKTOP_V1_RECOVERY_INTEGRITY"
DESKTOP_SCOPE = "SBP_LEX_DUAL_V6_DESKTOP_V1_LOCAL_PRIVATE_SINGLE_HOST_NO_NODE"
MAX_JSON_BYTES = 8_388_608
MAX_ARTIFACT_BYTES = 67_108_864
MAX_ARTIFACTS = 512
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER = re.compile(r"^[A-Z0-9][A-Z0-9_.-]{7,127}$")
LOGICAL_NAME = re.compile(r"^[a-z][a-z0-9_.-]{2,127}$")

AUTHORITY_DOMAINS = (
    "configuration",
    "security_state",
    "external_identity_replay",
    "execution_integrity",
    "audit_attestations",
    "measured_startup",
    "local_trust",
    "formal_assurance",
)
DOMAIN_ORDER = {name: (index + 1) * 100 for index, name in enumerate(AUTHORITY_DOMAINS)}
SENSITIVITY_CLASSES = frozenset({"PUBLIC_EVIDENCE", "PROTECTED_PRIVATE"})
REQUIRED_STATUSES = frozenset({"REQUIRED", "OPTIONAL"})
FORMATS = frozenset({"json", "jsonl", "text", "binary"})
VALIDATION_METHODS = frozenset({
    "sha256",
    "strict_json",
    "jsonl_hash_chain",
    "integrity_store",
    "measured_baseline_store",
    "formal_assurance",
})

_SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----", re.IGNORECASE),
    re.compile(rb'"(?:password|secret|api_token|private_key)"\s*:\s*"(?!\s*(?:REDACTED|PLACEHOLDER|NONE|null)\s*")[^"\r\n]{6,}"', re.IGNORECASE),
    re.compile(rb"(?:^|\s)(?:password|api[_-]?token|signing[_-]?secret)\s*=\s*(?!REDACTED|PLACEHOLDER)[^\s\r\n]{6,}", re.IGNORECASE),
)


class RecoveryError(RuntimeError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"recovery_failed:{reason}")


def strict_json_bytes(raw: bytes, *, label: str) -> dict[str, Any]:
    if not raw or len(raw) > MAX_JSON_BYTES:
        raise RecoveryError(f"{label}_size_invalid")
    try:
        value = loads_strict_json(raw.decode("utf-8"))
    except Exception as exc:
        raise RecoveryError(f"{label}_json_invalid") from exc
    if not isinstance(value, dict):
        raise RecoveryError(f"{label}_schema_invalid")
    return value


def read_strict_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file():
            raise OSError
        return strict_json_bytes(path.read_bytes(), label=label)
    except RecoveryError:
        raise
    except OSError as exc:
        raise RecoveryError(f"{label}_read_failed") from exc


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return sha256(raw).hexdigest()


def portable_path(value: str, *, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise RecoveryError(f"{label}_invalid")
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise RecoveryError(f"{label}_escape")
    if re.match(r"^[A-Za-z]:", value) or value.startswith("//"):
        raise RecoveryError(f"{label}_absolute")
    return candidate.as_posix()


def resolve_beneath(root: Path, relative: str, *, label: str, must_exist: bool = False) -> Path:
    rel = portable_path(relative, label=label)
    approved = root.resolve()
    target = (approved / Path(*PurePosixPath(rel).parts)).resolve(strict=False)
    if not target.is_relative_to(approved):
        raise RecoveryError(f"{label}_escape")
    cursor = approved
    for part in PurePosixPath(rel).parts:
        cursor = cursor / part
        if cursor.exists() and cursor.is_symlink():
            raise RecoveryError(f"{label}_symlink")
    if must_exist and not target.is_file():
        raise RecoveryError(f"{label}_missing")
    return target


def ensure_approved_destination(path: Path, approved_root: Path) -> Path:
    root = approved_root.resolve()
    target = path.resolve(strict=False)
    if target == root or not target.is_relative_to(root):
        raise RecoveryError("unapproved_destination")
    cursor = root
    relative = target.relative_to(root)
    for part in relative.parts:
        cursor = cursor / part
        if cursor.exists() and cursor.is_symlink():
            raise RecoveryError("destination_symlink_escape")
    return target


def package_member_base(package_root: Path, artefact: Mapping[str, Any]) -> Path:
    sensitivity = str(artefact.get("sensitivity_class", "")).lower()
    if sensitivity not in {"public_evidence", "protected_private"}:
        raise RecoveryError("package_sensitivity_invalid")
    domain = str(artefact.get("authority_domain", ""))
    if domain not in AUTHORITY_DOMAINS:
        raise RecoveryError("package_authority_domain_invalid")
    return package_root / "domains" / domain / sensitivity


def scan_for_secrets(raw: bytes, *, logical_name: str) -> None:
    if any(pattern.search(raw) for pattern in _SECRET_PATTERNS):
        raise RecoveryError(f"secret_material_detected:{logical_name}")


def bound_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    copied = json.loads(json.dumps(payload))
    return {
        "payload": copied,
        "payload_digest": generate_digest(copied),
        "integrity_signature": sign_payload({"integrity_domain": RECOVERY_DOMAIN, "payload": copied}),
    }


def validate_bound(value: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"payload", "payload_digest", "integrity_signature"}:
        raise RecoveryError(f"{label}_schema_invalid")
    payload = value.get("payload")
    if not isinstance(payload, Mapping):
        raise RecoveryError(f"{label}_payload_invalid")
    copied = json.loads(json.dumps(payload))
    if value.get("payload_digest") != generate_digest(copied):
        raise RecoveryError(f"{label}_digest_invalid")
    if not verify_signature(
        {"integrity_domain": RECOVERY_DOMAIN, "payload": copied},
        value.get("integrity_signature", {}),
    ):
        raise RecoveryError(f"{label}_signature_invalid")
    return copied


def atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temp.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        fsync_directory(path.parent)
    except OSError as exc:
        temp.unlink(missing_ok=True)
        raise RecoveryError("atomic_write_failed") from exc


def atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    atomic_write(path, canonical_bytes(value))


def fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise RecoveryError("directory_flush_failed") from exc


@contextmanager
def exclusive_lock(path: Path, *, collision_reason: str) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(descriptor)
    except FileExistsError as exc:
        raise RecoveryError(collision_reason) from exc
    except OSError as exc:
        raise RecoveryError("lock_acquisition_failed") from exc
    try:
        yield
    finally:
        if descriptor is not None:
            os.close(descriptor)
        path.unlink(missing_ok=True)


def remove_tree(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
