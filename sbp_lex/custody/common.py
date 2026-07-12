from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from sbp_lex.api.schema_validation import loads_strict_json
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

R3_VERSION = "R3_DESKTOP_V1_CUSTODY_ASSURANCE_V1"
R3_DOMAIN = "SBP_LEX_DESKTOP_V1_EXTERNAL_CUSTODY_ASSURANCE"
DESKTOP_SCOPE = "SBP_LEX_DUAL_V6_DESKTOP_V1_LOCAL_PRIVATE_SINGLE_HOST_NO_NODE"
IDENTIFIER = re.compile(r"^[A-Z0-9][A-Z0-9_.-]{7,127}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_JSON = 16 * 1024 * 1024


class CustodyError(RuntimeError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"custody_failed:{reason}")


def utc_text(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise CustodyError("timestamp_invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise CustodyError("timestamp_invalid")
    return parsed.replace(microsecond=0).isoformat()


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256_bytes(raw: bytes) -> str:
    return sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    digest = sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise CustodyError("file_read_failed") from exc
    return digest.hexdigest()


def tree_digest(root: Path) -> str:
    base = root.resolve()
    if base.is_symlink() or not base.is_dir():
        raise CustodyError("package_missing")
    records: list[dict[str, Any]] = []
    for path in sorted(base.rglob("*"), key=lambda item: item.relative_to(base).as_posix()):
        if path.is_symlink():
            raise CustodyError("package_symlink")
        if path.is_file():
            records.append({"path": path.relative_to(base).as_posix(), "sha256": file_sha256(path), "size_bytes": path.stat().st_size})
    if not records:
        raise CustodyError("package_empty")
    return generate_digest({"files": records})


def seal(payload: Mapping[str, Any]) -> dict[str, Any]:
    copied = json.loads(json.dumps(payload))
    return {
        "payload": copied,
        "payload_digest": generate_digest(copied),
        "integrity_signature": sign_payload({"integrity_domain": R3_DOMAIN, "payload": copied}),
    }


def unseal(value: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"payload", "payload_digest", "integrity_signature"}:
        raise CustodyError(f"{label}_schema_invalid")
    payload = value.get("payload")
    if not isinstance(payload, Mapping):
        raise CustodyError(f"{label}_payload_invalid")
    copied = json.loads(json.dumps(payload))
    if value.get("payload_digest") != generate_digest(copied):
        raise CustodyError(f"{label}_digest_invalid")
    if not verify_signature({"integrity_domain": R3_DOMAIN, "payload": copied}, value.get("integrity_signature", {})):
        raise CustodyError(f"{label}_signature_invalid")
    return copied


def read_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        if not raw or len(raw) > MAX_JSON:
            raise ValueError
        value = loads_strict_json(raw.decode("utf-8"))
    except Exception as exc:
        raise CustodyError(f"{label}_invalid") from exc
    if not isinstance(value, dict):
        raise CustodyError(f"{label}_invalid")
    return value


def atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temp.open("xb") as handle:
            handle.write(canonical_bytes(value)); handle.flush(); os.fsync(handle.fileno())
        os.replace(temp, path)
    except OSError as exc:
        temp.unlink(missing_ok=True)
        raise CustodyError("atomic_write_failed") from exc


def require_identifier(value: Any, reason: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise CustodyError(reason)
    return value
