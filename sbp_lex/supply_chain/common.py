from __future__ import annotations

import json
import os
import re
import uuid
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from sbp_lex.api.schema_validation import loads_strict_json
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

R2_VERSION = "R2_DESKTOP_V1_SUPPLY_CHAIN_V1"
R2_DOMAIN = "SBP_LEX_DESKTOP_V1_SUPPLY_CHAIN_ASSURANCE"
DESKTOP_SCOPE = "SBP_LEX_DUAL_V6_DESKTOP_V1_LOCAL_PRIVATE_SINGLE_HOST_NO_NODE"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_JSON_BYTES = 32 * 1024 * 1024


class SupplyChainError(RuntimeError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"supply_chain_failed:{reason}")


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def file_sha256(path: Path) -> str:
    digest = sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise SupplyChainError("file_read_failed") from exc
    return digest.hexdigest()


def portable_path(value: str, *, label: str = "path") -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise SupplyChainError(f"{label}_invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise SupplyChainError(f"{label}_escape")
    if re.match(r"^[A-Za-z]:", value) or value.startswith("//"):
        raise SupplyChainError(f"{label}_absolute")
    return path.as_posix()


def resolve_file(root: Path, relative: str, *, label: str = "path") -> Path:
    rel = portable_path(relative, label=label)
    approved = root.resolve()
    target = (approved / Path(*PurePosixPath(rel).parts)).resolve(strict=False)
    if not target.is_relative_to(approved):
        raise SupplyChainError(f"{label}_escape")
    cursor = approved
    for part in PurePosixPath(rel).parts:
        cursor /= part
        if cursor.exists() and cursor.is_symlink():
            raise SupplyChainError(f"{label}_symlink")
    if not target.is_file():
        raise SupplyChainError(f"{label}_missing")
    return target


def read_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        if not raw or len(raw) > MAX_JSON_BYTES:
            raise ValueError
        value = loads_strict_json(raw.decode("utf-8"))
    except Exception as exc:
        raise SupplyChainError(f"{label}_invalid") from exc
    if not isinstance(value, dict):
        raise SupplyChainError(f"{label}_invalid")
    return value


def atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    raw = canonical_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise SupplyChainError("atomic_write_failed") from exc


def seal(payload: Mapping[str, Any]) -> dict[str, Any]:
    copied = json.loads(json.dumps(payload))
    return {
        "payload": copied,
        "payload_digest": generate_digest(copied),
        "integrity_signature": sign_payload({"integrity_domain": R2_DOMAIN, "payload": copied}),
    }


def unseal(value: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"payload", "payload_digest", "integrity_signature"}:
        raise SupplyChainError(f"{label}_schema_invalid")
    payload = value.get("payload")
    if not isinstance(payload, Mapping):
        raise SupplyChainError(f"{label}_payload_invalid")
    copied = json.loads(json.dumps(payload))
    if value.get("payload_digest") != generate_digest(copied):
        raise SupplyChainError(f"{label}_digest_invalid")
    signed = {"integrity_domain": R2_DOMAIN, "payload": copied}
    if not verify_signature(signed, value.get("integrity_signature", {})):
        raise SupplyChainError(f"{label}_signature_invalid")
    return copied
