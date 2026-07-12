from __future__ import annotations

import json
import os
import uuid
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from sbp_lex.api.schema_validation import loads_strict_json
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

R4_VERSION = "R4_DESKTOP_V1_IVVP_V1"
R4_DOMAIN = "SBP_LEX_DESKTOP_V1_INDEPENDENT_VERIFICATION_PACKAGE"
DESKTOP_SCOPE = "SBP_LEX_DUAL_V6_DESKTOP_V1_LOCAL_PRIVATE_SINGLE_HOST_NO_NODE"
REPOSITORY_IDENTITY = "github.com/SBP0917/SBP_LEX_DUAL_V6"


class IVVPError(RuntimeError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"ivvp_failed:{reason}")


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def file_sha256(path: Path) -> str:
    digest = sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise IVVPError("evidence_read_failed") from exc
    return digest.hexdigest()


def read_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        if not raw or len(raw) > 64 * 1024 * 1024: raise ValueError
        value = loads_strict_json(raw.decode("utf-8"))
    except Exception as exc:
        raise IVVPError(f"{label}_invalid") from exc
    if not isinstance(value, dict): raise IVVPError(f"{label}_invalid")
    return value


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(canonical_bytes(value))


def seal(payload: Mapping[str, Any]) -> dict[str, Any]:
    copied = json.loads(json.dumps(payload))
    return {"payload": copied, "payload_digest": generate_digest(copied), "integrity_signature": sign_payload({"integrity_domain": R4_DOMAIN, "payload": copied})}


def unseal(value: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"payload", "payload_digest", "integrity_signature"}: raise IVVPError(f"{label}_schema_invalid")
    payload = value.get("payload")
    if not isinstance(payload, Mapping): raise IVVPError(f"{label}_payload_invalid")
    copied = json.loads(json.dumps(payload))
    if value.get("payload_digest") != generate_digest(copied): raise IVVPError(f"{label}_digest_invalid")
    if not verify_signature({"integrity_domain": R4_DOMAIN, "payload": copied}, value.get("integrity_signature", {})): raise IVVPError(f"{label}_signature_invalid")
    return copied
