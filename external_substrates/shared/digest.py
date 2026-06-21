from __future__ import annotations

from hashlib import sha256
from typing import Any, Mapping

from external_substrates.shared.canonical_json import canonical_bytes


def sha256_digest(data: Any) -> str:
    payload = data if isinstance(data, bytes) else canonical_bytes(data)
    return sha256(payload).hexdigest()


def digest_mapping(data: Mapping[str, Any]) -> str:
    return sha256_digest(dict(data))

