from __future__ import annotations

from hashlib import sha256
import json


def canonical_json_digest(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode("utf-8")
    return sha256(encoded).hexdigest()
