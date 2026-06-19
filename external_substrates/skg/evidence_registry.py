from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping, Sequence

from external_substrates.shared.digest import digest_mapping


def register_evidence(evidence: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    records = [deepcopy(dict(item)) for item in evidence]
    for record in records:
        record.setdefault("evidence_digest", digest_mapping({key: value for key, value in record.items() if key != "evidence_digest"}))
    return sorted(records, key=lambda item: str(item.get("evidence_id", "")))

