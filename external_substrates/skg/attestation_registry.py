from __future__ import annotations

from typing import Any, Mapping, Sequence

from external_substrates.shared.source_attestation import count_attested_sources, summarise_sources


def build_attestation_registry(sources: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {"attestation_count": count_attested_sources(sources), "source_summary": summarise_sources(sources)}

