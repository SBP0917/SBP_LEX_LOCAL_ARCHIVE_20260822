from __future__ import annotations

from copy import deepcopy

import pytest

from external_substrates.dtn.signal_builder import build_dtn_signal_package
from external_substrates.shared.pre_context_package import build_pre_context_package, validate_pre_context_package
from external_substrates.shared.source_attestation import build_source_record
from external_substrates.skg.signal_builder import build_skg_signal_package


TIMESTAMP = "2026-06-19T00:00:00Z"
REQUEST = "request-fingerprint-15-6a"


def source(source_id: str) -> dict[str, object]:
    return build_source_record(
        source_id=source_id,
        source_type="declared",
        source_uri=f"local://{source_id}",
        verified=True,
        attested=True,
        freshness_valid=True,
        consistency_valid=True,
        retrieved_at=TIMESTAMP,
    )


def packages() -> tuple[dict[str, object], dict[str, object]]:
    skg = build_skg_signal_package(
        request_fingerprint=REQUEST,
        authorities=[{"authority_id": "root", "name": "Root", "jurisdiction": "AU", "legitimacy_status": "verified"}],
        rules=[{"rule_id": "rule-1", "authority_id": "root", "jurisdiction": "AU", "effective_at": "2025-01-01T00:00:00Z", "precedence": 1}],
        conflicts=[],
        source_records=[source("skg")],
        authority_id="root",
        jurisdiction="AU",
        timestamp=TIMESTAMP,
    )
    dtn = build_dtn_signal_package(
        request_fingerprint=REQUEST,
        skg_constraint_package=skg,
        context={
            "dependencies": [{"dependency_id": "power", "available": True}],
            "capabilities": [{"capability_id": "observe", "available": True}],
            "pathway": {"pathway_id": "pathway-1", "objective": "observe"},
            "environment": {"controlled": True},
            "operational_state": {"contained": True},
            "cascading_impact": {"bounded": True},
        },
        source_records=[source("dtn")],
        timestamp=TIMESTAMP,
    )
    return skg, dtn


def build() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    skg, dtn = packages()
    package = build_pre_context_package(skg_package=skg, dtn_package=dtn, nonce="nonce-15-6a", timestamp=TIMESTAMP)
    return skg, dtn, package


def test_pre_context_package_requires_skg_and_dtn_digests() -> None:
    skg, dtn, package = build()
    assert package["skg_package_digest"] == skg["digest"]
    assert package["dtn_package_digest"] == dtn["digest"]
    for field in ("skg_package_digest", "dtn_package_digest"):
        broken = deepcopy(package)
        broken.pop(field)
        assert not validate_pre_context_package(broken)


def test_pre_context_package_requires_request_nonce_timestamp_digest_and_signature() -> None:
    _, _, package = build()
    for field in ("request_fingerprint", "nonce", "timestamp", "digest", "signature"):
        broken = deepcopy(package)
        broken.pop(field)
        assert not validate_pre_context_package(broken)
    with pytest.raises(ValueError, match="nonce"):
        skg, dtn = packages()
        build_pre_context_package(skg_package=skg, dtn_package=dtn, nonce="")


def test_pre_context_rejects_mismatched_signal_request_fingerprint() -> None:
    skg, dtn, package = build()
    package["signals"]["feasibility_signal"]["request_fingerprint"] = "different"
    assert not validate_pre_context_package(package, skg_package=skg, dtn_package=dtn)


def test_pre_context_preserves_deduplicated_source_summary() -> None:
    _, _, package = build()
    assert package["source_summary"] == {
        "total_sources": 2,
        "verified_sources": 2,
        "attested_sources": 2,
        "fresh_sources": 2,
        "consistent_sources": 2,
    }


def test_pre_context_validates_against_source_packages() -> None:
    skg, dtn, package = build()
    assert validate_pre_context_package(package, skg_package=skg, dtn_package=dtn)


def test_pre_context_contains_no_execution_or_governance_authority() -> None:
    _, _, package = build()
    rendered = repr(package)
    assert "execution_permission" not in rendered
    assert "governance_result" not in rendered

