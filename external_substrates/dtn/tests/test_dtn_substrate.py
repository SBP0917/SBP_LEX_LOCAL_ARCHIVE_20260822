from __future__ import annotations

from copy import deepcopy

import pytest

from external_substrates.dtn.dependency_model import model_dependencies
from external_substrates.dtn.signal_builder import build_dtn_signal_package, validate_dtn_signal_package
from external_substrates.shared.source_attestation import build_source_record
from external_substrates.skg.signal_builder import build_skg_signal_package


TIMESTAMP = "2026-06-19T00:00:00Z"
REQUEST = "request-fingerprint-15-6a"


def source(source_id: str) -> dict[str, object]:
    return build_source_record(
        source_id=source_id,
        source_type="declared-operational-record",
        source_uri=f"local://{source_id}",
        verified=True,
        attested=True,
        freshness_valid=True,
        consistency_valid=True,
        retrieved_at=TIMESTAMP,
    )


def skg_package() -> dict[str, object]:
    return build_skg_signal_package(
        request_fingerprint=REQUEST,
        authorities=[
            {"authority_id": "root", "name": "Root", "jurisdiction": "AU", "legitimacy_status": "verified"},
            {"authority_id": "child", "name": "Child", "jurisdiction": "AU", "parent_authority_id": "root", "legitimacy_status": "verified"},
        ],
        rules=[{"rule_id": "rule-1", "authority_id": "root", "jurisdiction": "AU", "effective_at": "2025-01-01T00:00:00Z", "precedence": 10}],
        conflicts=[],
        source_records=[source("skg-source")],
        authority_id="child",
        jurisdiction="AU",
        timestamp=TIMESTAMP,
    )


def context() -> dict[str, object]:
    return {
        "environment": {"type": "controlled", "controlled": True, "human_proximity": "low", "conditions": ["dry", "stable"]},
        "operational_state": {"status": "ready", "contained": True, "emergency_stop_available": True},
        "dependencies": [{"dependency_id": "power", "available": True}, {"dependency_id": "sensor", "available": True}],
        "capabilities": [{"capability_id": "observe", "available": True}],
        "pathway": {"pathway_id": "pathway-1", "objective": "observe", "steps": ["inspect"]},
        "declared_risk": 1,
        "cascading_impact": {"affected_dependencies": 0, "propagation_level": 0, "bounded": True},
    }


def build() -> dict[str, object]:
    skg = skg_package()
    return build_dtn_signal_package(
        request_fingerprint=REQUEST,
        skg_constraint_package=skg,
        context=context(),
        source_records=[source("dtn-source")],
        timestamp=TIMESTAMP,
    )


def test_dtn_refuses_to_emit_without_valid_skg_constraints() -> None:
    with pytest.raises(ValueError, match="SKG"):
        build_dtn_signal_package(
            request_fingerprint=REQUEST,
            skg_constraint_package={},
            context=context(),
            source_records=[source("dtn-source")],
            timestamp=TIMESTAMP,
        )


def test_dtn_rejects_mismatched_request_binding() -> None:
    with pytest.raises(ValueError, match="fingerprints"):
        build_dtn_signal_package(
            request_fingerprint="different-request",
            skg_constraint_package=skg_package(),
            context=context(),
            source_records=[source("dtn-source")],
            timestamp=TIMESTAMP,
        )


def test_dtn_package_and_every_signal_include_skg_constraint_digest() -> None:
    package = build()
    expected = skg_package()["digest"]
    assert package["skg_constraint_digest"] == expected
    assert all(signal["skg_constraint_digest"] == expected for signal in package["signals"].values())


def test_dtn_package_is_request_digest_signature_and_timestamp_bound() -> None:
    skg = skg_package()
    package = build_dtn_signal_package(
        request_fingerprint=REQUEST,
        skg_constraint_package=skg,
        context=context(),
        source_records=[source("dtn-source")],
        timestamp=TIMESTAMP,
    )
    assert validate_dtn_signal_package(package, skg_constraint_package=skg)
    assert package["request_fingerprint"] == REQUEST
    assert package["digest"] and package["signature"] and package["timestamp"] == TIMESTAMP


def test_dependency_signal_is_deterministic() -> None:
    left = model_dependencies([{"dependency_id": "z", "available": True}, {"dependency_id": "a", "available": True}])
    right = model_dependencies([{"dependency_id": "a", "available": True}, {"dependency_id": "z", "available": True}])
    assert left == right


def test_capability_feasibility_and_risk_signals_are_deterministic() -> None:
    assert build()["signals"] == build()["signals"]
    signals = build()["signals"]
    assert signals["capability_signal"]["payload"]["available"] is True
    assert signals["feasibility_signal"]["payload"]["feasible"] is True
    assert signals["risk_potential_signal"]["payload"]["level"] == "LOW"


def test_tampered_dtn_package_is_invalid() -> None:
    skg = skg_package()
    package = build_dtn_signal_package(
        request_fingerprint=REQUEST,
        skg_constraint_package=skg,
        context=context(),
        source_records=[source("dtn-source")],
        timestamp=TIMESTAMP,
    )
    package["signals"]["dependency_signal"]["payload"]["satisfied"] = False
    assert not validate_dtn_signal_package(package, skg_constraint_package=skg)


def test_dtn_does_not_emit_execution_or_governance_authority() -> None:
    rendered = repr(build())
    assert "execution_permission" not in rendered
    assert "governance_result" not in rendered


def test_dtn_does_not_override_skg_constraint_digest() -> None:
    package = deepcopy(build())
    package["skg_constraint_digest"] = "0" * 64
    assert not validate_dtn_signal_package(package, skg_constraint_package=skg_package())

