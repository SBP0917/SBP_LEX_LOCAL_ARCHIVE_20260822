from __future__ import annotations

from copy import deepcopy

from external_substrates.shared.source_attestation import build_source_record
from external_substrates.skg.authority_graph import resolve_authority_chain
from external_substrates.skg.conflict_resolver import resolve_policy_conflicts
from external_substrates.skg.rule_lineage_engine import validate_rule_lineage
from external_substrates.skg.signal_builder import build_skg_signal_package, validate_skg_signal_package


TIMESTAMP = "2026-06-19T00:00:00Z"


def fixtures() -> dict[str, object]:
    source = build_source_record(
        source_id="registry-1",
        source_type="authority-register",
        source_uri="local://authority-register/1",
        verified=True,
        attested=True,
        freshness_valid=True,
        consistency_valid=True,
        retrieved_at=TIMESTAMP,
    )
    return {
        "request_fingerprint": "request-fingerprint-15-6a",
        "authorities": [
            {"authority_id": "root", "name": "Root", "jurisdiction": "AU", "legitimacy_status": "verified"},
            {"authority_id": "child", "name": "Child", "jurisdiction": "AU", "parent_authority_id": "root", "legitimacy_status": "verified"},
        ],
        "rules": [
            {"rule_id": "rule-high", "authority_id": "root", "jurisdiction": "AU", "effective_at": "2025-01-01T00:00:00Z", "precedence": 20},
            {"rule_id": "rule-low", "authority_id": "child", "jurisdiction": "AU", "effective_at": "2025-02-01T00:00:00Z", "precedence": 10},
        ],
        "conflicts": [{"conflict_id": "conflict-1", "resolved": True, "resolution": "rule-high"}],
        "source_records": [source],
        "authority_id": "child",
        "jurisdiction": "AU",
        "procedural_requirements": [{"requirement_id": "proc-1", "required": True}],
        "licensing_authorities": [{"authority_id": "root", "scope": "license"}],
        "classification_authorities": [{"authority_id": "root", "scope": "classification"}],
        "timestamp": TIMESTAMP,
    }


def test_authority_chain_resolves_deterministically() -> None:
    data = fixtures()
    expected = {"authority_chain": ["child", "root"], "resolved": True, "reason": "resolved"}
    assert resolve_authority_chain(data["authorities"], "child") == expected
    assert resolve_authority_chain(reversed(data["authorities"]), "child") == expected


def test_revoked_authority_is_rejected() -> None:
    authorities = deepcopy(fixtures()["authorities"])
    authorities[0]["revoked"] = True
    result = resolve_authority_chain(authorities, "child")
    assert result["resolved"] is False
    assert result["reason"] == "revoked_authority"


def test_stale_rule_lineage_is_rejected() -> None:
    rules = deepcopy(fixtures()["rules"])
    rules[0]["expires_at"] = "2026-01-01T00:00:00Z"
    result = validate_rule_lineage(rules, now=TIMESTAMP)
    assert result["valid"] is False
    assert any("stale" in failure for failure in result["failures"])


def test_unresolved_conflict_is_not_marked_resolved() -> None:
    result = resolve_policy_conflicts([{"conflict_id": "conflict-1", "resolved": False}])
    assert result["resolved"] is False
    assert result["unresolved_conflict_ids"] == ["conflict-1"]


def test_skg_signal_package_is_request_digest_signature_and_timestamp_bound() -> None:
    package = build_skg_signal_package(**fixtures())
    assert validate_skg_signal_package(package)
    assert package["request_fingerprint"] == "request-fingerprint-15-6a"
    assert package["digest"] and package["signature"] and package["timestamp"] == TIMESTAMP
    assert all(signal["request_fingerprint"] == package["request_fingerprint"] for signal in package["signals"].values())


def test_skg_preserves_source_attestation_records() -> None:
    package = build_skg_signal_package(**fixtures())
    assert package["source_summary"]["attested_sources"] == 1
    assert all(signal["source_records"] == package["source_records"] for signal in package["signals"].values())


def test_tampered_skg_package_is_invalid() -> None:
    package = build_skg_signal_package(**fixtures())
    package["signals"]["jurisdiction_signal"]["payload"]["resolved"] = False
    assert not validate_skg_signal_package(package)


def test_skg_does_not_emit_execution_or_governance_authority() -> None:
    package = build_skg_signal_package(**fixtures())
    rendered = repr(package)
    assert "execution_permission" not in rendered
    assert "governance_result" not in rendered

