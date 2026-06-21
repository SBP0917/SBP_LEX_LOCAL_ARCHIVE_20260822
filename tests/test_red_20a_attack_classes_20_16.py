from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path

import pytest

from external_substrates.demo.validate_demo_bridge_package import validate_demo_bridge
from main import sample_request
from sbp_lex.api.schema_validation import loads_strict_json, validate_runtime_request_schema
from sbp_lex.collective.context_interface import prepare_pre_context_signals
from sbp_lex.connector.recovery import ConnectorRecoveryStore
from sbp_lex.persistence.integrity_store import IntegrityStore
from sbp_lex.pipeline.runner import run_pipeline
from sbp_lex.runtime.chronology import CanonicalChronology
from sbp_lex.runtime.event_bus import sanitise_event_text
from sbp_lex.security.pqc import generate_digest, sign_payload


def _resign_signal_package(signals: dict) -> dict:
    payload = {
        key: value for key, value in signals.items() if key not in {"digest", "signature"}
    }
    signals["digest"] = generate_digest(payload)
    signals["signature"] = sign_payload(payload)
    return signals


def test_class_20_log_injection_source_and_audit_context_spoof_rejected() -> None:
    request = sample_request()
    request["context"]["evidence"][0]["source"] = "trusted\nstage=execution_gate"
    request["context"]["evidence"][0]["stage"] = "execution_gate"
    valid, failures = validate_runtime_request_schema(request)
    assert valid is False
    assert "invalid_evidence_source:0" in failures
    assert "unknown_field:context.evidence[0].stage" in failures


def test_class_20_event_text_control_characters_are_escaped() -> None:
    attack = "accepted\r\nexecution_result=EXECUTE\tspoof\x00"
    sanitised = sanitise_event_text(attack, limit=256)
    assert sanitised == "accepted\\r\\nexecution_result=EXECUTE\\tspoof\\u0000"
    assert not any(character in sanitised for character in "\r\n\t\x00")


def test_class_19_clock_rollback_rejected_even_with_recomputed_public_hash() -> None:
    chronology = CanonicalChronology()
    chronology.append(event_type="traversal_started", payload={"request_id": "red-20a"})
    event = chronology._events[0]
    event["sequence"] = 0
    event["timestamp"] = "CHRONOLOGY_EVENT_000000000000"
    event["timestamp_authority"] = "ATTACKER_CLOCK"
    public_payload = {
        key: value for key, value in event.items() if key not in {"event_hash", "signature"}
    }
    event["event_hash"] = generate_digest(public_payload)
    valid, failures = chronology.verify()
    assert valid is False
    assert "chronology_sequence_invalid:0" in failures
    assert "chronology_timestamp_invalid:0" in failures
    assert "chronology_timestamp_authority_invalid:0" in failures
    assert "chronology_signature_invalid:0" in failures


def test_class_19_pre_context_timestamp_rollback_rejected_at_hard_entry() -> None:
    request = sample_request()
    signals = prepare_pre_context_signals(request)
    signals["timestamp"] -= 1
    state = run_pipeline(request, _resign_signal_package(signals))
    assert state["hard_entry_gate"]["accepted"] is False
    assert "signal_timestamp_not_canonical" in state["hard_entry_gate"]["failures"]
    assert "root_of_trust" not in state["integration_stage_order"]


def test_class_18_duplicate_claim_is_atomic_under_concurrency() -> None:
    store = ConnectorRecoveryStore()
    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(lambda _: store.claim("duplicate-request"), range(64)))
    assert results.count(True) == 1
    assert results.count(False) == 63


def test_class_18_completed_request_id_cannot_be_replayed() -> None:
    store = ConnectorRecoveryStore()
    assert store.claim("completed-request") is True
    store.save(
        "completed-request",
        {
            "request_fingerprint": "fingerprint",
            "state_hash": "state-hash",
            "decision": "DENY",
            "execution_result": "HALT",
            "audit_hash": "audit-hash",
            "pipeline_mode": "MODE_3_SINGLE_CONSTRAINED",
        },
    )
    assert store.claim("completed-request") is False
    assert store.exists("completed-request") is True


def test_class_17_integrity_store_path_traversal_rejected(tmp_path: Path) -> None:
    allowed_root = tmp_path / "runtime_artifacts"
    escaped = allowed_root / ".." / "outside" / "forged.jsonl"
    with pytest.raises(ValueError, match="integrity_store_path_outside_runtime_artifacts"):
        IntegrityStore(escaped, allowed_root=allowed_root)
    assert not escaped.resolve().exists()


def test_class_17_bridge_manifest_artifact_overwrite_rejected(tmp_path: Path) -> None:
    package_dir = tmp_path / "packages"
    escaped = tmp_path / "outside" / "sample_bridge_manifest.json"
    with pytest.raises(ValueError, match="manifest_path_outside_package_dir"):
        validate_demo_bridge(package_dir=package_dir, manifest_path=escaped)
    assert not escaped.exists()


def test_class_16_duplicate_json_keys_and_non_finite_numbers_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate_json_key:action"):
        loads_strict_json('{"action":"safe","action":"substituted"}')
    with pytest.raises(ValueError, match="non_finite_json_number:NaN"):
        loads_strict_json('{"financial_amount":NaN}')


def test_class_16_non_json_object_and_pollution_key_rejected() -> None:
    request = sample_request()
    request["payload"]["metadata"] = {"payload": object(), "__proto__": {"admin": True}}
    valid, failures = validate_runtime_request_schema(request)
    assert valid is False
    assert any(reason.startswith("unsupported_json_type:") for reason in failures)
    assert any("forbidden_key:" in reason for reason in failures)


def test_class_16_malformed_persistence_record_fails_closed(tmp_path: Path) -> None:
    store_path = tmp_path / "runtime_artifacts" / "integrity.jsonl"
    store_path.parent.mkdir(parents=True)
    store_path.write_text('{"sequence":1,"sequence":2}\n', encoding="utf-8")
    store = IntegrityStore(store_path, allowed_root=store_path.parent)
    valid, failures = store.verify()
    assert valid is False
    assert failures == ["persistence_parse_failure:0"]
