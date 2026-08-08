from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from main import sample_request
from sbp_lex.audit.pipeline_replay_ledger import (
    PipelineReplayLedger,
    verify_replay_ledger_entries,
)
from sbp_lex.persistence.integrity_store import IntegrityStore
from sbp_lex.pipeline.dual_runner import run_dual_pipeline
from sbp_lex.runtime.terminal_custody import (
    REJECTION_CUSTODY_FIELDS,
    TERMINAL_CUSTODY_FIELDS,
    durable_custody_bindings,
)


@pytest.fixture(scope="module")
def sealed_state() -> dict[str, Any]:
    state = run_dual_pipeline(sample_request())
    assert state.get("terminal_state_seal")
    return state


@pytest.fixture(scope="module")
def rejected_state() -> dict[str, Any]:
    state = run_dual_pipeline({"undeclared": True})
    assert state.get("object_type") == "HardEntryDenialEvidence"
    assert state.get("accepted") is False
    return state


def _legacy_state() -> dict[str, Any]:
    return {
        "request_fingerprint": "legacy-request",
        "state_hash": "legacy-state",
        "decision": "DENY",
        "execution_result": "HALT",
        "audit_hash": "legacy-audit",
        "pipeline_convergence": {"convergence_hash": "legacy-convergence"},
    }


def test_terminal_digests_are_exactly_bound_into_both_custody_stores(
    sealed_state: dict[str, Any], tmp_path: Path,
) -> None:
    expected = durable_custody_bindings(sealed_state, require=True)
    assert expected is not None
    ledger = PipelineReplayLedger()
    ledger_entry = ledger.append(sealed_state)
    store = IntegrityStore(
        tmp_path / "integrity.jsonl", allowed_root=tmp_path
    )
    persistence_record = store.append_state_summary(sealed_state)
    assert {
        field: ledger_entry[field] for field in TERMINAL_CUSTODY_FIELDS
    } == expected
    assert {
        field: persistence_record[field]
        for field in TERMINAL_CUSTODY_FIELDS
    } == expected
    assert ledger.verify() == (True, [])
    assert store.verify() == (True, [])


def test_terminal_state_mutation_is_rejected_before_persistence(
    sealed_state: dict[str, Any], tmp_path: Path,
) -> None:
    tampered = deepcopy(sealed_state)
    tampered["decision"] = "DENY"
    with pytest.raises(ValueError, match="terminal_custody_seal_invalid"):
        PipelineReplayLedger().append(tampered)
    store = IntegrityStore(
        tmp_path / "tampered.jsonl", allowed_root=tmp_path
    )
    with pytest.raises(ValueError, match="terminal_custody_seal_invalid"):
        store.append_state_summary(tampered)


def test_legacy_prefix_is_readable_but_custody_cannot_downgrade(
    sealed_state: dict[str, Any], tmp_path: Path,
) -> None:
    ledger = PipelineReplayLedger()
    ledger.append(_legacy_state())
    ledger.append(sealed_state)
    assert ledger.verify() == (True, [])
    with pytest.raises(
        RuntimeError, match="replay_ledger_terminal_custody_downgrade"
    ):
        ledger.append(_legacy_state())

    store = IntegrityStore(
        tmp_path / "migration.jsonl", allowed_root=tmp_path
    )
    store.append_state_summary(_legacy_state())
    store.append_state_summary(sealed_state)
    assert store.verify() == (True, [])
    with pytest.raises(
        RuntimeError, match="persistence_terminal_custody_downgrade"
    ):
        store.append_state_summary(_legacy_state())


def test_partial_terminal_custody_record_fails_closed(
    sealed_state: dict[str, Any],
) -> None:
    ledger = PipelineReplayLedger()
    ledger.append(sealed_state)
    entries = ledger.export()
    entries[0].pop("terminal_seal_digest")
    valid, failures = verify_replay_ledger_entries(
        entries, ledger.checkpoint()
    )
    assert valid is False
    assert "ledger_terminal_custody_fields_incomplete:0" in failures


def test_hard_entry_rejection_uses_distinct_non_terminal_custody(
    rejected_state: dict[str, Any], tmp_path: Path,
) -> None:
    expected = durable_custody_bindings(rejected_state, require=True)
    assert expected is not None
    ledger_entry = PipelineReplayLedger().append(rejected_state)
    store = IntegrityStore(
        tmp_path / "rejections.jsonl", allowed_root=tmp_path
    )
    persistence_record = store.append_state_summary(rejected_state)
    assert TERMINAL_CUSTODY_FIELDS.isdisjoint(ledger_entry)
    assert TERMINAL_CUSTODY_FIELDS.isdisjoint(persistence_record)
    assert {
        field: ledger_entry[field] for field in REJECTION_CUSTODY_FIELDS
    } == expected
    assert {
        field: persistence_record[field]
        for field in REJECTION_CUSTODY_FIELDS
    } == expected
