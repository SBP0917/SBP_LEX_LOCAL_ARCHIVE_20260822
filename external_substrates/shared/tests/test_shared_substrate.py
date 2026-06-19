from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from external_substrates.shared.canonical_json import canonical_dumps
from external_substrates.shared.digest import digest_mapping
from external_substrates.shared.freshness import validate_freshness
from external_substrates.shared.signal_envelope import build_signal_envelope, validate_signal_envelope
from external_substrates.shared.source_attestation import build_source_record, count_attested_sources


NOW = datetime(2026, 6, 19, 0, 0, tzinfo=timezone.utc)


def source(source_id: str = "source-1", **overrides: object) -> dict[str, object]:
    values = {
        "source_id": source_id,
        "source_type": "authority-register",
        "source_uri": f"local://{source_id}",
        "verified": True,
        "attested": True,
        "freshness_valid": True,
        "consistency_valid": True,
        "retrieved_at": "2026-06-19T00:00:00Z",
    }
    values.update(overrides)
    return build_source_record(**values)


def test_canonical_json_and_digest_are_deterministic() -> None:
    left = {"b": [2, 1], "a": {"z": True}}
    right = {"a": {"z": True}, "b": [2, 1]}
    assert canonical_dumps(left) == canonical_dumps(right)
    assert digest_mapping(left) == digest_mapping(right)


def test_freshness_validation_accepts_only_bounded_past_timestamp() -> None:
    recent = NOW - timedelta(seconds=30)
    assert validate_freshness(recent, 60, NOW)
    assert not validate_freshness(NOW - timedelta(seconds=61), 60, NOW)
    assert not validate_freshness(NOW + timedelta(seconds=1), 60, NOW)


def test_source_attestation_count_requires_all_qualification_flags() -> None:
    sources = [source("qualified"), source("unverified", verified=False)]
    assert count_attested_sources(sources) == 1


def test_signal_envelope_is_request_digest_timestamp_and_signature_bound() -> None:
    envelope = build_signal_envelope(
        request_fingerprint="request-123",
        signal_type="authority_link_signal",
        payload={"authority_id": "authority-1"},
        source_records=[source()],
        timestamp="2026-06-19T00:00:00Z",
    )
    assert validate_signal_envelope(envelope)
    for field in ("request_fingerprint", "digest", "timestamp", "signature"):
        broken = dict(envelope)
        broken.pop(field)
        assert not validate_signal_envelope(broken)


def test_signal_envelope_rejects_external_execution_authority() -> None:
    with pytest.raises(ValueError, match="authority"):
        build_signal_envelope(
            request_fingerprint="request-123",
            signal_type="invalid_signal",
            payload={"execution_permission": "ALLOW"},
            source_records=[source()],
        )

