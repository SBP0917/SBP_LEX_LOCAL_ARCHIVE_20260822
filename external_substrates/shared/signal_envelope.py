from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping, Sequence

from external_substrates.shared.digest import digest_mapping
from external_substrates.shared.freshness import utc_timestamp, validate_freshness
from external_substrates.shared.signing import sign_payload, verify_signature
from external_substrates.shared.source_attestation import count_attested_sources, validate_source_record
from external_substrates.shared.validation import contains_prohibited_authority, require_non_empty_string


def _digest_body(envelope: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value) for key, value in envelope.items() if key not in {"digest", "signature"}}


def _signature_body(envelope: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value) for key, value in envelope.items() if key != "signature"}


def build_signal_envelope(
    *,
    request_fingerprint: str,
    signal_type: str,
    payload: Mapping[str, Any],
    source_records: Sequence[Mapping[str, Any]],
    timestamp: str | None = None,
    signing_key: str | bytes | None = None,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not require_non_empty_string(request_fingerprint):
        raise ValueError("request_fingerprint is required")
    if not require_non_empty_string(signal_type):
        raise ValueError("signal_type is required")
    if contains_prohibited_authority(payload):
        raise ValueError("external signals cannot contain execution or governance authority")
    sources = [deepcopy(dict(source)) for source in source_records]
    envelope: dict[str, Any] = {
        "request_fingerprint": request_fingerprint,
        "signal_type": signal_type,
        "payload": deepcopy(dict(payload)),
        "source_records": sources,
        "attestation_count": count_attested_sources(sources),
        "freshness_valid": bool(sources) and all(source.get("freshness_valid") is True for source in sources),
        "consistency_valid": bool(sources) and all(source.get("consistency_valid") is True for source in sources),
        "timestamp": timestamp or utc_timestamp(),
    }
    if extra:
        envelope.update(deepcopy(dict(extra)))
    envelope["digest"] = digest_mapping(_digest_body(envelope))
    envelope["signature"] = sign_payload(_signature_body(envelope), signing_key)
    return envelope


def validate_signal_envelope(
    envelope: Mapping[str, Any],
    *,
    verification_key: str | bytes | None = None,
    max_age_seconds: int | float | None = None,
    now: Any = None,
) -> bool:
    required = {
        "request_fingerprint",
        "signal_type",
        "payload",
        "source_records",
        "attestation_count",
        "freshness_valid",
        "consistency_valid",
        "digest",
        "signature",
        "timestamp",
    }
    if not isinstance(envelope, Mapping) or not required.issubset(envelope):
        return False
    if not require_non_empty_string(envelope.get("request_fingerprint")):
        return False
    if not require_non_empty_string(envelope.get("signal_type")) or not isinstance(envelope.get("payload"), Mapping):
        return False
    if not require_non_empty_string(envelope.get("timestamp")):
        return False
    if not require_non_empty_string(envelope.get("digest")) or not require_non_empty_string(envelope.get("signature")):
        return False
    sources = envelope.get("source_records")
    if not isinstance(sources, list) or not all(validate_source_record(source) for source in sources):
        return False
    if contains_prohibited_authority(envelope):
        return False
    if envelope.get("attestation_count") != count_attested_sources(sources):
        return False
    if envelope.get("freshness_valid") is not (bool(sources) and all(source.get("freshness_valid") is True for source in sources)):
        return False
    if envelope.get("consistency_valid") is not (bool(sources) and all(source.get("consistency_valid") is True for source in sources)):
        return False
    if envelope.get("digest") != digest_mapping(_digest_body(envelope)):
        return False
    if not verify_signature(_signature_body(envelope), str(envelope.get("signature")), verification_key):
        return False
    if max_age_seconds is not None and not validate_freshness(envelope.get("timestamp"), max_age_seconds, now):
        return False
    return True
