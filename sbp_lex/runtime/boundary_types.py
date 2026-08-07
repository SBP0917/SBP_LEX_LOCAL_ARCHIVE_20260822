from __future__ import annotations

from dataclasses import dataclass
import json
from threading import RLock
from typing import Any, Mapping

from external_substrates.shared.canonical_json import canonical_dumps
from sbp_lex.security.pqc import generate_digest, verify_signature


def _decode_mapping(value: str, *, reason: str) -> dict[str, Any]:
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(reason) from exc
    if not isinstance(decoded, dict):
        raise ValueError(reason)
    return decoded


@dataclass(frozen=True)
class AdapterResult:
    """Immutable, serialized output of the non-authoritative request adapter."""

    schema_version: str
    normalized_request_json: str
    normalized_request_digest: str
    request_fingerprint: str
    input_size_bytes: int
    adapter_digest: str

    def normalized_request(self) -> dict[str, Any]:
        return _decode_mapping(
            self.normalized_request_json,
            reason="adapter_normalized_request_invalid",
        )

    def validate(self) -> tuple[bool, list[str]]:
        failures: list[str] = []
        try:
            request = self.normalized_request()
        except ValueError as exc:
            return False, [str(exc)]
        canonical = canonical_dumps(request)
        digest = generate_digest(request)
        if canonical != self.normalized_request_json:
            failures.append("adapter_serialization_not_canonical")
        if digest != self.normalized_request_digest:
            failures.append("normalized_request_digest_mismatch")
        if digest != self.request_fingerprint:
            failures.append("request_fingerprint_mismatch")
        if len(canonical.encode("utf-8")) != self.input_size_bytes:
            failures.append("adapter_input_size_mismatch")
        payload = {
            "schema_version": self.schema_version,
            "normalized_request_digest": self.normalized_request_digest,
            "request_fingerprint": self.request_fingerprint,
            "input_size_bytes": self.input_size_bytes,
        }
        if self.adapter_digest != generate_digest(payload):
            failures.append("adapter_digest_mismatch")
        return not failures, sorted(set(failures))


@dataclass(frozen=True)
class HardEntryAdmission:
    """Immutable capability-free proof that Hard Entry accepted one boundary."""

    schema_version: str
    adapter: AdapterResult
    eie_json: str
    eie_digest: str
    collective_signal_json: str
    collective_signal_digest: str
    substrate_evidence_json: str
    bridge_result_digest: str
    validation_logical_time: int
    admission_digest: str

    def eie(self) -> dict[str, Any]:
        return _decode_mapping(self.eie_json, reason="hard_entry_eie_invalid")

    def collective_signals(self) -> dict[str, Any]:
        return _decode_mapping(
            self.collective_signal_json,
            reason="hard_entry_collective_signal_invalid",
        )

    def substrate_evidence(self) -> dict[str, Any]:
        return _decode_mapping(
            self.substrate_evidence_json,
            reason="hard_entry_substrate_evidence_invalid",
        )

    def digest_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "adapter_digest": self.adapter.adapter_digest,
            "request_fingerprint": self.adapter.request_fingerprint,
            "eie_digest": self.eie_digest,
            "collective_signal_digest": self.collective_signal_digest,
            "substrate_evidence_digest": generate_digest(
                self.substrate_evidence()
            ),
            "bridge_result_digest": self.bridge_result_digest,
            "validation_logical_time": self.validation_logical_time,
        }

    def validate_seal(self) -> tuple[bool, list[str]]:
        failures: list[str] = []
        adapter_valid, adapter_failures = self.adapter.validate()
        if not adapter_valid:
            failures.extend(adapter_failures)
        try:
            eie = self.eie()
            signals = self.collective_signals()
            evidence = self.substrate_evidence()
        except ValueError as exc:
            return False, sorted(set(failures + [str(exc)]))
        if canonical_dumps(eie) != self.eie_json:
            failures.append("hard_entry_eie_serialization_not_canonical")
        if canonical_dumps(signals) != self.collective_signal_json:
            failures.append("hard_entry_signal_serialization_not_canonical")
        if canonical_dumps(evidence) != self.substrate_evidence_json:
            failures.append("hard_entry_evidence_serialization_not_canonical")
        if eie.get("eie_hash") != self.eie_digest:
            failures.append("hard_entry_eie_digest_mismatch")
        eie_payload = {
            key: value for key, value in eie.items() if key != "eie_hash"
        }
        if generate_digest(eie_payload) != self.eie_digest:
            failures.append("hard_entry_eie_content_digest_mismatch")
        if signals.get("digest") != self.collective_signal_digest:
            failures.append("hard_entry_signal_digest_mismatch")
        signal_payload = {
            key: value
            for key, value in signals.items()
            if key not in {"digest", "signature"}
        }
        if generate_digest(signal_payload) != self.collective_signal_digest:
            failures.append("hard_entry_signal_content_digest_mismatch")
        if not verify_signature(signal_payload, signals.get("signature", {})):
            failures.append("hard_entry_signal_signature_invalid")
        if evidence.get("bridge_result_digest") != self.bridge_result_digest:
            failures.append("hard_entry_bridge_digest_mismatch")
        if self.admission_digest != generate_digest(self.digest_payload()):
            failures.append("hard_entry_admission_digest_mismatch")
        return not failures, sorted(set(failures))


@dataclass(frozen=True)
class HardEntryResult:
    accepted: bool
    admission: HardEntryAdmission | None
    evidence_json: str

    def evidence(self) -> dict[str, Any]:
        return _decode_mapping(
            self.evidence_json,
            reason="hard_entry_result_evidence_invalid",
        )


class EIEReplayRegistry:
    """Caller-owned nonce/digest replay registry for one admission domain."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._nonces: set[str] = set()
        self._digests: set[str] = set()

    def validate_and_record(
        self, *, nonce: str, eie_digest: str
    ) -> tuple[bool, list[str]]:
        failures: list[str] = []
        with self._lock:
            if nonce in self._nonces:
                failures.append("replayed_eie_nonce")
            if eie_digest in self._digests:
                failures.append("replayed_eie_digest")
            if not failures:
                self._nonces.add(nonce)
                self._digests.add(eie_digest)
        return not failures, failures

    def snapshot(self) -> Mapping[str, tuple[str, ...]]:
        with self._lock:
            return {
                "nonces": tuple(sorted(self._nonces)),
                "digests": tuple(sorted(self._digests)),
            }
