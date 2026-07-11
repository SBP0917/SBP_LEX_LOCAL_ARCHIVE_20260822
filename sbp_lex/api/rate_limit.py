from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

ADMISSION_DOMAIN = "SBP_LEX_DESKTOP_V1_H2D_ADMISSION_STATE"
ADMISSION_VERSION = "H2D_ADMISSION_STATE_V1"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ADMISSION_ROOT = (REPOSITORY_ROOT / "runtime_artifacts" / "api_security_state").resolve()
DEFAULT_ADMISSION_PATH = ADMISSION_ROOT / "admission_state.json"
MAX_PERSISTED_BYTES = 1_048_576

RATE_DENIAL = "api_rate_limit_exceeded"
CONCURRENCY_DENIAL = "api_concurrency_limit_exceeded"
AUTH_FAILURE_DENIAL = "authentication_failure_limit_exceeded"
CAPACITY_DENIAL = "runtime_capacity_unavailable"
INVALID_STATE_DENIAL = "admission_state_invalid"


class AdmissionConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True)
class AdmissionConfiguration:
    requests_per_window: int = 120
    authentication_failures_per_window: int = 12
    maximum_concurrent_traversals: int = 4
    maximum_concurrent_replays: int = 1
    maximum_concurrent_connectors: int = 4
    maximum_event_stream_subscribers: int = 8
    maximum_exports: int = 2
    maximum_tracked_identities: int = 1024
    admission_retention_seconds: int = 300
    cooldown_seconds: int = 60
    window_seconds: int = 60


_CONFIG_FIELDS: dict[str, tuple[str, int]] = {
    "requests_per_window": ("SBP_LEX_ADMISSION_REQUESTS_PER_WINDOW", 1000),
    "authentication_failures_per_window": ("SBP_LEX_ADMISSION_AUTH_FAILURES_PER_WINDOW", 100),
    "maximum_concurrent_traversals": ("SBP_LEX_ADMISSION_MAX_CONCURRENT_TRAVERSALS", 32),
    "maximum_concurrent_replays": ("SBP_LEX_ADMISSION_MAX_CONCURRENT_REPLAYS", 8),
    "maximum_concurrent_connectors": ("SBP_LEX_ADMISSION_MAX_CONCURRENT_CONNECTORS", 32),
    "maximum_event_stream_subscribers": ("SBP_LEX_ADMISSION_MAX_EVENT_SUBSCRIBERS", 64),
    "maximum_exports": ("SBP_LEX_ADMISSION_MAX_EXPORTS", 16),
    "maximum_tracked_identities": ("SBP_LEX_ADMISSION_MAX_TRACKED_IDENTITIES", 4096),
    "admission_retention_seconds": ("SBP_LEX_ADMISSION_RETENTION_SECONDS", 3600),
    "cooldown_seconds": ("SBP_LEX_ADMISSION_COOLDOWN_SECONDS", 600),
    "window_seconds": ("SBP_LEX_ADMISSION_WINDOW_SECONDS", 300),
}


def load_admission_configuration(environ: Mapping[str, str] | None = None) -> AdmissionConfiguration:
    source = os.environ if environ is None else environ
    defaults = AdmissionConfiguration()
    values: dict[str, int] = {}
    for field, (name, maximum) in _CONFIG_FIELDS.items():
        if name not in source:
            values[field] = getattr(defaults, field)
            continue
        raw = source[name]
        if not isinstance(raw, str) or not raw.strip():
            raise AdmissionConfigurationError(f"invalid_admission_configuration:{name}:blank")
        try:
            value = int(raw)
        except ValueError as exc:
            raise AdmissionConfigurationError(f"invalid_admission_configuration:{name}:non_numeric") from exc
        if value <= 0:
            raise AdmissionConfigurationError(f"invalid_admission_configuration:{name}:non_positive")
        if value > maximum:
            raise AdmissionConfigurationError(f"invalid_admission_configuration:{name}:excessive")
        values[field] = value
    if values["cooldown_seconds"] > values["admission_retention_seconds"]:
        raise AdmissionConfigurationError("invalid_admission_configuration:cooldown_exceeds_retention")
    return AdmissionConfiguration(**values)


def admission_class(path: str, principal_type: str | None = None) -> str:
    endpoint = urlparse(path).path
    if endpoint == "/runtime/traverse":
        return "operator_traversal"
    if endpoint == "/runtime/replay":
        return "replay"
    if endpoint.startswith("/connector/") and endpoint not in {"/connector/checkpoints"}:
        return "connector"
    if principal_type == "validator":
        return "validator"
    if principal_type == "maintenance":
        return "maintenance"
    if principal_type == "administrator":
        return "administration"
    return "observation"


def resource_class(path: str) -> str | None:
    endpoint = urlparse(path).path
    if endpoint == "/runtime/traverse":
        return "traversal"
    if endpoint == "/runtime/replay":
        return "replay"
    if endpoint in {"/connector/envelope", "/connector/build-envelope"}:
        return "connector"
    if endpoint == "/runtime/events":
        return "event_stream"
    if endpoint.startswith("/desktop/export/"):
        return "export"
    return None


@dataclass(frozen=True)
class AdmissionResult:
    allowed: bool
    status: int
    reason: str
    admission_class: str
    resource_class: str | None
    remaining: int

    def as_payload(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "admission_class": self.admission_class,
            "resource_class": self.resource_class,
            "remaining": self.remaining,
        }


class AdmissionLease:
    def __init__(self, controller: "AdmissionController", result: AdmissionResult, resource: str | None):
        self.controller = controller
        self.result = result
        self.resource = resource if result.allowed else None
        self._released = False

    def release(self) -> None:
        if self.resource is not None and not self._released:
            self.controller._release(self.resource)
            self._released = True

    def __enter__(self) -> "AdmissionLease":
        return self

    def __exit__(self, *_: Any) -> None:
        self.release()


class AdmissionController:
    """Deterministic, bounded single-host transport admission control."""

    def __init__(
        self, configuration: AdmissionConfiguration | None = None, *,
        clock: Callable[[], float] = time.time, persistence_path: Path | None = None,
        persist: bool = False,
    ) -> None:
        self.configuration = configuration or load_admission_configuration()
        self._clock = clock
        self._lock = threading.RLock()
        self._events: dict[str, list[float]] = {}
        self._failure_events: dict[str, list[float]] = {}
        self._cooldowns: dict[str, float] = {}
        self._fingerprints: dict[str, list[float]] = {}
        self._active = {name: 0 for name in ("traversal", "replay", "connector", "event_stream", "export")}
        self._high_water_time = 0.0
        self._valid = True
        self._persist = persist
        self._path = (persistence_path or DEFAULT_ADMISSION_PATH).resolve(strict=False)
        if self._persist:
            self._validate_path()
            self._load()

    def _validate_path(self) -> None:
        if not self._path.is_relative_to(ADMISSION_ROOT) or self._path.suffix.lower() != ".json":
            raise AdmissionConfigurationError("invalid_admission_state_path")

    @staticmethod
    def _digest(kind: str, value: str) -> str:
        return generate_digest({"domain": ADMISSION_DOMAIN, "kind": kind, "value": value})

    def _now(self) -> float:
        candidate = float(self._clock())
        if candidate < 0 or candidate != candidate or candidate == float("inf"):
            self._valid = False
            return self._high_water_time
        self._high_water_time = max(self._high_water_time, candidate)
        return self._high_water_time

    def _limit_for(self, resource: str) -> int:
        return {
            "traversal": self.configuration.maximum_concurrent_traversals,
            "replay": self.configuration.maximum_concurrent_replays,
            "connector": self.configuration.maximum_concurrent_connectors,
            "event_stream": self.configuration.maximum_event_stream_subscribers,
            "export": self.configuration.maximum_exports,
        }[resource]

    def _bounded_cleanup(self, now: float) -> None:
        cutoff = now - self.configuration.admission_retention_seconds
        for mapping in (self._events, self._failure_events, self._fingerprints):
            for key in sorted(list(mapping)):
                kept = [stamp for stamp in mapping[key] if cutoff < stamp <= now]
                if kept:
                    bound = max(
                        self.configuration.requests_per_window,
                        self.configuration.authentication_failures_per_window,
                    )
                    mapping[key] = kept[-bound:]
                else:
                    del mapping[key]
        for key in sorted(list(self._cooldowns)):
            if self._cooldowns[key] <= now:
                del self._cooldowns[key]

    def _tracked_keys(self) -> set[str]:
        return set(self._events) | set(self._failure_events) | set(self._cooldowns) | set(self._fingerprints)

    def _state_is_valid(self) -> bool:
        if not all(isinstance(item, dict) for item in (
            self._events, self._failure_events, self._cooldowns, self._fingerprints, self._active,
        )):
            return False
        if set(self._active) != {"traversal", "replay", "connector", "event_stream", "export"}:
            return False
        if any(not isinstance(value, int) or value < 0 for value in self._active.values()):
            return False
        try:
            self._validated_event_map(self._events)
            self._validated_event_map(self._failure_events)
            self._validated_event_map(self._fingerprints)
            self._validated_scalar_map(self._cooldowns)
        except (TypeError, ValueError):
            return False
        return True

    def _ensure_keys(self, keys: list[str]) -> bool:
        existing = self._tracked_keys()
        additions = {key for key in keys if key not in existing}
        return len(existing) + len(additions) <= self.configuration.maximum_tracked_identities

    def _snapshot_payload(self) -> dict[str, Any]:
        return {
            "version": ADMISSION_VERSION,
            "integrity_domain": ADMISSION_DOMAIN,
            "high_water_time": self._high_water_time,
            "events": {key: list(value) for key, value in sorted(self._events.items())},
            "failure_events": {key: list(value) for key, value in sorted(self._failure_events.items())},
            "cooldowns": dict(sorted(self._cooldowns.items())),
            "fingerprints": {key: list(value) for key, value in sorted(self._fingerprints.items())},
        }

    def _save(self) -> None:
        if not self._persist:
            return
        payload = self._snapshot_payload()
        wrapper = {
            "payload": payload,
            "integrity_hash": generate_digest(payload),
            "integrity_signature": sign_payload({"integrity_domain": ADMISSION_DOMAIN, "payload": payload}),
        }
        encoded = (json.dumps(wrapper, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(encoded) > MAX_PERSISTED_BYTES:
            raise RuntimeError(CAPACITY_DENIAL)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temp = self._path.with_name(self._path.name + f".{uuid.uuid4().hex}.tmp")
        try:
            with temp.open("xb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, self._path)
        except OSError as exc:
            temp.unlink(missing_ok=True)
            raise RuntimeError(CAPACITY_DENIAL) from exc

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = self._path.read_bytes()
            if len(raw) > MAX_PERSISTED_BYTES:
                raise ValueError
            wrapper = json.loads(raw)
            payload = wrapper["payload"]
            if (
                not isinstance(payload, dict)
                or payload.get("version") != ADMISSION_VERSION
                or payload.get("integrity_domain") != ADMISSION_DOMAIN
                or wrapper.get("integrity_hash") != generate_digest(payload)
                or not verify_signature(
                    {"integrity_domain": ADMISSION_DOMAIN, "payload": payload},
                    wrapper.get("integrity_signature", {}),
                )
            ):
                raise ValueError
            self._high_water_time = float(payload["high_water_time"])
            self._events = self._validated_event_map(payload["events"])
            self._failure_events = self._validated_event_map(payload["failure_events"])
            self._cooldowns = self._validated_scalar_map(payload["cooldowns"])
            self._fingerprints = self._validated_event_map(payload["fingerprints"])
            if len(self._tracked_keys()) > self.configuration.maximum_tracked_identities:
                raise ValueError
            self._bounded_cleanup(self._now())
        except Exception:
            self._valid = False

    @staticmethod
    def _validated_event_map(value: Any) -> dict[str, list[float]]:
        if not isinstance(value, dict):
            raise ValueError
        result: dict[str, list[float]] = {}
        for key, events in value.items():
            if not isinstance(key, str) or not isinstance(events, list):
                raise ValueError
            parsed = [float(stamp) for stamp in events]
            if any(stamp < 0 or stamp != stamp or stamp == float("inf") for stamp in parsed):
                raise ValueError
            result[key] = sorted(parsed)
        return result

    @staticmethod
    def _validated_scalar_map(value: Any) -> dict[str, float]:
        if not isinstance(value, dict):
            raise ValueError
        result = {str(key): float(stamp) for key, stamp in value.items()}
        if any(stamp < 0 or stamp != stamp or stamp == float("inf") for stamp in result.values()):
            raise ValueError
        return result

    def _deny(self, reason: str, klass: str, resource: str | None, status: int) -> AdmissionLease:
        return AdmissionLease(self, AdmissionResult(False, status, reason, klass, resource, 0), None)

    def admit(
        self, *, source_address: str, endpoint: str, credential_id: str,
        principal_id: str, principal_type: str, request_fingerprint: str | None = None,
    ) -> AdmissionLease:
        klass = admission_class(endpoint, principal_type)
        resource = resource_class(endpoint)
        with self._lock:
            now = self._now()
            if not self._valid or not self._state_is_valid():
                self._valid = False
                return self._deny(INVALID_STATE_DENIAL, klass, resource, 503)
            self._bounded_cleanup(now)
            values = {
                "source": source_address, "credential": credential_id,
                "principal": principal_id, "principal_type": principal_type,
                "endpoint": urlparse(endpoint).path,
            }
            keys = [self._digest(kind, f"{klass}:{value}") for kind, value in values.items()]
            fingerprint_key = self._digest("fingerprint", request_fingerprint) if request_fingerprint else None
            all_keys = keys + ([fingerprint_key] if fingerprint_key else [])
            if not self._ensure_keys(all_keys):
                return self._deny(CAPACITY_DENIAL, klass, resource, 503)
            window_cutoff = now - self.configuration.window_seconds
            for key in keys:
                recent = [stamp for stamp in self._events.get(key, []) if stamp > window_cutoff]
                if len(recent) >= self.configuration.requests_per_window:
                    return self._deny(RATE_DENIAL, klass, resource, 429)
            if fingerprint_key:
                duplicates = [stamp for stamp in self._fingerprints.get(fingerprint_key, []) if stamp > window_cutoff]
                if len(duplicates) >= self.configuration.authentication_failures_per_window:
                    return self._deny(RATE_DENIAL, klass, resource, 429)
            if resource is not None:
                current = self._active.get(resource)
                if not isinstance(current, int) or current < 0:
                    self._valid = False
                    return self._deny(INVALID_STATE_DENIAL, klass, resource, 503)
                if current >= self._limit_for(resource):
                    return self._deny(CONCURRENCY_DENIAL, klass, resource, 429)
            for key in keys:
                self._events.setdefault(key, []).append(now)
            if fingerprint_key:
                self._fingerprints.setdefault(fingerprint_key, []).append(now)
            if resource is not None:
                self._active[resource] += 1
            try:
                self._save()
            except RuntimeError as exc:
                if resource is not None:
                    self._active[resource] -= 1
                self._valid = False
                return self._deny(str(exc), klass, resource, 503)
            remaining = min(
                self.configuration.requests_per_window - len(self._events[key]) for key in keys
            )
            return AdmissionLease(self, AdmissionResult(True, 200, "admission_allowed", klass, resource, remaining), resource)

    def record_failure(self, *, source_address: str, endpoint: str, failure_type: str) -> AdmissionResult:
        klass = admission_class(endpoint)
        with self._lock:
            now = self._now()
            if not self._valid or not self._state_is_valid():
                self._valid = False
                return AdmissionResult(False, 503, INVALID_STATE_DENIAL, klass, None, 0)
            self._bounded_cleanup(now)
            key = self._digest(failure_type, f"{klass}:{source_address}:{urlparse(endpoint).path}")
            if not self._ensure_keys([key]):
                return AdmissionResult(False, 503, CAPACITY_DENIAL, klass, None, 0)
            if self._cooldowns.get(key, 0) > now:
                return AdmissionResult(False, 429, AUTH_FAILURE_DENIAL, klass, None, 0)
            cutoff = now - self.configuration.window_seconds
            recent = [stamp for stamp in self._failure_events.get(key, []) if stamp > cutoff]
            recent.append(now)
            self._failure_events[key] = recent
            if len(recent) >= self.configuration.authentication_failures_per_window:
                self._cooldowns[key] = now + self.configuration.cooldown_seconds
                reason, status = AUTH_FAILURE_DENIAL, 429
            else:
                reason, status = "failure_recorded", 200
            try:
                self._save()
            except RuntimeError:
                self._valid = False
                return AdmissionResult(False, 503, CAPACITY_DENIAL, klass, None, 0)
            return AdmissionResult(status == 200, status, reason, klass, None, max(0, self.configuration.authentication_failures_per_window - len(recent)))

    def preflight_failure_limits(
        self, *, source_address: str, endpoint: str,
        failure_types: tuple[str, ...] = ("authentication_failure", "malformed_request"),
    ) -> AdmissionResult:
        """Reject an established abuse cooldown before parsing or authentication."""
        klass = admission_class(endpoint)
        with self._lock:
            now = self._now()
            if not self._valid or not self._state_is_valid():
                self._valid = False
                return AdmissionResult(False, 503, INVALID_STATE_DENIAL, klass, None, 0)
            self._bounded_cleanup(now)
            for failure_type in sorted(failure_types):
                key = self._digest(
                    failure_type,
                    f"{klass}:{source_address}:{urlparse(endpoint).path}",
                )
                if self._cooldowns.get(key, 0) > now:
                    return AdmissionResult(False, 429, AUTH_FAILURE_DENIAL, klass, None, 0)
            return AdmissionResult(True, 200, "failure_preflight_allowed", klass, None, 0)

    def _release(self, resource: str) -> None:
        with self._lock:
            value = self._active.get(resource)
            if not isinstance(value, int) or value <= 0:
                self._valid = False
                return
            self._active[resource] = value - 1

    def invalidate_for_tests(self) -> None:
        with self._lock:
            self._valid = False


_ACTIVE_CONTROLLER: AdmissionController | None = None
_ACTIVE_CONFIGURATION: AdmissionConfiguration | None = None


def initialize_admission_controller(*, persist: bool = True) -> AdmissionController:
    global _ACTIVE_CONTROLLER, _ACTIVE_CONFIGURATION
    configuration = load_admission_configuration()
    _ACTIVE_CONTROLLER = AdmissionController(configuration, persist=persist)
    _ACTIVE_CONFIGURATION = configuration
    return _ACTIVE_CONTROLLER


def active_admission_controller() -> AdmissionController:
    global _ACTIVE_CONTROLLER, _ACTIVE_CONFIGURATION
    configuration = load_admission_configuration()
    if _ACTIVE_CONTROLLER is None or _ACTIVE_CONFIGURATION != configuration:
        _ACTIVE_CONTROLLER = AdmissionController(configuration, persist=False)
        _ACTIVE_CONFIGURATION = configuration
    return _ACTIVE_CONTROLLER


def reset_admission_controller_for_tests() -> None:
    global _ACTIVE_CONTROLLER, _ACTIVE_CONFIGURATION
    _ACTIVE_CONTROLLER = None
    _ACTIVE_CONFIGURATION = None
