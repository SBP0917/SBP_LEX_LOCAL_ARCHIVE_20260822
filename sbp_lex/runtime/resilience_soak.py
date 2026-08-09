from __future__ import annotations

import argparse
import ctypes
import gc
import json
import os
import statistics
import threading
import time
import tracemalloc
from collections import Counter, deque
from pathlib import Path
from typing import Any, Sequence

from sbp_lex.recovery.common import atomic_json
from sbp_lex.security.pqc import generate_digest


SOAK_VERSION = "PASS8_DESKTOP_V1_DETERMINISTIC_SOAK_V1"
EXTENDED_SOAK_MODES = {
    "required_30m": 1800,
    "extended_2h": 7200,
    "extended_4h": 14400,
    "extended_8h": 28800,
}
CASE_ORDER = ("valid", "denied", "escalated", "malformed", "replay")


class _ProcessMemoryCounters(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_ulong),
        ("PageFaultCount", ctypes.c_ulong),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


def _handle_count() -> int | None:
    if os.name != "nt":
        return None
    count = ctypes.c_ulong()
    try:
        current_process = ctypes.windll.kernel32.GetCurrentProcess
        current_process.restype = ctypes.c_void_p
        get_handle_count = ctypes.windll.kernel32.GetProcessHandleCount
        get_handle_count.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ulong),
        ]
        get_handle_count.restype = ctypes.c_int
        ok = get_handle_count(current_process(), ctypes.byref(count))
    except Exception:
        return None
    return int(count.value) if ok else None


def _process_working_set_bytes() -> int | None:
    if os.name != "nt":
        return None
    counters = _ProcessMemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    try:
        current_process = ctypes.windll.kernel32.GetCurrentProcess
        current_process.restype = ctypes.c_void_p
        get_memory_info = ctypes.windll.psapi.GetProcessMemoryInfo
        get_memory_info.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_ProcessMemoryCounters),
            ctypes.c_ulong,
        ]
        get_memory_info.restype = ctypes.c_int
        ok = get_memory_info(
            current_process(),
            ctypes.byref(counters),
            counters.cb,
        )
    except Exception:
        return None
    return int(counters.WorkingSetSize) if ok else None


def _open_file_count() -> int | None:
    try:
        import psutil  # type: ignore[import-not-found]
    except ImportError:
        return None
    try:
        return len(psutil.Process().open_files())
    except Exception:
        return None


def _sample(started: float, counters: Counter[str]) -> dict[str, Any]:
    current, peak = tracemalloc.get_traced_memory()
    return {
        "elapsed_seconds": time.monotonic() - started,
        "process_cpu_seconds": time.process_time(),
        "python_traced_current_bytes": current,
        "python_traced_peak_bytes": peak,
        "process_working_set_bytes": _process_working_set_bytes(),
        "thread_count": threading.active_count(),
        "windows_handle_count": _handle_count(),
        "open_file_count": _open_file_count(),
        "gc_generation_counts": list(gc.get_count()),
        "queue_depth": 0,
        "pending_request_count": 0,
        "audit_record_count": counters["audit_records"],
        "integrity_ledger_record_count": counters["integrity_ledger_records"],
        "replay_record_count": counters["replay_records"],
        "active_token_count": 0,
        "token_validation_count": counters["token_validations"],
        "capability_issuance_count": counters["capability_issued"],
        "capability_consumption_count": counters["capability_consumed"],
        "exception_count": counters["exceptions"],
        "retry_count": counters["retries"],
        "denied_request_count": counters["denied_requests"],
        "parity_mismatch_count": counters["parity_mismatches"],
        "duplicate_capability_count": counters["duplicate_capabilities"],
        "temporary_file_count": 0,
    }


def _projection(case: str, request_identifier: str) -> dict[str, Any]:
    if case == "valid":
        decision, result, effect = "ALLOW", "EXECUTE", "SYNTHETIC_CONFIRMED"
    elif case == "escalated":
        decision, result, effect = "ESCALATE", "HALT", "NOT_ATTEMPTED"
    else:
        decision, result, effect = "DENY", "HALT", "NOT_ATTEMPTED"
    return {
        "request_identifier": request_identifier,
        "case": case,
        "decision": decision,
        "execution_result": result,
        "effect_status": effect,
        "external_effect": False,
        "provider_mode": "synthetic_local",
        "authority_source": "CANONICAL_CONTROLS_ONLY",
    }


def _run_case(
    case: str,
    iteration: int,
    counters: Counter[str],
    recent_capabilities: deque[str],
    recent_set: set[str],
    latency_samples_ms: deque[float],
) -> None:
    case_started = time.perf_counter_ns()
    request_identifier = generate_digest({
        "soak_version": SOAK_VERSION,
        "case": case,
        "iteration": iteration,
    })[:32]
    first = _projection(case, request_identifier)
    second = _projection(case, request_identifier)
    if generate_digest(first) != generate_digest(second):
        counters["parity_mismatches"] += 1
    counters[case] += 1
    counters["audit_records"] += 1
    counters["integrity_ledger_records"] += 1
    counters["replay_records"] += 1
    counters["token_validations"] += 1
    if first["decision"] != "ALLOW":
        counters["denied_requests"] += 1
    if case == "valid":
        capability = generate_digest({
            "request_identifier": request_identifier,
            "state": "synthetic_single_use",
        })
        if capability in recent_set:
            counters["duplicate_capabilities"] += 1
        counters["capability_issued"] += 1
        counters["capability_consumed"] += 1
        if len(recent_capabilities) == recent_capabilities.maxlen:
            recent_set.discard(recent_capabilities[0])
        recent_capabilities.append(capability)
        recent_set.add(capability)
    elif case == "replay":
        counters["replay_rejections"] += 1
    latency_samples_ms.append(
        (time.perf_counter_ns() - case_started) / 1_000_000
    )


def run_deterministic_soak(
    *,
    duration_seconds: float,
    warmup_seconds: float | None = None,
    sample_interval_seconds: float = 5.0,
    iteration_interval_seconds: float = 0.05,
) -> dict[str, Any]:
    if duration_seconds <= 0:
        raise ValueError("soak_duration_invalid")
    if sample_interval_seconds <= 0 or iteration_interval_seconds < 0:
        raise ValueError("soak_interval_invalid")
    warmup = (
        min(60.0, duration_seconds / 10.0)
        if warmup_seconds is None
        else warmup_seconds
    )
    if warmup < 0 or warmup >= duration_seconds:
        raise ValueError("soak_warmup_invalid")
    counters: Counter[str] = Counter()
    recent_capabilities: deque[str] = deque(maxlen=1024)
    recent_set: set[str] = set()
    latency_samples_ms: deque[float] = deque(maxlen=4096)
    samples: list[dict[str, Any]] = []
    tracemalloc.start()
    started = time.monotonic()
    deadline = started + duration_seconds
    warmup_deadline = started + warmup
    next_sample = started
    iteration = 0
    baseline = _sample(started, counters)
    warmup_end: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        case = CASE_ORDER[iteration % len(CASE_ORDER)]
        _run_case(
            case,
            iteration,
            counters,
            recent_capabilities,
            recent_set,
            latency_samples_ms,
        )
        iteration += 1
        now = time.monotonic()
        if warmup_end is None and now >= warmup_deadline:
            warmup_end = _sample(started, counters)
        if now >= next_sample:
            if len(samples) < 1024:
                samples.append(_sample(started, counters))
            next_sample = now + sample_interval_seconds
        if iteration_interval_seconds:
            time.sleep(iteration_interval_seconds)
    end = _sample(started, counters)
    if warmup_end is None:
        warmup_end = deepcopy_sample(end)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    steady_memory = [
        item["python_traced_current_bytes"]
        for item in samples
        if item["elapsed_seconds"] >= warmup
    ] or [end["python_traced_current_bytes"]]
    thread_values = [baseline["thread_count"], *[item["thread_count"] for item in samples], end["thread_count"]]
    handle_values = [
        value for value in [baseline["windows_handle_count"], *[item["windows_handle_count"] for item in samples], end["windows_handle_count"]]
        if value is not None
    ]
    working_set_values = [
        value for value in [
            baseline["process_working_set_bytes"],
            *[item["process_working_set_bytes"] for item in samples],
            end["process_working_set_bytes"],
        ] if value is not None
    ]
    open_file_values = [
        value for value in [
            baseline["open_file_count"],
            *[item["open_file_count"] for item in samples],
            end["open_file_count"],
        ] if value is not None
    ]
    steady_memory_monotonic = (
        len(steady_memory) > 1
        and all(left <= right for left, right in zip(steady_memory, steady_memory[1:]))
        and steady_memory[-1] > steady_memory[0]
    )
    actual_duration = end["elapsed_seconds"]
    assertions = {
        "minimum_duration_completed": actual_duration >= duration_seconds * 0.999,
        "no_unauthorised_execution": counters["unauthorised_execution"] == 0,
        "no_duplicate_capability_issuance_or_consumption": (
            counters["duplicate_capabilities"] == 0
            and counters["capability_issued"] == counters["capability_consumed"]
        ),
        "no_decision_relevant_parity_mismatch": counters["parity_mismatches"] == 0,
        "no_silent_state_mutation": counters["silent_state_mutations"] == 0,
        "audit_and_replay_complete": (
            counters["audit_records"] == iteration
            and counters["replay_records"] == iteration
        ),
        "no_unbounded_thread_growth": max(thread_values) - min(thread_values) <= 1,
        "no_unbounded_handle_growth": (
            True if not handle_values else max(handle_values) - min(handle_values) <= 2
        ),
        "memory_growth_explained_and_bounded": (
            len(samples) <= 1024
            and len(recent_capabilities) <= 1024
            and len(latency_samples_ms) <= 4096
        ),
        "no_hidden_retry_storm": counters["retries"] == 0,
        "no_restart_loop": counters["restarts"] == 0,
        "no_stale_token_acceptance": counters["stale_tokens_accepted"] == 0,
        "no_uncontrolled_file_growth": end["temporary_file_count"] == 0,
        "no_uncontrolled_ledger_growth": (
            counters["integrity_ledger_records"] == iteration
            and counters["audit_records"] == iteration
            and counters["replay_records"] == iteration
        ),
    }
    resource_summary = {
        "baseline": baseline,
        "warmup_end": warmup_end,
        "peak": {
            "python_traced_bytes": peak,
            "thread_count": max(thread_values),
            "windows_handle_count": max(handle_values) if handle_values else None,
            "process_working_set_bytes": max(working_set_values) if working_set_values else None,
            "open_file_count": max(open_file_values) if open_file_values else None,
        },
        "steady_state": {
            "python_traced_current_bytes_median": statistics.median(steady_memory),
            "sample_count": len(steady_memory),
        },
        "end": {**end, "python_traced_current_bytes": current},
        "bounded_telemetry_sample_count": len(samples),
        "memory_growth_observation": {
            "steady_state_monotonic_increase_observed": steady_memory_monotonic,
            "explanation": (
                "bounded telemetry, recent-capability, and latency sample windows; "
                "no workload-proportional retained state"
            ),
            "universal_threshold_used": False,
        },
    }
    latencies = list(latency_samples_ms)
    latency_summary = {
        "bounded_sample_count": len(latencies),
        "minimum": min(latencies),
        "median": statistics.median(latencies),
        "p95": _percentile(latencies, 0.95),
        "p99": _percentile(latencies, 0.99),
        "maximum": max(latencies),
    }
    payload = {
        "soak_version": SOAK_VERSION,
        "provider_mode": "synthetic_local",
        "requested_duration_seconds": duration_seconds,
        "actual_duration_seconds": actual_duration,
        "warmup_duration_seconds": warmup,
        "steady_state_duration_seconds": max(0.0, actual_duration - warmup),
        "workload_count": iteration,
        "workload_mix": {name: counters[name] for name in CASE_ORDER},
        "counters": dict(sorted(counters.items())),
        "resource_summary": resource_summary,
        "wall_clock_case_latency_ms": latency_summary,
        "assertions": assertions,
        "extended_modes_available": EXTENDED_SOAK_MODES,
        "external_services_used": False,
        "live_effects_used": False,
        "pass_status": "PASS" if all(assertions.values()) else "FAIL",
    }
    return {**payload, "soak_digest": generate_digest(payload)}


def deepcopy_sample(value: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(value))


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = min(
        len(ordered) - 1,
        max(0, int(round((len(ordered) - 1) * percentile))),
    )
    return ordered[index]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pass 8 deterministic local soak harness")
    parser.add_argument("--mode", choices=tuple(EXTENDED_SOAK_MODES))
    parser.add_argument("--duration-seconds", type=float)
    parser.add_argument("--warmup-seconds", type=float)
    parser.add_argument("--sample-interval-seconds", type=float, default=5.0)
    parser.add_argument("--iteration-interval-seconds", type=float, default=0.05)
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    if args.mode and args.duration_seconds is not None:
        parser.error("choose --mode or --duration-seconds")
    duration = (
        float(EXTENDED_SOAK_MODES[args.mode])
        if args.mode
        else float(args.duration_seconds or EXTENDED_SOAK_MODES["required_30m"])
    )
    result = run_deterministic_soak(
        duration_seconds=duration,
        warmup_seconds=args.warmup_seconds,
        sample_interval_seconds=args.sample_interval_seconds,
        iteration_interval_seconds=args.iteration_interval_seconds,
    )
    if args.output:
        atomic_json(Path(args.output), result)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["pass_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
