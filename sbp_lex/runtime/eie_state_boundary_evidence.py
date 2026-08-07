from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from main import sample_request
from sbp_lex.pipeline.dual_runner import run_dual_pipeline
from sbp_lex.pipeline.hard_ingress import run_hard_ingress
from sbp_lex.pipeline.replay_runner import run_replay_check
from sbp_lex.pipeline.runner import _run_admitted_pipeline, run_pipeline
from sbp_lex.security.pqc import generate_digest
from sbp_lex.shared import state_builder


SCHEMA_VERSION = "desktop-v1.runtime-pass3-evidence.v1"


def build_runtime_pass3_evidence() -> dict[str, Any]:
    request = sample_request()
    ingress = run_hard_ingress(request=request)
    if not ingress.accepted or ingress.admission is None:
        raise RuntimeError("runtime_pass3_valid_ingress_unavailable")
    admission = ingress.admission
    state = run_dual_pipeline(request)
    replay = run_replay_check(request=request, replay_count=3)
    invalid = dict(request)
    invalid["undeclared_state"] = {"state_hash": "injected"}
    denial = run_pipeline(invalid)
    state_builder_bypass_rejected = False
    downstream_bypass_rejected = False
    try:
        state_builder.build_state(request)  # type: ignore[arg-type]
    except TypeError:
        state_builder_bypass_rejected = True
    try:
        _run_admitted_pipeline({})  # type: ignore[arg-type]
    except TypeError:
        downstream_bypass_rejected = True
    parity = state.get("pipeline_initial_parity", {})
    evidence_payload = {
        "schema_version": SCHEMA_VERSION,
        "captured_at": "2026-08-07T00:00:00Z",
        "runtime": "SBP_LEX_DUAL_V6_DESKTOP_V1",
        "provider_mode": "synthetic_local",
        "normalized_request_digest": (
            admission.adapter.normalized_request_digest
        ),
        "request_fingerprint": admission.adapter.request_fingerprint,
        "eie_digest": admission.eie_digest,
        "skg_package_digest": state.get(
            "verified_substrate_references", {}
        ).get("skg_package_digest"),
        "dtn_package_digest": state.get(
            "verified_substrate_references", {}
        ).get("dtn_package_digest"),
        "bridge_result_digest": admission.bridge_result_digest,
        "initial_state_hash": parity.get("initial_state_hash"),
        "state_hash_basis": parity.get("state_hash_basis"),
        "collective_signal_package_digest": parity.get(
            "collective_signal_package_digest"
        ),
        "collective_attachment_hash": parity.get(
            "collective_attachment_hash"
        ),
        "pipeline_a_initial_hash": parity.get(
            "pipeline_a_initial_hash"
        ),
        "pipeline_b_initial_hash": parity.get(
            "pipeline_b_initial_hash"
        ),
        "exact_parity_result": parity.get("exact_parity_result"),
        "near_match_reconciliation_used": parity.get(
            "near_match_reconciliation_used"
        ),
        "boundary_results": {
            "hard_entry_accepted": state.get("hard_entry_gate", {}).get(
                "accepted"
            ),
            "state_schema_version": state.get("state_schema_version"),
            "state_construction_hash": state.get(
                "state_construction_hash"
            ),
            "collective_signal_status": state.get(
                "collective_signal_status"
            ),
            "decision": state.get("decision"),
            "execution_result": state.get("execution_result"),
            "replay_matched": replay.get("matched"),
            "replay_hash": replay.get("replay_hash"),
            "replay_mismatches": replay.get("mismatches"),
            "invalid_ingress_governed_state_formed": denial.get(
                "governed_state_formed"
            ),
            "invalid_ingress_authority_token_issued": denial.get(
                "authority_token_issued"
            ),
            "state_builder_bypass_rejected": state_builder_bypass_rejected,
            "downstream_bypass_rejected": downstream_bypass_rejected,
        },
    }
    return {
        **evidence_payload,
        "evidence_digest": generate_digest(evidence_payload),
    }


def write_runtime_pass3_evidence(path: Path | None = None) -> Path:
    repository_root = Path(__file__).resolve().parents[2]
    target = path or (
        repository_root
        / "outputs"
        / "runtime"
        / "eie_state_boundary_evidence.json"
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            build_runtime_pass3_evidence(),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return target


if __name__ == "__main__":
    print(write_runtime_pass3_evidence())
