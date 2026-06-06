from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.audit.audit_finalisation import build_audit_record, finalise_audit
from sbp_lex.shared.hash_chain import append_hash_entry


def run_audit(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    audit_state = {
        "request_fingerprint": working_state.get("request_fingerprint"),
        "state_hash": working_state.get("state_hash"),
        "decision": working_state.get("decision"),
        "execution_verified": working_state.get("execution_verified", False),
        "convergence_hash": working_state.get("convergence_hash"),
        "audit_chain": working_state.get("hash_chain", []),
        "pipeline_mode": working_state.get("pipeline_mode"),
    }
    audit_record = build_audit_record(audit_state)
    audit_finalisation = finalise_audit(audit_record) if audit_record.get("valid") else {"audit_complete": False, "reason": audit_record.get("reason")}
    working_state["audit_record"] = audit_record
    working_state["audit_hash"] = audit_record.get("audit_hash", "")
    working_state["audit_finalisation"] = audit_finalisation
    working_state.setdefault("audit_trace", []).append({"stage": "audit", "audit_hash": working_state["audit_hash"], "audit_complete": audit_finalisation.get("audit_complete", False)})
    return append_hash_entry(working_state, stage="audit", payload={"audit_hash": working_state["audit_hash"], "audit_complete": audit_finalisation.get("audit_complete", False)})
