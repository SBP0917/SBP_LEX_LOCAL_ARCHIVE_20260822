from __future__ import annotations

import json
import sys

from sbp_lex.api.server import run_server
from sbp_lex.runtime.canonical_runtime import CANONICAL_RUNTIME


def sample_request() -> dict:
    return {
        "action": "test_action",
        "payload": {
            "classification": {
                "ap_acf_class": "CLASS_4B",
                "autonomy_level": 50,
                "autonomy_ceiling": 75,
                "operational_scope": "controlled_test",
                "public_exposure": "controlled",
            },
            "licence_state": "VALID",
        },
        "resolved_authority": "test_authority",
        "jurisdiction": "AU-PACIFIC",
        "context": {
            "evidence": [
                {"source": "test_source_a", "content": "evidence_a"},
                {"source": "test_source_b", "content": "evidence_b"},
                {"source": "test_source_c", "content": "evidence_c"},
            ],
            "financial_amount": 5000,
            "operational_scope": "controlled_test",
            "public_exposure": "controlled",
            "environment": "controlled_test",
            "human_proximity": "low",
            "operational_containment": "bounded",
            "emergency_stop_available": True,
            "licence_state": "VALID",
        },
        "safety_profile": {
            "human_safety": 2,
            "irreversibility": 1,
            "cascading_impact": 1,
            "financial_operational": 1,
        },
    }


def main(request: dict | None = None, pre_context_signals: dict | None = None) -> dict:
    return CANONICAL_RUNTIME.traverse(request or sample_request(), request_id="local-sample", pre_context_signals=pre_context_signals)["state"]


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "server":
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
        run_server(port=port)
    elif len(sys.argv) > 1 and sys.argv[1] == "status":
        print(json.dumps(CANONICAL_RUNTIME.status(), indent=2, default=str))
    elif len(sys.argv) > 1 and sys.argv[1] == "replay":
        print(json.dumps(CANONICAL_RUNTIME.replay(sample_request(), replay_count=2), indent=2, default=str))
    else:
        state = main(sample_request())
        summary = {
            "decision": state.get("decision"),
            "execution_result": state.get("execution_result"),
            "pipeline_mode": state.get("pipeline_mode"),
            "audit_hash": state.get("audit_hash"),
            "convergence_matched": state.get("pipeline_convergence", {}).get("matched"),
            "token_failures": state.get("token_verification_failures", []),
        }
        print(json.dumps(summary, indent=2, default=str))
