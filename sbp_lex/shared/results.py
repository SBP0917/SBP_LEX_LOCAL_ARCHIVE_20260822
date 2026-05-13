from __future__ import annotations

GOVERNANCE_RESULTS = {"ALLOW", "DENY", "ESCALATE"}
PROCEDURAL_TRUTH_RESULTS = {"PASS", "FAIL", "ESCALATE"}
CLASSIFICATION_RESULTS = {"ALLOW", "DENY", "ESCALATE"}
LICENSING_RESULTS = {"ALLOW", "DENY", "ESCALATE"}
DOMAIN_RESULTS = {"pass", "fail", "escalate"}
AURION_RESULTS = {"pass", "fail", "escalate", "require_next_candidate"}
EXECUTION_RESULTS = {"EXECUTE", "HALT"}
DECISION_RESULTS = {"APPROVED", "DENY", "ESCALATE"}

RESULT_SETS = {
    "governance": GOVERNANCE_RESULTS,
    "procedural_truth": PROCEDURAL_TRUTH_RESULTS,
    "classification": CLASSIFICATION_RESULTS,
    "licensing": LICENSING_RESULTS,
    "domain": DOMAIN_RESULTS,
    "aurion": AURION_RESULTS,
    "execution": EXECUTION_RESULTS,
    "decision": DECISION_RESULTS,
}


def validate_result(stage: str, value: str) -> bool:
    allowed = RESULT_SETS.get(stage)
    if allowed is None:
        return False
    return value in allowed


def enforce_result(stage: str, value: str) -> str:
    if validate_result(stage, value):
        return value
    if stage == "execution":
        return "HALT"
    if stage == "decision":
        return "DENY"
    if stage in {"domain", "aurion"}:
        return "fail"
    if stage == "procedural_truth":
        return "FAIL"
    return "DENY"
