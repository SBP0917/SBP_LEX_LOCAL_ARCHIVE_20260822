from __future__ import annotations

from pathlib import Path

from sbp_oda.dependencies import inspect_dependency_and_pqc_provider
from sbp_oda.status import ODAStatus


QUERY_INDEX: dict[str, str] = {
    "what_is_oda": "ODA is the local Onsite Deployment Assistant. It inspects, diagnoses, answers bounded support questions, and packages local evidence without runtime authority.",
    "what_is_pvpl": "PVPL is the local/private proof publication scaffolding. In this repository it remains runtime-detached and does not publish externally.",
    "controlled_traversal_status": "Controlled traversal status must be checked through SBP-LEX runtime commands such as python main.py and python main.py replay; ODA does not decide traversal outcomes.",
    "where_are_proof_bundles": "Local ODA support bundles are written only to explicit operator-provided paths such as runtime_artifacts/oda_02/support_bundle.json.",
    "what_tests_should_reviewer_run": "Reviewers should run compileall, focused ODA tests, focused PQC provider tests, focused PVPL tests, full pytest, ODA CLI checks, python main.py, and python main.py replay.",
    "why_did_runtime_deny_or_halt": "Inspect the SBP-LEX runtime output, audit/replay evidence, execution gate failures, and token failures. ODA can package evidence but cannot reinterpret or override runtime decisions.",
    "what_is_safe_to_change": "Support-only documentation, reports, and explicit ODA output paths may be changed inside approved task scope. Runtime authority files require separate owner-controlled implementation work.",
    "what_requires_owner_approval": "Support bundle export, maintenance work-package planning, config restoration plans, and any sensitive support action require owner approval or review before application.",
    "what_is_blocked_by_canonical_boundary": "ODA blocks runtime governance changes, pipeline-order changes, execution-gate mutation, token/audit/hash-chain authority mutation, unrestricted remote shell, and runtime decision issuance.",
    "how_to_create_support_bundle": "Run: python -m sbp_oda.cli --support-bundle --runtime-root . --out runtime_artifacts/oda_02/support_bundle.json",
}


def answer_query(query_id: str, runtime_root: str | Path = ".") -> dict[str, object]:
    key = query_id.strip().lower()
    if key == "pqc_provider_status":
        dependency = inspect_dependency_and_pqc_provider(runtime_root)
        return {
            "status": ODAStatus.HARNESS_OK.value if dependency["provider_status"] == "PQC_PROVIDER_AVAILABLE" else ODAStatus.HARNESS_WARNING.value,
            "query_id": key,
            "answer": "PQC provider status is reported from local dependency inspection only; no certification is claimed.",
            "dependency_status": dependency,
            "runtime_authority": "NONE",
        }
    if key not in QUERY_INDEX:
        return {
            "status": ODAStatus.HARNESS_WARNING.value,
            "query_id": key,
            "answer": "unsupported by deterministic ODA query map",
            "runtime_authority": "NONE",
        }
    return {
        "status": ODAStatus.HARNESS_OK.value,
        "query_id": key,
        "answer": QUERY_INDEX[key],
        "runtime_authority": "NONE",
    }


def deterministic_query_index() -> dict[str, str]:
    return {**QUERY_INDEX, "pqc_provider_status": "Reports local cryptography.mldsa provider availability without certification claims."}
