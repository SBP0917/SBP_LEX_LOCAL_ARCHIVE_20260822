from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from sbp_simulation.command_policy import command_allowed
from sbp_simulation.runner import _display_path, _write_json
from sbp_simulation.status import SCENARIO_STATUSES


SCENARIO_GROUPS = {"LOW_SINGLE_PIPELINE", "MEDIUM_SPLIT_VALIDATOR", "TOP_FULL_DUAL"}
SCENARIO_RISK_TIERS = {"LOW", "MEDIUM", "TOP"}
SCENARIO_TRAVERSAL_MODES = {"SINGLE_PIPELINE", "SPLIT_VALIDATOR", "FULL_DUAL"}
SCENARIO_EXPECTED_OUTCOMES = {
    "EXPECT_ALLOW",
    "EXPECT_DENY",
    "EXPECT_ESCALATE",
    "EXPECT_HALT",
    "EXPECT_REPLAY_MATCH",
    "EXPECT_PARITY_FAIL",
    "EXPECT_TAMPER_DETECTED",
}
ADAPTIVE_TRAVERSAL_MAPPING = {
    "LOW": "SINGLE_PIPELINE",
    "MEDIUM": "SPLIT_VALIDATOR",
    "TOP": "FULL_DUAL",
}
SCENARIO_BOUNDARY_STATEMENT = (
    "SIM-02 is local/private controlled validation only. It is not production "
    "activation, external actuation, runtime authority, a university validation "
    "result, or public publication."
)


@dataclass(frozen=True)
class ScenarioFixture:
    simulation_id: str
    simulation_version: str
    scenario_group: str
    risk_tier: str
    traversal_mode: str
    expected_outcome_category: str
    scenario_intent: str
    input_profile: dict[str, Any]
    required_stage_expectations: list[str]
    required_token_expectations: list[str]
    required_audit_expectations: list[str]
    required_replay_expectations: list[str]
    required_pvpl_expectations: list[str]
    required_oda_explanation_expectations: list[str]
    runtime_command: list[str] | None
    replay_command: list[str] | None
    phase19a_required: bool
    runtime_backed: bool
    reviewer_notes: list[str]
    forbidden_claims: list[str]


SCENARIO_REQUIRED_FIELDS = {
    "simulation_id",
    "simulation_version",
    "scenario_group",
    "risk_tier",
    "traversal_mode",
    "expected_outcome_category",
    "scenario_intent",
    "input_profile",
    "required_stage_expectations",
    "required_token_expectations",
    "required_audit_expectations",
    "required_replay_expectations",
    "required_pvpl_expectations",
    "required_oda_explanation_expectations",
    "runtime_command",
    "replay_command",
    "phase19a_required",
    "runtime_backed",
    "reviewer_notes",
    "forbidden_claims",
}


def _scenario(
    simulation_id: str,
    group: str,
    risk: str,
    traversal: str,
    expected: str,
    intent: str,
    *,
    replay: bool = False,
) -> ScenarioFixture:
    return ScenarioFixture(
        simulation_id=simulation_id,
        simulation_version="SIM-02",
        scenario_group=group,
        risk_tier=risk,
        traversal_mode=traversal,
        expected_outcome_category=expected,
        scenario_intent=intent,
        input_profile={
            "fixture_kind": "controlled_scenario_definition",
            "risk_tier": risk,
            "phase": "pre_phase_19a",
        },
        required_stage_expectations=[
            f"{traversal} traversal stages must be exercised after Phase 19A activation.",
            "Scenario library validation must not be treated as runtime traversal proof.",
        ],
        required_token_expectations=[
            "Required token evidence must be present or explicitly fail closed during future runtime execution.",
        ],
        required_audit_expectations=[
            "Future runtime execution must emit replayable audit evidence for this scenario.",
        ],
        required_replay_expectations=[
            "Replay evidence must match deterministic comparison fields after runtime activation."
            if replay
            else "Replay handling must remain available for reviewer follow-up after runtime activation.",
        ],
        required_pvpl_expectations=[
            "Scenario fixture and result JSON paths must be available for local/private PVPL bundle inclusion.",
        ],
        required_oda_explanation_expectations=[
            "ODA-readable explanation must identify the scenario intent, expected outcome, and Phase 19A dependency.",
        ],
        runtime_command=None,
        replay_command=None,
        phase19a_required=True,
        runtime_backed=False,
        reviewer_notes=[
            "Definition-ready scenario for controlled future traversal activation.",
            "No full runtime traversal proof is claimed by SIM-02.",
        ],
        forbidden_claims=[
            "production activation",
            "full runtime proof",
            "university validation result",
            "public publication",
        ],
    )


SCENARIO_LIBRARY: dict[str, ScenarioFixture] = {
    "LOW_ALLOW_ROUTINE_STATUS_CHECK": _scenario(
        "LOW_ALLOW_ROUTINE_STATUS_CHECK",
        "LOW_SINGLE_PIPELINE",
        "LOW",
        "SINGLE_PIPELINE",
        "EXPECT_ALLOW",
        "Routine low-risk validation path.",
    ),
    "LOW_DENY_MISSING_REQUIRED_TOKEN": _scenario(
        "LOW_DENY_MISSING_REQUIRED_TOKEN",
        "LOW_SINGLE_PIPELINE",
        "LOW",
        "SINGLE_PIPELINE",
        "EXPECT_DENY",
        "Prove low-risk path still denies or blocks when required token evidence is absent.",
    ),
    "LOW_REPLAY_MATCH": _scenario(
        "LOW_REPLAY_MATCH",
        "LOW_SINGLE_PIPELINE",
        "LOW",
        "SINGLE_PIPELINE",
        "EXPECT_REPLAY_MATCH",
        "Prove low-risk replay determinism.",
        replay=True,
    ),
    "MEDIUM_ALLOW_SPLIT_VALIDATOR_CONFIG_REVIEW": _scenario(
        "MEDIUM_ALLOW_SPLIT_VALIDATOR_CONFIG_REVIEW",
        "MEDIUM_SPLIT_VALIDATOR",
        "MEDIUM",
        "SPLIT_VALIDATOR",
        "EXPECT_ALLOW",
        "Medium-risk split-validator scenario.",
    ),
    "MEDIUM_ESCALATE_CORROBORATION_SHORTFALL": _scenario(
        "MEDIUM_ESCALATE_CORROBORATION_SHORTFALL",
        "MEDIUM_SPLIT_VALIDATOR",
        "MEDIUM",
        "SPLIT_VALIDATOR",
        "EXPECT_ESCALATE",
        "Procedural Truth corroboration threshold shortfall causes escalation.",
    ),
    "MEDIUM_DENY_LICENSE_SCOPE_MISMATCH": _scenario(
        "MEDIUM_DENY_LICENSE_SCOPE_MISMATCH",
        "MEDIUM_SPLIT_VALIDATOR",
        "MEDIUM",
        "SPLIT_VALIDATOR",
        "EXPECT_DENY",
        "Licence or scope mismatch blocks traversal.",
    ),
    "MEDIUM_REPLAY_MATCH": _scenario(
        "MEDIUM_REPLAY_MATCH",
        "MEDIUM_SPLIT_VALIDATOR",
        "MEDIUM",
        "SPLIT_VALIDATOR",
        "EXPECT_REPLAY_MATCH",
        "Replay determinism under split-validator scenario.",
        replay=True,
    ),
    "TOP_ALLOW_FULL_DUAL_FULLY_VALIDATED": _scenario(
        "TOP_ALLOW_FULL_DUAL_FULLY_VALIDATED",
        "TOP_FULL_DUAL",
        "TOP",
        "FULL_DUAL",
        "EXPECT_ALLOW",
        "High-risk full dual traversal where all required validations pass.",
    ),
    "TOP_DENY_GOVERNANCE_AUTHORITY_FAIL": _scenario(
        "TOP_DENY_GOVERNANCE_AUTHORITY_FAIL",
        "TOP_FULL_DUAL",
        "TOP",
        "FULL_DUAL",
        "EXPECT_DENY",
        "Governance or authority failure blocks full dual traversal.",
    ),
    "TOP_ESCALATE_AUTHORITY_CONFLICT": _scenario(
        "TOP_ESCALATE_AUTHORITY_CONFLICT",
        "TOP_FULL_DUAL",
        "TOP",
        "FULL_DUAL",
        "EXPECT_ESCALATE",
        "Conflicting authority or unresolved legitimacy produces escalation.",
    ),
    "TOP_HALT_TOKEN_SIGNATURE_TAMPER": _scenario(
        "TOP_HALT_TOKEN_SIGNATURE_TAMPER",
        "TOP_FULL_DUAL",
        "TOP",
        "FULL_DUAL",
        "EXPECT_HALT",
        "Token signature or hash-chain tamper produces halt or block.",
    ),
    "TOP_PARITY_MISMATCH_BLOCK": _scenario(
        "TOP_PARITY_MISMATCH_BLOCK",
        "TOP_FULL_DUAL",
        "TOP",
        "FULL_DUAL",
        "EXPECT_PARITY_FAIL",
        "Exact deterministic parity failure blocks execution.",
    ),
    "TOP_REPLAY_MATCH": _scenario(
        "TOP_REPLAY_MATCH",
        "TOP_FULL_DUAL",
        "TOP",
        "FULL_DUAL",
        "EXPECT_REPLAY_MATCH",
        "Replay determinism for full dual traversal.",
        replay=True,
    ),
}


def scenario_to_dict(scenario: ScenarioFixture) -> dict[str, Any]:
    return asdict(scenario)


def validate_scenario(payload: dict[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    missing = sorted(SCENARIO_REQUIRED_FIELDS - set(payload))
    failures.extend(f"missing_field:{field}" for field in missing)
    if payload.get("scenario_group") not in SCENARIO_GROUPS:
        failures.append("invalid_scenario_group")
    if payload.get("risk_tier") not in SCENARIO_RISK_TIERS:
        failures.append("invalid_risk_tier")
    if payload.get("traversal_mode") not in SCENARIO_TRAVERSAL_MODES:
        failures.append("invalid_traversal_mode")
    if payload.get("expected_outcome_category") not in SCENARIO_EXPECTED_OUTCOMES:
        failures.append("invalid_expected_outcome_category")
    expected_traversal = ADAPTIVE_TRAVERSAL_MAPPING.get(payload.get("risk_tier"))
    if expected_traversal and payload.get("traversal_mode") != expected_traversal:
        failures.append("invalid_adaptive_traversal_mapping")
    expected_group = {
        "LOW": "LOW_SINGLE_PIPELINE",
        "MEDIUM": "MEDIUM_SPLIT_VALIDATOR",
        "TOP": "TOP_FULL_DUAL",
    }.get(payload.get("risk_tier"))
    if expected_group and payload.get("scenario_group") != expected_group:
        failures.append("invalid_scenario_group_mapping")
    if not isinstance(payload.get("phase19a_required"), bool):
        failures.append("invalid_type:phase19a_required")
    if not isinstance(payload.get("runtime_backed"), bool):
        failures.append("invalid_type:runtime_backed")
    for field in (
        "required_stage_expectations",
        "required_token_expectations",
        "required_audit_expectations",
        "required_replay_expectations",
        "required_pvpl_expectations",
        "required_oda_explanation_expectations",
        "reviewer_notes",
        "forbidden_claims",
    ):
        if field in payload and not isinstance(payload[field], list):
            failures.append(f"invalid_type:{field}")
    if "input_profile" in payload and not isinstance(payload["input_profile"], dict):
        failures.append("invalid_type:input_profile")
    for command_field in ("runtime_command", "replay_command"):
        command = payload.get(command_field)
        if command is not None:
            allowed, reason = command_allowed(command)
            if not allowed:
                failures.append(f"invalid_command:{command_field}:{reason}")
    return not failures, failures


def get_scenario(scenario_id: str) -> ScenarioFixture | None:
    return SCENARIO_LIBRARY.get(scenario_id)


def list_scenarios() -> list[dict[str, Any]]:
    return [scenario_to_dict(scenario) for scenario in SCENARIO_LIBRARY.values()]


def scenario_index() -> dict[str, Any]:
    scenarios = list_scenarios()
    by_risk: dict[str, int] = {}
    by_traversal: dict[str, int] = {}
    by_outcome: dict[str, int] = {}
    invalid_count = 0
    for scenario in scenarios:
        by_risk[scenario["risk_tier"]] = by_risk.get(scenario["risk_tier"], 0) + 1
        by_traversal[scenario["traversal_mode"]] = by_traversal.get(scenario["traversal_mode"], 0) + 1
        by_outcome[scenario["expected_outcome_category"]] = by_outcome.get(scenario["expected_outcome_category"], 0) + 1
        if not validate_scenario(scenario)[0]:
            invalid_count += 1
    return {
        "total_scenarios": len(scenarios),
        "scenarios_by_risk_tier": by_risk,
        "scenarios_by_traversal_mode": by_traversal,
        "scenarios_by_expected_outcome": by_outcome,
        "runtime_backed_count": sum(1 for item in scenarios if item["runtime_backed"]),
        "phase19a_required_count": sum(1 for item in scenarios if item["phase19a_required"]),
        "invalid_count": invalid_count,
        "scenario_ids": [scenario["simulation_id"] for scenario in scenarios],
    }


def validate_scenario_library() -> dict[str, Any]:
    results = []
    for scenario in SCENARIO_LIBRARY.values():
        payload = scenario_to_dict(scenario)
        valid, failures = validate_scenario(payload)
        results.append({"scenario_id": scenario.simulation_id, "valid": valid, "failures": failures})
    valid = all(item["valid"] for item in results)
    return {
        "scenario_library_status": "SIM_OK" if valid else "SIM_FAILED",
        "index": scenario_index(),
        "results": results,
    }


def _scenario_status(scenario: ScenarioFixture, valid: bool) -> tuple[str, str]:
    if not valid:
        return "SCENARIO_INVALID", "INVALID"
    if scenario.runtime_backed:
        return "SCENARIO_RUNTIME_BACKED", "RUNTIME_CAPTURED"
    if scenario.phase19a_required:
        return "SCENARIO_READY_FOR_PHASE_19A", "NOT_EXECUTED_PHASE19A_REQUIRED"
    return "SCENARIO_INCOMPLETE_RUNTIME_PATH", "BLOCKED"


def _forbidden_claims_absent(payload: dict[str, Any]) -> bool:
    checked_payload = {
        "scenario_intent": payload.get("scenario_intent"),
        "input_profile": payload.get("input_profile"),
        "required_stage_expectations": payload.get("required_stage_expectations"),
        "required_token_expectations": payload.get("required_token_expectations"),
        "required_audit_expectations": payload.get("required_audit_expectations"),
        "required_replay_expectations": payload.get("required_replay_expectations"),
        "required_pvpl_expectations": payload.get("required_pvpl_expectations"),
        "required_oda_explanation_expectations": payload.get("required_oda_explanation_expectations"),
    }
    text = json.dumps(checked_payload, sort_keys=True).lower()
    return not any(claim.lower() in text for claim in payload.get("forbidden_claims", []))


def _scenario_summary(result: dict[str, Any], fixture: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"# SIM-02 Reviewer Scenario Summary: {result['scenario_id']}",
            "",
            f"- Risk tier: {result['risk_tier']}",
            f"- Traversal mode: {result['traversal_mode']}",
            f"- Expected outcome: {result['expected_outcome_category']}",
            f"- Runtime-backed: {result['runtime_backed']}",
            f"- Phase 19A required: {result['phase19a_required']}",
            f"- Scenario status: {result['scenario_status']}",
            f"- Runtime execution status: {result['runtime_execution_status']}",
            "",
            "## Designed To Prove",
            "",
            fixture["scenario_intent"],
            "",
            "## Evidence Exists Now",
            "",
            "SIM-02 structural fixture validation and local scenario evidence files exist now. No runtime traversal proof is claimed.",
            "",
            "## Evidence After Phase 19A",
            "",
            "After controlled traversal activation, runtime command captures, replay outputs, audit evidence, token evidence, and PVPL bundle records should be attached to the scenario.",
            "",
            "## PVPL Instruction",
            "",
            "Include the scenario fixture, validation, result, and reviewer summary paths in a local/private proof bundle only.",
            "",
            "## ODA Explanation Seed",
            "",
            result["oda_explanation_seed"],
            "",
            "## Limitations",
            "",
            SCENARIO_BOUNDARY_STATEMENT,
            "",
        ]
    )


def run_scenario_library(
    out_root: str | Path = "runtime_artifacts/sim_02/",
    runtime_root: str | Path = ".",
) -> dict[str, Any]:
    root = Path(runtime_root).resolve()
    base = Path(out_root)
    if not base.is_absolute():
        base = root / base
    results: list[dict[str, Any]] = []
    for scenario in SCENARIO_LIBRARY.values():
        fixture_payload = scenario_to_dict(scenario)
        valid, failures = validate_scenario(fixture_payload)
        scenario_status, runtime_status = _scenario_status(scenario, valid)
        if scenario_status not in SCENARIO_STATUSES:
            scenario_status = "SCENARIO_INVALID"
            runtime_status = "INVALID"
        scenario_dir = base / scenario.simulation_id
        scenario_dir.mkdir(parents=True, exist_ok=True)
        fixture_path = scenario_dir / "scenario_fixture.json"
        validation_path = scenario_dir / "scenario_validation.json"
        result_path = scenario_dir / "scenario_result.json"
        summary_path = scenario_dir / "reviewer_scenario_summary.md"
        artifacts = [
            _display_path(fixture_path, root),
            _display_path(validation_path, root),
            _display_path(result_path, root),
            _display_path(summary_path, root),
        ]
        result = {
            "scenario_id": scenario.simulation_id,
            "fixture_valid": valid,
            "validation_failures": failures,
            "risk_tier": scenario.risk_tier,
            "traversal_mode": scenario.traversal_mode,
            "expected_outcome_category": scenario.expected_outcome_category,
            "runtime_backed": scenario.runtime_backed,
            "phase19a_required": scenario.phase19a_required,
            "scenario_status": scenario_status,
            "runtime_execution_status": runtime_status,
            "pvpl_ready_paths": artifacts,
            "oda_explanation_seed": (
                f"{scenario.simulation_id} is a {scenario.risk_tier} {scenario.traversal_mode} "
                f"definition-ready scenario expecting {scenario.expected_outcome_category}; "
                "Phase 19A runtime evidence is still required."
            ),
            "forbidden_claims_absent": _forbidden_claims_absent(fixture_payload),
            "boundary_statement": SCENARIO_BOUNDARY_STATEMENT,
        }
        validation = {"scenario_id": scenario.simulation_id, "valid": valid, "failures": failures}
        _write_json(fixture_path, fixture_payload)
        _write_json(validation_path, validation)
        _write_json(result_path, result)
        summary_path.write_text(_scenario_summary(result, fixture_payload), encoding="utf-8")
        results.append(result)
    status = "SIM_OK" if all(result["fixture_valid"] for result in results) else "SIM_FAILED"
    return {"simulation_status": status, "index": scenario_index(), "results": results}
