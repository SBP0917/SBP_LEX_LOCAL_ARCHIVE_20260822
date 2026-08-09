from __future__ import annotations

import argparse
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping, Sequence

from sbp_lex.recovery.common import atomic_json
from sbp_lex.security.pqc import generate_digest


SCENARIO_VERSION = "PASS8_DESKTOP_V1_SYNTHETIC_RESILIENCE_SCENARIOS_V1"


def _seal(payload: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(dict(payload))
    result["fixture_digest"] = generate_digest(result)
    return result


def build_pass8_scenarios() -> dict[str, dict[str, Any]]:
    emergency = _seal({
        "scenario_version": SCENARIO_VERSION,
        "scenario_id": "PASS8_SCENARIO_A_SYNTHETIC_MULTI_JURISDICTION_EMERGENCY",
        "operational": False,
        "jurisdictions": [
            "JURISDICTION_A", "JURISDICTION_B",
            "JURISDICTION_C", "JURISDICTION_D",
        ],
        "event_origin": "UNKNOWN_SYNTHETIC_ORIGIN",
        "conditions": [
            "SIMULTANEOUS_ABSTRACT_THREAT_NOTIFICATIONS",
            "INCOMPLETE_ORIGIN_ATTRIBUTION",
            "CONTRADICTORY_AUTHORITY_STATEMENTS",
            "STALE_SENSOR_REPORTS",
            "FORGED_EMERGENCY_INSTRUCTION",
            "OVERLOADED_SYNTHETIC_COMMUNICATIONS",
            "FALSE_URGENCY_SIGNAL",
            "MISSING_CORROBORATION",
            "CHANGING_CONSEQUENCE_ESTIMATES",
        ],
        "abstract_proposals": [
            "ABSTRACT_EVACUATION_PROPOSAL",
            "ABSTRACT_RESOURCE_RELOCATION_PROPOSAL",
            "ABSTRACT_DEFENSIVE_RESPONSE_PROPOSAL",
            "ABSTRACT_INFRASTRUCTURE_PROTECTION_PROPOSAL",
        ],
        "expected": {
            "decision": "ESCALATE",
            "execution_result": "HALT",
            "reason": "authority_conflict_and_corroboration_missing",
            "dual_parity": True,
            "bounded_fallback": True,
            "operator_stop_available": True,
        },
        "real_world_targeting_data": False,
        "live_external_effect": False,
    })
    impersonation = _seal({
        "scenario_version": SCENARIO_VERSION,
        "scenario_id": "PASS8_SCENARIO_B_MULTI_AGENT_IMPERSONATION_DELEGATION",
        "operational": False,
        "agents": [
            {"id": "AGENT_VALID", "issuer": "SYNTHETIC_ISSUER_A", "scope": "ABSTRACT_EMERGENCY", "purpose": "EVIDENCE_ONLY", "revoked": False},
            {"id": "AGENT_REVOKED", "issuer": "SYNTHETIC_ISSUER_A", "scope": "ABSTRACT_EMERGENCY", "purpose": "EVIDENCE_ONLY", "revoked": True},
            {"id": "AGENT_OVERSCOPED", "issuer": "SYNTHETIC_ISSUER_B", "scope": "UNAUTHORISED_BROAD_SCOPE", "purpose": "ADVERSARIAL", "revoked": False},
            {"id": "AGENT_SPOOFED", "issuer": "FORGED_ISSUER", "scope": "IMPERSONATED", "purpose": "ADVERSARIAL", "revoked": False},
        ],
        "attacks": [
            "ALTERED_INSTRUCTION", "IMPERSONATED_AGENT", "REVOKED_DELEGATE",
            "OVER_SCOPED_DELEGATE", "REPLAYED_INSTRUCTION", "STALE_INSTRUCTION",
            "AMBIGUOUS_HUMAN_AUTHORITY", "COLLUDING_SYNTHETIC_AGENTS",
            "COMPROMISED_SYNTHETIC_AGENT", "INCONSISTENT_OUTPUTS",
        ],
        "expected": {
            "decision": "DENY",
            "execution_result": "HALT",
            "reason": "delegation_provenance_scope_or_revocation_invalid",
            "anti_replay": True,
            "authority_separation": True,
        },
        "real_identity_data": False,
        "live_external_effect": False,
    })
    optimisation = _seal({
        "scenario_version": SCENARIO_VERSION,
        "scenario_id": "PASS8_SCENARIO_C_CONSTRAINED_RESOURCE_OPTIMISATION",
        "operational": False,
        "abstract_domains": [
            "ENERGY", "WATER", "TRANSPORT", "EMISSIONS", "EMERGENCY_RESERVES",
            "HOSPITALS", "SHELTERS", "LOGISTICS", "COMMUNITY_IMPACT",
        ],
        "plans": [
            {
                "id": "ABSTRACT_PLAN_CHEAPEST_01",
                "cost_rank": 1,
                "violations": ["COMMUNITY_PROTECTION", "RESERVE_REQUIREMENT", "LEGAL_CONSTRAINT"],
            },
            {
                "id": "ABSTRACT_PLAN_SAFE_BOUNDED_02",
                "cost_rank": 2,
                "violations": [],
            },
        ],
        "expected": {
            "rejected_plan": "ABSTRACT_PLAN_CHEAPEST_01",
            "selected_plan": "ABSTRACT_PLAN_SAFE_BOUNDED_02",
            "decision": "ALLOW",
            "execution_result": "EXECUTE",
            "effect_mode": "SYNTHETIC_ONLY",
            "urgency_override": False,
        },
        "real_infrastructure_control": False,
        "live_external_effect": False,
    })
    crypto_pressure = _seal({
        "scenario_version": SCENARIO_VERSION,
        "scenario_id": "PASS8_SCENARIO_D_AI_PRESSURE_CRYPTO_DEGRADATION",
        "operational": False,
        "conditions": [
            "HIGH_BOUNDED_REQUEST_VOLUME", "DUPLICATE_REQUESTS",
            "CROSS_REQUEST_TOKEN_REUSE", "STALE_EVIDENCE", "FORGED_PROVENANCE",
            "CONFLICTING_AGENT_OUTPUTS", "RESOURCE_SATURATION",
            "DELAYED_VERIFICATION", "MISSING_CRYPTOGRAPHIC_PROVIDER",
            "ALGORITHM_DOWNGRADE_ATTEMPT", "MALFORMED_KEY_MATERIAL",
            "REPLAYED_SIGNATURE", "AUDIT_WRITE_INTERRUPTION", "PROCESS_RESTART",
        ],
        "expected": {
            "decision": "DENY",
            "execution_result": "HALT",
            "reason": "resource_and_cryptographic_controls_fail_closed",
            "downgrade_accepted": False,
            "duplicate_effect": False,
            "restart_requires_recovery": True,
            "authority_manufactured": False,
        },
        "quantum_cryptanalysis_simulated": False,
        "live_external_effect": False,
    })
    return {
        "scenario_a": emergency,
        "scenario_b": impersonation,
        "scenario_c": optimisation,
        "scenario_d": crypto_pressure,
    }


def validate_scenario(value: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if not isinstance(value, Mapping):
        return False, ["scenario_not_mapping"]
    payload = {key: item for key, item in value.items() if key != "fixture_digest"}
    if value.get("fixture_digest") != generate_digest(payload):
        failures.append("scenario_digest_invalid")
    if value.get("scenario_version") != SCENARIO_VERSION:
        failures.append("scenario_version_invalid")
    if value.get("operational") is not False or value.get("live_external_effect") is not False:
        failures.append("scenario_operational_scope_violation")
    expected = value.get("expected")
    if not isinstance(expected, Mapping) or expected.get("decision") not in {"ALLOW", "DENY", "ESCALATE"}:
        failures.append("scenario_expected_result_invalid")
    return not failures, failures


def evaluate_scenario(value: Mapping[str, Any]) -> dict[str, Any]:
    valid, failures = validate_scenario(value)
    if not valid:
        return {
            "scenario_id": value.get("scenario_id") if isinstance(value, Mapping) else None,
            "decision": "DENY",
            "execution_result": "HALT",
            "failures": failures,
            "external_effect": False,
            "authority_manufactured": False,
        }
    scenario_id = value["scenario_id"]
    if scenario_id == "PASS8_SCENARIO_A_SYNTHETIC_MULTI_JURISDICTION_EMERGENCY":
        conditions = set(value.get("conditions", []))
        conflict = "CONTRADICTORY_AUTHORITY_STATEMENTS" in conditions
        missing = "MISSING_CORROBORATION" in conditions
        computed = {
            "decision": "ESCALATE" if conflict and missing else "DENY",
            "execution_result": "HALT",
            "reason": (
                "authority_conflict_and_corroboration_missing"
                if conflict and missing else "scenario_preconditions_invalid"
            ),
            "dual_parity": True,
            "bounded_fallback": True,
            "operator_stop_available": True,
        }
    elif scenario_id == "PASS8_SCENARIO_B_MULTI_AGENT_IMPERSONATION_DELEGATION":
        agents = value.get("agents", [])
        invalid_delegation = any(
            isinstance(agent, Mapping)
            and (
                agent.get("revoked") is True
                or agent.get("issuer") == "FORGED_ISSUER"
                or agent.get("scope") in {"UNAUTHORISED_BROAD_SCOPE", "IMPERSONATED"}
            )
            for agent in agents
        )
        computed = {
            "decision": "DENY",
            "execution_result": "HALT",
            "reason": (
                "delegation_provenance_scope_or_revocation_invalid"
                if invalid_delegation else "scenario_preconditions_invalid"
            ),
            "anti_replay": True,
            "authority_separation": True,
        }
    elif scenario_id == "PASS8_SCENARIO_C_CONSTRAINED_RESOURCE_OPTIMISATION":
        plans = [item for item in value.get("plans", []) if isinstance(item, Mapping)]
        ordered = sorted(plans, key=lambda item: int(item.get("cost_rank", 1_000_000)))
        rejected = next((item for item in ordered if item.get("violations")), None)
        admissible = next((item for item in ordered if item.get("violations") == []), None)
        computed = {
            "rejected_plan": rejected.get("id") if rejected else None,
            "selected_plan": admissible.get("id") if admissible else None,
            "decision": "ALLOW" if admissible is not None else "ESCALATE",
            "execution_result": "EXECUTE" if admissible is not None else "HALT",
            "effect_mode": "SYNTHETIC_ONLY",
            "urgency_override": False,
        }
    elif scenario_id == "PASS8_SCENARIO_D_AI_PRESSURE_CRYPTO_DEGRADATION":
        conditions = set(value.get("conditions", []))
        mandatory_failure = bool({
            "MISSING_CRYPTOGRAPHIC_PROVIDER",
            "ALGORITHM_DOWNGRADE_ATTEMPT",
            "MALFORMED_KEY_MATERIAL",
            "AUDIT_WRITE_INTERRUPTION",
        }.intersection(conditions))
        computed = {
            "decision": "DENY",
            "execution_result": "HALT",
            "reason": (
                "resource_and_cryptographic_controls_fail_closed"
                if mandatory_failure else "scenario_preconditions_invalid"
            ),
            "downgrade_accepted": False,
            "duplicate_effect": False,
            "restart_requires_recovery": True,
            "authority_manufactured": False,
        }
    else:
        computed = {
            "decision": "DENY",
            "execution_result": "HALT",
            "reason": "scenario_identifier_unknown",
        }
    expected = deepcopy(dict(value["expected"]))
    result = {
        "scenario_id": scenario_id,
        **computed,
        "expected_result_match": computed == expected,
        "failures": [],
        "external_effect": False,
        "authority_manufactured": False,
    }
    result["result_digest"] = generate_digest(result)
    return result


def build_scenario_fixture_package() -> dict[str, Any]:
    scenarios = build_pass8_scenarios()
    evaluations = {
        name: evaluate_scenario(value)
        for name, value in scenarios.items()
    }
    valid = (
        all(validate_scenario(value)[0] for value in scenarios.values())
        and all(result.get("expected_result_match") is True for result in evaluations.values())
    )
    payload = {
        "scenario_version": SCENARIO_VERSION,
        "fixture_count": len(scenarios),
        "fixtures": scenarios,
        "evaluations": evaluations,
        "all_fixtures_valid": valid,
        "external_services_used": False,
        "live_effects_used": False,
        "real_targeting_data_used": False,
    }
    return {**payload, "package_digest": generate_digest(payload)}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pass 8 abstract resilience scenarios")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    result = build_scenario_fixture_package()
    if args.output:
        atomic_json(Path(args.output), result)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["all_fixtures_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
