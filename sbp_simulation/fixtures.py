from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


RISK_TIERS = {"LOW", "MEDIUM", "TOP", "UNKNOWN"}
TRAVERSAL_MODES = {"SINGLE_PIPELINE", "SPLIT_VALIDATOR", "FULL_DUAL", "UNKNOWN"}
EXPECTED_OUTCOME_CATEGORIES = {
    "EXPECT_ALLOW",
    "EXPECT_DENY",
    "EXPECT_ESCALATE",
    "EXPECT_HALT",
    "EXPECT_REPLAY_MATCH",
    "EXPECT_PARITY_FAIL",
    "EXPECT_TAMPER_DETECTED",
    "UNKNOWN",
}


@dataclass(frozen=True)
class SimulationFixture:
    simulation_id: str
    simulation_version: str
    description: str
    risk_tier: str
    traversal_mode: str
    expected_outcome_category: str
    runtime_command: list[str] | None
    replay_command: list[str] | None
    required_artifacts: list[str] = field(default_factory=list)
    expected_observations: dict[str, Any] = field(default_factory=dict)
    forbidden_claims: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


SEED_FIXTURES: dict[str, SimulationFixture] = {
    "MAIN_RUNTIME_SMOKE": SimulationFixture(
        simulation_id="MAIN_RUNTIME_SMOKE",
        simulation_version="SIM-01",
        description="Capture the existing controlled runtime smoke command.",
        risk_tier="UNKNOWN",
        traversal_mode="SPLIT_VALIDATOR",
        expected_outcome_category="EXPECT_ALLOW",
        runtime_command=["python", "main.py"],
        replay_command=None,
        required_artifacts=[],
        expected_observations={"convergence_matched": True},
        forbidden_claims=["production activation", "university validation complete", "external publication"],
        notes=["Reports only the existing runtime command output."],
    ),
    "MAIN_REPLAY_SMOKE": SimulationFixture(
        simulation_id="MAIN_REPLAY_SMOKE",
        simulation_version="SIM-01",
        description="Capture the existing controlled replay smoke command.",
        risk_tier="UNKNOWN",
        traversal_mode="SPLIT_VALIDATOR",
        expected_outcome_category="EXPECT_REPLAY_MATCH",
        runtime_command=None,
        replay_command=["python", "main.py", "replay"],
        required_artifacts=[],
        expected_observations={"matched": True},
        forbidden_claims=["production activation", "university validation complete", "external publication"],
        notes=["Reports only the existing replay command output."],
    ),
}


REQUIRED_FIELDS = {
    "simulation_id",
    "simulation_version",
    "description",
    "risk_tier",
    "traversal_mode",
    "expected_outcome_category",
    "runtime_command",
    "replay_command",
    "required_artifacts",
    "expected_observations",
    "forbidden_claims",
    "notes",
}


def fixture_to_dict(fixture: SimulationFixture) -> dict[str, Any]:
    return asdict(fixture)


def validate_fixture(payload: dict[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    missing = sorted(REQUIRED_FIELDS - set(payload))
    failures.extend(f"missing_field:{field}" for field in missing)
    if payload.get("risk_tier") not in RISK_TIERS:
        failures.append("invalid_risk_tier")
    if payload.get("traversal_mode") not in TRAVERSAL_MODES:
        failures.append("invalid_traversal_mode")
    if payload.get("expected_outcome_category") not in EXPECTED_OUTCOME_CATEGORIES:
        failures.append("invalid_expected_outcome_category")
    if not payload.get("runtime_command") and not payload.get("replay_command"):
        failures.append("missing_command")
    for field in ("runtime_command", "replay_command", "required_artifacts", "forbidden_claims", "notes"):
        if field in payload and payload[field] is not None and not isinstance(payload[field], list):
            failures.append(f"invalid_type:{field}")
    if "expected_observations" in payload and not isinstance(payload["expected_observations"], dict):
        failures.append("invalid_type:expected_observations")
    return not failures, failures


def get_fixture(simulation_id: str) -> SimulationFixture | None:
    return SEED_FIXTURES.get(simulation_id)


def list_fixtures() -> list[dict[str, Any]]:
    return [fixture_to_dict(fixture) for fixture in SEED_FIXTURES.values()]
