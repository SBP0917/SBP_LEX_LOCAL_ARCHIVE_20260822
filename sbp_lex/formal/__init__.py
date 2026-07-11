"""Detached, non-authoritative Desktop V1 architectural assurance."""

from sbp_lex.formal.model import (
    ARCHITECTURAL_STATES,
    CANONICAL_CONTROL_STATES,
    PIPELINE_MODES,
    FormalState,
    LineageNode,
    TransitionRecord,
)
from sbp_lex.formal.verifier import (
    FormalArchitectureVerifier,
    FormalViolation,
    FormalVerificationResult,
    formalize_runtime_state,
    replay_formal_verification,
)

__all__ = [
    "ARCHITECTURAL_STATES",
    "CANONICAL_CONTROL_STATES",
    "PIPELINE_MODES",
    "FormalArchitectureVerifier",
    "FormalState",
    "FormalViolation",
    "FormalVerificationResult",
    "LineageNode",
    "TransitionRecord",
    "formalize_runtime_state",
    "replay_formal_verification",
]
