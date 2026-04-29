from __future__ import annotations
 import importlib
 from copy import deepcopy
 from typing import Any, Callable, Dict, Mapping
 from sbp_lex.authority_first.anchor_validation_engine import anchor_validation_engine
 from sbp_lex.authority_first.attestation_consensus_engine import attestation_consensus_engine
 from sbp_lex.authority_first.attestation_engine import attestation_engine
 from sbp_lex.authority_first.truth_anchor_engine import truth_anchor_engine
 from sbp_lex.authority_first.truth_continuity_engine import truth_continuity_engine
 from sbp_lex.authority_first.truth_expiry_engine import truth_expiry_engine
 from sbp_lex.authority_first.truth_revocation_engine import truth_revocation_engine
 from sbp_lex.classification.engine import ClassificationEngine
 from sbp_lex.collective.context_interface import attach_collective_signals
 from sbp_lex.config.pipeline_config import GOVERNANCE_RESULTS, HASH_CHAIN_STAGE_NAMES
 from sbp_lex.governance.engine import GovernanceEngine
 from sbp_lex.governance.procedural_truth_engine import evaluate_procedural_truth
 from sbp_lex.licensing.engine import LicensingEngine
 from sbp_lex.security.pqc import generate_digest
 from sbp_lex.
