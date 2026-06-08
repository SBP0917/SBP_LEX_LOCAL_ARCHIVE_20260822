from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.security.pqc import generate_digest, sign_payload


def prepare_dtn_context(request: Mapping[str, Any], skg_context: Mapping[str, Any]) -> Dict[str, Any]:
    context = deepcopy(dict(request.get("context", {}))) if isinstance(request.get("context", {}), Mapping) else {}
    safety_profile = deepcopy(dict(request.get("safety_profile", {}))) if isinstance(request.get("safety_profile", {}), Mapping) else {}
    dependency_signal = {
        "dependencies": context.get("dependencies", []),
        "dependency_count": len(context.get("dependencies", [])) if isinstance(context.get("dependencies", []), list) else 0,
        "critical_dependency_present": bool(context.get("critical_dependency_present", False)),
    }
    operational_context_signal = {
        "environment": context.get("environment", "UNDECLARED"),
        "human_proximity": context.get("human_proximity", "UNDECLARED"),
        "geographic_isolation": context.get("geographic_isolation", "UNDECLARED"),
        "operational_containment": context.get("operational_containment", "UNDECLARED"),
        "public_exposure": context.get("public_exposure", "UNDECLARED"),
        "operational_scope": context.get("operational_scope", "UNDECLARED"),
    }
    risk_potential_signal = _derive_risk_potential(safety_profile=safety_profile, context=context)
    payload = {
        "dependency_signal": dependency_signal,
        "operational_context_signal": operational_context_signal,
        "risk_potential_signal": risk_potential_signal,
        "skg_constraint_digest": skg_context.get("skg_digest"),
    }
    return {**payload, "dtn_digest": generate_digest(payload)}


def _derive_risk_potential(*, safety_profile: Mapping[str, Any], context: Mapping[str, Any]) -> float:
    values = [
        int(safety_profile.get("human_safety", 0)),
        int(safety_profile.get("irreversibility", 0)),
        int(safety_profile.get("cascading_impact", 0)),
        int(safety_profile.get("financial_operational", 0)),
    ]
    base = max(values) if values else 0
    exposure_boost = 1 if str(context.get("public_exposure", "")).lower() in {"public", "public-critical", "mixed"} else 0
    return float(min(5, base + exposure_boost))


def sign_dtn_context(dtn_context: Mapping[str, Any]) -> Dict[str, Any]:
    payload = dict(dtn_context)
    return {**payload, "dtn_signature": sign_payload(payload)}
