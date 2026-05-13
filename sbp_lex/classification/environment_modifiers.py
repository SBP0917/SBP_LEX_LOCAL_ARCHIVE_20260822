from __future__ import annotations

from typing import Any, Dict, Mapping


def normalize_environment_modifiers(context: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "environment": context.get("environment", "UNDECLARED"),
        "human_proximity": context.get("human_proximity", "UNDECLARED"),
        "geographic_isolation": context.get("geographic_isolation", "UNDECLARED"),
        "operational_containment": context.get("operational_containment", "UNDECLARED"),
        "public_exposure": context.get("public_exposure", "UNDECLARED"),
        "operational_scope": context.get("operational_scope", "UNDECLARED"),
    }


def environment_can_reduce_class(modifiers: Mapping[str, Any]) -> bool:
    human_proximity = str(modifiers.get("human_proximity", "")).lower()
    geographic_isolation = str(modifiers.get("geographic_isolation", "")).lower()
    containment = str(modifiers.get("operational_containment", "")).lower()

    return (
        human_proximity in {"none", "isolated", "no-human-proximity"}
        and geographic_isolation in {"high", "remote", "isolated", "underground"}
        and containment in {"bounded", "contained", "controlled"}
    )


def public_exposure_is_high(modifiers: Mapping[str, Any]) -> bool:
    exposure = str(modifiers.get("public_exposure", "")).lower()
    return exposure in {"public", "mixed", "public-critical", "critical-public"}


def environment_requires_escalation(modifiers: Mapping[str, Any]) -> bool:
    if public_exposure_is_high(modifiers):
        return True
    environment = str(modifiers.get("environment", "")).lower()
    return environment in {"defence", "aviation", "critical_infrastructure", "public_transport", "medical"}
