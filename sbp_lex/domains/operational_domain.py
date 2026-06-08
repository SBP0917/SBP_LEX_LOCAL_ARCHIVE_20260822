from __future__ import annotations

from typing import Any, Dict, Mapping

from sbp_lex.domains.base_domain import DOMAIN_ESCALATE, DOMAIN_FAIL, DOMAIN_PASS, make_domain_result


class OperationalDomain:
    name = "operational_domain"

    def evaluate(self, state: Mapping[str, Any]) -> Dict[str, Any]:
        context = state.get("context", {}) or {}
        classification = state.get("classification", {}) or {}
        modifiers = classification.get("environment_modifiers", {}) or {}

        failures: list[str] = []
        evidence: dict[str, Any] = {}

        environment = modifiers.get("environment") or context.get("environment")
        human_proximity = modifiers.get("human_proximity") or context.get("human_proximity")
        containment = modifiers.get("operational_containment") or context.get("operational_containment")
        operational_scope = classification.get("operational_scope") or context.get("operational_scope")

        if not environment or environment == "UNDECLARED":
            failures.append("environment_undeclared")

        if not operational_scope or operational_scope == "UNDECLARED":
            failures.append("operational_scope_undeclared")

        if human_proximity in {"high", "dense", "public"} and containment in {"none", "unbounded", "UNDECLARED"}:
            failures.append("high_human_proximity_without_containment")

        emergency_stop_available = bool(context.get("emergency_stop_available", False))
        ap_acf_class = classification.get("ap_acf_class")
        if ap_acf_class in {"CLASS_5", "CLASS_5A", "CLASS_5B"} and not emergency_stop_available:
            failures.append("critical_class_without_emergency_stop")

        evidence.update(
            {
                "environment": environment,
                "human_proximity": human_proximity,
                "operational_containment": containment,
                "operational_scope": operational_scope,
                "emergency_stop_available": emergency_stop_available,
            }
        )

        if "critical_class_without_emergency_stop" in failures:
            return make_domain_result(
                domain=self.name,
                result=DOMAIN_ESCALATE,
                reason="critical_operational_control_missing",
                failures=failures,
                evidence=evidence,
            )

        if failures:
            return make_domain_result(
                domain=self.name,
                result=DOMAIN_FAIL,
                reason="operational_domain_failed",
                failures=failures,
                evidence=evidence,
            )

        return make_domain_result(
            domain=self.name,
            result=DOMAIN_PASS,
            reason="operational_domain_passed",
            evidence=evidence,
        )
