from __future__ import annotations

from typing import Any, Dict, Mapping

from sbp_lex.domains.base_domain import DOMAIN_ESCALATE, DOMAIN_FAIL, DOMAIN_PASS, make_domain_result


class LegalDomain:
    name = "legal_domain"

    def evaluate(self, state: Mapping[str, Any]) -> Dict[str, Any]:
        context = state.get("context", {}) or {}
        classification = state.get("classification", {}) or {}

        failures: list[str] = []
        evidence: dict[str, Any] = {}

        jurisdiction = state.get("jurisdiction") or context.get("jurisdiction")
        if not jurisdiction:
            failures.append("jurisdiction_missing")

        legal_hold = bool(context.get("legal_hold", False))
        if legal_hold:
            failures.append("legal_hold_active")

        prohibited_scope = context.get("prohibited_scope", [])
        operational_scope = classification.get("operational_scope") or context.get("operational_scope")
        if isinstance(prohibited_scope, list) and operational_scope in prohibited_scope:
            failures.append("operational_scope_legally_prohibited")

        evidence["jurisdiction"] = jurisdiction
        evidence["operational_scope"] = operational_scope
        evidence["legal_hold"] = legal_hold

        if "legal_hold_active" in failures or "operational_scope_legally_prohibited" in failures:
            return make_domain_result(
                domain=self.name,
                result=DOMAIN_ESCALATE,
                reason=(
                    "legal_hold_requires_escalation"
                    if "legal_hold_active" in failures
                    else "prohibited_scope_requires_escalation"
                ),
                failures=failures,
                evidence=evidence,
            )

        if failures:
            return make_domain_result(
                domain=self.name,
                result=DOMAIN_FAIL,
                reason="legal_domain_failed",
                failures=failures,
                evidence=evidence,
            )

        return make_domain_result(
            domain=self.name,
            result=DOMAIN_PASS,
            reason="legal_domain_passed",
            evidence=evidence,
      )
