from __future__ import annotations

from typing import Any, Dict, Mapping

from sbp_lex.domains.base_domain import DOMAIN_ESCALATE, DOMAIN_FAIL, DOMAIN_PASS, make_domain_result


class RiskDomain:
    name = "risk_domain"

    def evaluate(self, state: Mapping[str, Any]) -> Dict[str, Any]:
        safety = state.get("safety_profile", {}) or {}
        context = state.get("context", {}) or {}
        classification = state.get("classification", {}) or {}

        failures: list[str] = []
        evidence: dict[str, Any] = {}

        computed_tier = safety.get("computed_tier")
        financial_tier = safety.get("financial_tier")
        corroboration_met = bool(state.get("corroboration_met", False))
        ap_acf_class = classification.get("ap_acf_class")

        if computed_tier in {"MEDIUM", "TOP"} and not corroboration_met:
            failures.append("risk_tier_without_corroboration")

        if computed_tier == "TOP" and ap_acf_class not in {"CLASS_4", "CLASS_4A", "CLASS_4B", "CLASS_5", "CLASS_5A", "CLASS_5B"}:
            failures.append("top_consequence_low_class_mismatch")

        if financial_tier == "TOP" and not context.get("financial_authority_confirmed", False):
            failures.append("top_financial_tier_without_authority_confirmation")

        evidence.update(
            {
                "computed_tier": computed_tier,
                "financial_tier": financial_tier,
                "corroboration_met": corroboration_met,
                "ap_acf_class": ap_acf_class,
                "financial_authority_confirmed": context.get("financial_authority_confirmed", False),
            }
        )

        if "top_financial_tier_without_authority_confirmation" in failures:
            return make_domain_result(
                domain=self.name,
                result=DOMAIN_ESCALATE,
                reason="top_financial_tier_requires_authority_confirmation",
                failures=failures,
                evidence=evidence,
            )

        if failures:
            return make_domain_result(
                domain=self.name,
                result=DOMAIN_FAIL,
                reason="risk_domain_failed",
                failures=failures,
                evidence=evidence,
            )

        return make_domain_result(
            domain=self.name,
            result=DOMAIN_PASS,
            reason="risk_domain_passed",
            evidence=evidence,
        )
