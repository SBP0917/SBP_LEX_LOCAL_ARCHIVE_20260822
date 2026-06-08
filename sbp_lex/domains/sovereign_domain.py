from __future__ import annotations

from typing import Any, Dict, Mapping

from sbp_lex.domains.base_domain import DOMAIN_FAIL, DOMAIN_PASS, make_domain_result


class SovereignDomain:
    name = "sovereign_domain"

    def evaluate(self, state: Mapping[str, Any]) -> Dict[str, Any]:
        context = state.get("context", {}) or {}
        collective = state.get("collective_signals", {}) or {}

        failures: list[str] = []
        evidence: dict[str, Any] = {}

        authority_signal = collective.get("authority_link_signal", {}) or {}
        jurisdiction_signal = collective.get("jurisdiction_signal", {}) or {}

        resolved_authority = state.get("resolved_authority") or authority_signal.get("resolved_authority")
        jurisdiction = state.get("jurisdiction") or jurisdiction_signal.get("jurisdiction")

        if not resolved_authority or resolved_authority == "UNRESOLVED":
            failures.append("sovereign_authority_unresolved")

        if not jurisdiction or jurisdiction == "UNRESOLVED":
            failures.append("sovereign_jurisdiction_unresolved")

        sovereign_boundary = context.get("sovereign_boundary", "DECLARED")
        if sovereign_boundary in {"VIOLATED", "CONFLICTED"}:
            failures.append("sovereign_boundary_violation")

        evidence["resolved_authority"] = resolved_authority
        evidence["jurisdiction"] = jurisdiction
        evidence["sovereign_boundary"] = sovereign_boundary

        if failures:
            return make_domain_result(
                domain=self.name,
                result=DOMAIN_FAIL,
                reason="sovereign_domain_failed",
                failures=failures,
                evidence=evidence,
            )

        return make_domain_result(
            domain=self.name,
            result=DOMAIN_PASS,
            reason="sovereign_domain_passed",
            evidence=evidence,
      )
