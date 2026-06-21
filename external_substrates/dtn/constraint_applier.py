from __future__ import annotations

from typing import Any, Mapping

from external_substrates.skg.signal_builder import validate_skg_signal_package


def apply_skg_constraints(skg_package: Mapping[str, Any]) -> dict[str, Any]:
    if not validate_skg_signal_package(skg_package):
        raise ValueError("valid SKG constraint package is required")
    signals = skg_package["signals"]
    authority = signals["authority_link_signal"]["payload"]
    jurisdiction = signals["jurisdiction_signal"]["payload"]
    conflicts = signals["policy_conflict_signal"]["payload"]
    revocation = signals["revocation_signal"]["payload"]
    lineage = signals["truth_lineage_signal"]["payload"]
    valid = all(
        (
            authority.get("resolved") is True,
            jurisdiction.get("resolved") is True,
            conflicts.get("resolved") is True,
            revocation.get("revocation_clear") is True,
            lineage.get("valid") is True,
        )
    )
    return {
        "valid": valid,
        "skg_constraint_digest": skg_package["digest"],
        "authority_chain": list(authority.get("authority_chain", [])),
        "jurisdiction": jurisdiction.get("requested_jurisdiction"),
        "prohibited_pathway_ids": [],
    }

