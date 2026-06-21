from __future__ import annotations

from typing import Any, Mapping

from external_substrates.dtn.signal_builder import build_dtn_signal_package, validate_dtn_signal_package


def prepare_dtn_signals(request: Mapping[str, Any]) -> dict[str, Any]:
    """Prepare external operational signals under an explicit SKG constraint."""
    package = build_dtn_signal_package(**dict(request))
    return {"valid": validate_dtn_signal_package(package, skg_constraint_package=request["skg_constraint_package"]), "package": package}

