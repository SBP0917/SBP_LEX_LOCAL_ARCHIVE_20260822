from __future__ import annotations

from typing import Any, Mapping

from external_substrates.skg.signal_builder import build_skg_signal_package, validate_skg_signal_package


def prepare_skg_signals(request: Mapping[str, Any]) -> dict[str, Any]:
    """Prepare external SKG signals without invoking or mutating SBP-LEX."""
    package = build_skg_signal_package(**dict(request))
    return {"valid": validate_skg_signal_package(package), "package": package}

