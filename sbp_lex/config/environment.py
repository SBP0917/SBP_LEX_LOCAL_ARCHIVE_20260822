from __future__ import annotations

import os
from typing import Any, Dict

from sbp_lex.api.access_control import SecurityConfigurationError, security_mode


def environment_security_report() -> Dict[str, Any]:
    raw_mode = os.environ.get("SBP_LEX_API_SECURITY_MODE", "local").strip().lower()
    try:
        mode = security_mode()
        mode_error = None
    except SecurityConfigurationError as exc:
        mode = raw_mode
        mode_error = str(exc)
    token_required = os.environ.get("SBP_LEX_REQUIRE_API_TOKEN", "0") == "1" or mode == "private"
    signing_secret = os.environ.get("SBP_LEX_SIGNING_SECRET")
    api_token = os.environ.get("SBP_LEX_API_TOKEN")
    warnings: list[str] = []

    if mode_error and mode not in {"local", "private", "disabled"}:
        warnings.append("invalid_api_security_mode")
    if mode_error == "disabled_api_security_mode_outside_test_harness":
        warnings.append("api_security_disabled_outside_test_harness")
    elif mode == "disabled":
        warnings.append("api_security_disabled")
    if token_required and not api_token:
        warnings.append("api_token_required_but_missing")
    if signing_secret is None:
        warnings.append("default_local_signing_secret_active")
    elif len(signing_secret) < 32:
        warnings.append("signing_secret_short")
    if api_token is not None and len(api_token) < 24:
        warnings.append("api_token_short")

    return {
        "mode": mode,
        "token_required": token_required,
        "signing_secret_configured": signing_secret is not None,
        "api_token_configured": api_token is not None,
        "warnings": warnings,
        "valid": len([item for item in warnings if item not in {"default_local_signing_secret_active"}]) == 0,
    }
