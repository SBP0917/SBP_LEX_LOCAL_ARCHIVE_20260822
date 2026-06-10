from __future__ import annotations

import os
import hmac
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlparse

from sbp_lex.security.pqc import generate_digest

LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost"}
ALLOWED_GET_PATHS = {
    "/health",
    "/dashboard",
    "/desktop",
    "/desktop/static/images/sbp_lex_background.png",
    "/desktop/latest",
    "/desktop/export/latest",
    "/desktop/export/replay-ledger",
    "/desktop/export/events",
    "/runtime/status",
    "/runtime/events",
    "/runtime/integrity",
    "/connector/checkpoints",
    "/apk/contract",
}
ALLOWED_POST_PATHS = {"/runtime/traverse", "/runtime/replay", "/connector/envelope", "/connector/build-envelope"}
DEFAULT_MAX_BODY_BYTES = 1_000_000
DEFAULT_MAX_REPLAY_COUNT = 5


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    status: int
    reason: str
    mode: str
    client_host: str

    def as_payload(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "mode": self.mode,
            "client_host": self.client_host,
        }


def security_mode() -> str:
    """Return active API security mode.

    local: localhost access only by default.
    private: token required; remote access allowed only with valid token.
    disabled: not recommended; leaves API open for isolated test harnesses only.
    """
    return os.environ.get("SBP_LEX_API_SECURITY_MODE", "local").strip().lower()


def configured_api_token() -> str | None:
    token = os.environ.get("SBP_LEX_API_TOKEN")
    return token if token else None


def require_api_token() -> bool:
    if os.environ.get("SBP_LEX_REQUIRE_API_TOKEN", "0") == "1":
        return True
    return security_mode() == "private"


def max_body_bytes() -> int:
    raw = os.environ.get("SBP_LEX_MAX_API_BODY_BYTES")
    if not raw:
        return DEFAULT_MAX_BODY_BYTES
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MAX_BODY_BYTES
    return max(1_024, min(value, 10_000_000))


def max_replay_count() -> int:
    raw = os.environ.get("SBP_LEX_MAX_REPLAY_COUNT")
    if not raw:
        return DEFAULT_MAX_REPLAY_COUNT
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MAX_REPLAY_COUNT
    return max(2, min(value, 20))


def is_local_client(client_host: str) -> bool:
    return client_host in LOCAL_HOSTS or client_host.startswith("127.")


def extract_bearer_token(headers: Mapping[str, str]) -> str | None:
    auth = headers.get("Authorization") or headers.get("authorization")
    if not auth:
        return None
    prefix = "Bearer "
    if not auth.startswith(prefix):
        return None
    token = auth[len(prefix):].strip()
    return token or None


def token_valid(headers: Mapping[str, str]) -> bool:
    expected = configured_api_token()
    provided = extract_bearer_token(headers)
    if not expected:
        return not require_api_token()
    if not provided:
        return False
    return hmac.compare_digest(provided, expected)


def validate_path(method: str, path: str) -> tuple[bool, str]:
    parsed = urlparse(path)
    if method == "GET" and parsed.path in ALLOWED_GET_PATHS:
        return True, "path_allowed"
    if method == "POST" and parsed.path in ALLOWED_POST_PATHS:
        return True, "path_allowed"
    return False, "path_not_allowed"


def validate_content_type(method: str, headers: Mapping[str, str]) -> tuple[bool, str]:
    if method != "POST":
        return True, "content_type_not_required"
    content_type = headers.get("Content-Type") or headers.get("content-type") or ""
    if "application/json" in content_type.lower():
        return True, "content_type_allowed"
    return False, "content_type_must_be_application_json"


def decide_access(*, method: str, path: str, client_host: str, headers: Mapping[str, str]) -> AccessDecision:
    mode = security_mode()
    path_ok, path_reason = validate_path(method, path)
    if not path_ok:
        return AccessDecision(False, 404, path_reason, mode, client_host)

    content_ok, content_reason = validate_content_type(method, headers)
    if not content_ok:
        return AccessDecision(False, 415, content_reason, mode, client_host)

    if mode == "disabled":
        return AccessDecision(True, 200, "security_disabled", mode, client_host)

    local = is_local_client(client_host)
    if mode == "local" and not local:
        return AccessDecision(False, 403, "local_runtime_only", mode, client_host)

    if require_api_token() and not token_valid(headers):
        return AccessDecision(False, 401, "api_token_required_or_invalid", mode, client_host)

    return AccessDecision(True, 200, "access_allowed", mode, client_host)


def request_security_fingerprint(*, method: str, path: str, client_host: str) -> str:
    return generate_digest({"method": method, "path": path, "client_host": client_host, "mode": security_mode()})
