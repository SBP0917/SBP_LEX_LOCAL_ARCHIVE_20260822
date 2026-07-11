from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

from sbp_lex.api.access_control import decide_access, max_body_bytes, max_replay_count, request_security_fingerprint, security_mode
from sbp_lex.api.apk_contract import validate_runtime_status_contract
from sbp_lex.config.environment import environment_security_report
from sbp_lex.api.rate_limit import API_RATE_LIMITER
from sbp_lex.api.schema_validation import loads_strict_json, validate_api_body_schema, validate_runtime_request_schema
from sbp_lex.connector.envelope import build_connector_envelope
from sbp_lex.desktop.dashboard import (
    desktop_background_bytes,
    desktop_dashboard_html,
    export_latest_runtime_json,
    export_replay_ledger_json,
    export_traversal_events_json,
    latest_runtime_snapshot,
)
from sbp_lex.connector.fabric import process_connector_envelope
from sbp_lex.connector.recovery import CONNECTOR_RECOVERY
from sbp_lex.persistence.integrity_store import RUNTIME_INTEGRITY_STORE
from sbp_lex.runtime.canonical_runtime import CANONICAL_RUNTIME
from sbp_lex.runtime.event_bus import RUNTIME_EVENTS


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: Dict[str, Any]) -> None:
    body = json.dumps(payload, indent=2, default=str).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Pragma", "no-cache")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Referrer-Policy", "no-referrer")
    handler.end_headers()
    handler.wfile.write(body)



def _html_response(handler: BaseHTTPRequestHandler, status: int, html: str) -> None:
    body = html.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Pragma", "no-cache")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Referrer-Policy", "no-referrer")
    handler.end_headers()
    handler.wfile.write(body)


def _png_response(handler: BaseHTTPRequestHandler, status: int, body: bytes) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", "image/png")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "private, max-age=3600")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Referrer-Policy", "no-referrer")
    handler.end_headers()
    handler.wfile.write(body)


def _validate_endpoint_payload(path: str, payload: Dict[str, Any]) -> tuple[bool, list[str]]:
    if path in {"/runtime/traverse", "/runtime/replay"} and "action" in payload:
        return validate_runtime_request_schema(payload)
    return validate_api_body_schema(path, payload)


class RuntimeAPIHandler(BaseHTTPRequestHandler):
    server_version = "SBP-LEX-V1-RuntimeAPI"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _headers_mapping(self) -> dict[str, str]:
        return {key: value for key, value in self.headers.items()}

    def _client_host(self) -> str:
        return str(self.client_address[0]) if self.client_address else "unknown"

    def _authorize(self, method: str, body: bytes | None = None) -> tuple[bool, int, Dict[str, Any]]:
        client_host = self._client_host()
        path = self.path
        headers = self._headers_mapping()
        allowed, rate = API_RATE_LIMITER.allow(client_host)
        if not allowed:
            RUNTIME_EVENTS.emit(
                "api_access_rejected",
                {"reason": "rate_limited", "client_host": client_host, "path": urlparse(path).path},
            )
            return False, 429, {"error": "rate_limited", "rate": rate}

        decision = decide_access(method=method, path=path, client_host=client_host, headers=headers, body=body)
        if not decision.allowed:
            RUNTIME_EVENTS.emit(
                "api_access_rejected",
                {
                    "reason": decision.reason,
                    "status": decision.status,
                    "client_host": client_host,
                    "path": urlparse(path).path,
                    "security_fingerprint": request_security_fingerprint(method=method, path=path, client_host=client_host),
                },
            )
            return False, decision.status, {"error": decision.reason, "access": decision.as_payload()}
        return True, 200, {"access": decision.as_payload(), "rate": rate}

    def do_GET(self) -> None:
        ok, status, payload = self._authorize("GET")
        if not ok:
            return _json_response(self, status, payload)

        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/health":
            return _json_response(self, 200, {"ok": True, "service": "SBP-LEX V1 Canonical Runtime", "access": payload.get("access")})
        if parsed.path in {"/dashboard", "/desktop"}:
            return _html_response(self, 200, desktop_dashboard_html())
        if parsed.path == "/desktop/static/images/sbp_lex_background.png":
            return _png_response(self, 200, desktop_background_bytes())
        if parsed.path == "/desktop/latest":
            return _json_response(self, 200, latest_runtime_snapshot())
        if parsed.path == "/desktop/export/latest":
            return _json_response(self, 200, export_latest_runtime_json())
        if parsed.path == "/desktop/export/replay-ledger":
            return _json_response(self, 200, export_replay_ledger_json())
        if parsed.path == "/desktop/export/events":
            return _json_response(self, 200, export_traversal_events_json())
        if parsed.path == "/runtime/status":
            return _json_response(self, 200, CANONICAL_RUNTIME.status())
        if parsed.path == "/runtime/events":
            try:
                after = int(query.get("after", [0])[0])
            except (TypeError, ValueError):
                return _json_response(self, 400, {"error": "invalid_after_parameter"})
            return _json_response(self, 200, {"events": RUNTIME_EVENTS.since(after)})
        if parsed.path == "/connector/checkpoints":
            return _json_response(self, 200, {"checkpoints": CONNECTOR_RECOVERY.export(), "history": CONNECTOR_RECOVERY.export_history()})
        if parsed.path == "/runtime/integrity":
            status = CANONICAL_RUNTIME.status()
            contract_ok, contract_failures = validate_runtime_status_contract(status)
            return _json_response(
                self,
                200,
                {
                    "status_contract_valid": contract_ok,
                    "status_contract_failures": contract_failures,
                    "runtime_status": status,
                    "environment_security": environment_security_report(),
                    "persistence_records": RUNTIME_INTEGRITY_STORE.export(),
                },
            )
        if parsed.path == "/apk/contract":
            status = CANONICAL_RUNTIME.status()
            contract_ok, contract_failures = validate_runtime_status_contract(status)
            return _json_response(
                self,
                200,
                {
                    "apk_contract_version": "SBP_LEX_V1_APK_CONNECTOR_CONTRACT_1",
                    "topology": "APK -> Connector Fabric -> Canonical Runtime -> Pipeline A/B -> Parity/Convergence -> Audit/Observability",
                    "apk_authority": "observational_orchestration_only",
                    "runtime_authority": "canonical_execution_authority",
                    "status_contract_valid": contract_ok,
                    "status_contract_failures": contract_failures,
                    "required_status_fields": sorted(list({"runtime_id", "api_security_mode", "traversal_count", "chronology_valid", "event_bus_valid", "replay_ledger_valid", "connector_recovery_valid", "persistence_valid"})),
                },
            )
        return _json_response(self, 404, {"error": "not_found", "path": parsed.path})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            limit = max_body_bytes()
            if length <= 0:
                return _json_response(self, 400, {"error": "empty_request_body"})
            if length > limit:
                return _json_response(self, 413, {"error": "request_too_large", "limit": limit})
            body_bytes = self.rfile.read(length)
            body = body_bytes.decode("utf-8")
            payload = loads_strict_json(body or "{}")
            if not isinstance(payload, dict):
                return _json_response(self, 400, {"error": "json_body_must_be_object"})
        except Exception:
            return _json_response(self, 400, {"error": "invalid_json"})

        ok, status, access_payload = self._authorize("POST", body=body_bytes)
        if not ok:
            return _json_response(self, status, access_payload)

        schema_ok, schema_failures = _validate_endpoint_payload(parsed.path, payload)
        if not schema_ok:
            RUNTIME_EVENTS.emit("api_schema_rejected", {"path": parsed.path, "failures": schema_failures})
            return _json_response(self, 400, {"error": "schema_validation_failed", "failures": schema_failures})

        if parsed.path == "/runtime/traverse":
            request = payload.get("request", payload)
            if not isinstance(request, dict):
                return _json_response(self, 400, {"error": "request_must_be_object"})
            result = CANONICAL_RUNTIME.traverse(
                request,
                request_id=payload.get("request_id") if "request" in payload else None,
                pre_context_signals=payload.get("pre_context_signals") if "request" in payload else None,
            )
            return _json_response(self, 200, result)

        if parsed.path == "/runtime/replay":
            request = payload.get("request", payload)
            if not isinstance(request, dict):
                return _json_response(self, 400, {"error": "request_must_be_object"})
            replay_count = int(payload.get("replay_count", 2)) if "request" in payload else 2
            if replay_count > max_replay_count():
                return _json_response(self, 400, {"error": "replay_count_exceeds_limit", "limit": max_replay_count()})
            result = CANONICAL_RUNTIME.replay(
                request,
                replay_count=replay_count,
                pre_context_signals=payload.get("pre_context_signals") if "request" in payload else None,
            )
            return _json_response(self, 200, result)

        if parsed.path == "/connector/envelope":
            result = process_connector_envelope(payload)
            return _json_response(self, 200 if result.get("accepted") else 400, result)

        if parsed.path == "/connector/build-envelope":
            request = payload.get("request", {})
            if not isinstance(request, dict):
                return _json_response(self, 400, {"error": "request_must_be_object"})
            result = build_connector_envelope(
                request_id=str(payload.get("request_id", "manual-request")),
                source=str(payload.get("source", "manual")),
                request=request,
                metadata=payload.get("metadata", {}),
            )
            return _json_response(self, 200, result)

        return _json_response(self, 404, {"error": "not_found", "path": parsed.path})


def run_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    # Resolve before binding the socket. Invalid or non-test unauthenticated
    # configuration must prevent startup rather than fall through at request time.
    security_mode()
    server = ThreadingHTTPServer((host, port), RuntimeAPIHandler)
    print(f"SBP-LEX V1 Canonical Runtime API listening on http://{host}:{port}")
    server.serve_forever()
