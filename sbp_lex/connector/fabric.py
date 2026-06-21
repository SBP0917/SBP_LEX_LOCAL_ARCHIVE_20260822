from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.connector.envelope import validate_connector_envelope
from sbp_lex.connector.recovery import CONNECTOR_RECOVERY
from sbp_lex.runtime.canonical_runtime import CANONICAL_RUNTIME
from sbp_lex.runtime.event_bus import RUNTIME_EVENTS


def process_connector_envelope(envelope: Mapping[str, Any]) -> Dict[str, Any]:
    request_id = str(envelope.get("request_id", "")) if isinstance(envelope, Mapping) else ""
    source = str(envelope.get("source", "connector")) if isinstance(envelope, Mapping) else "connector"
    valid, failures = validate_connector_envelope(envelope)

    if not valid:
        rejection = CONNECTOR_RECOVERY.save_rejection(request_id, failures=failures, source=source)
        RUNTIME_EVENTS.emit("connector_envelope_rejected", {"request_id": request_id, "failures": failures})
        return {"accepted": False, "request_id": request_id, "failures": failures, "rejection": rejection}

    if not CONNECTOR_RECOVERY.claim(request_id):
        failures = ["duplicate_connector_request_id"]
        rejection = CONNECTOR_RECOVERY.save_rejection(request_id, failures=failures, source=source)
        RUNTIME_EVENTS.emit("connector_envelope_rejected", {"request_id": request_id, "failures": failures})
        return {"accepted": False, "request_id": request_id, "failures": failures, "rejection": rejection}

    try:
        RUNTIME_EVENTS.emit("connector_envelope_accepted", {"request_id": request_id, "source": source})
        result = CANONICAL_RUNTIME.traverse(deepcopy(dict(envelope.get("request", {}))), request_id=request_id)
        checkpoint = CONNECTOR_RECOVERY.save(request_id, result.get("state", {}), source=source)
        return {**result, "accepted": True, "checkpoint": checkpoint}
    except Exception as exc:
        failures = ["connector_runtime_exception", exc.__class__.__name__]
        rejection = CONNECTOR_RECOVERY.save_rejection(request_id, failures=failures, source=source)
        RUNTIME_EVENTS.emit("connector_interruption_recorded", {"request_id": request_id, "failures": failures})
        return {"accepted": False, "request_id": request_id, "failures": failures, "rejection": rejection}
