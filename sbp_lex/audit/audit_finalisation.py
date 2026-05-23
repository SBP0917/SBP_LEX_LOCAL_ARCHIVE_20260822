from __future__ import annotations

from typing import Any, Dict, Mapping

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature


REQUIRED_AUDIT_FIELDS = [
    "request_fingerprint",
    "state_hash",
    "decision",
    "execution_verified",
    "convergence_hash",
    "audit_chain",
    "pipeline_mode",
]


def build_audit_record(audit_state: Mapping[str, Any]) -> Dict[str, Any]:
    missing = [
        field
        for field in REQUIRED_AUDIT_FIELDS
        if audit_state.get(field) is None
    ]

    if missing:
        return {
            "valid": False,
            "reason": "AUDIT_FIELDS_MISSING",
            "missing": missing,
        }

    payload = {
        field: audit_state.get(field)
        for field in REQUIRED_AUDIT_FIELDS
    }

    digest = generate_digest(payload)
    signature = sign_payload(payload)
    verified = verify_signature(payload, signature)

    return {
        "valid": verified,
        "audit_hash": digest,
        "signature": signature,
        "payload": payload,
    }


def verify_audit_record(audit_record: Mapping[str, Any]) -> bool:
    payload = audit_record.get("payload")
    signature = audit_record.get("signature")
    return verify_signature(payload, signature)


def finalise_audit(audit_record: Mapping[str, Any]) -> Dict[str, Any]:
    verified = verify_audit_record(audit_record)

    if not verified:
        return {
            "audit_complete": False,
            "reason": "AUDIT_VERIFICATION_FAILED",
        }

    return {
        "audit_complete": True,
        "audit_locked": True,
        "audit_verified": True,
    }
        payload

    )

    verified=verify_signature(

        payload,

        signature,

    )

    return {

        "valid":

        verified,

        "audit_hash":

        digest,

        "signature":

        signature,

        "payload":

        payload,

    }


def verify_audit_record(

    audit_record:

    Mapping[str,Any],

)->bool:

    payload=(

        audit_record.get(

            "payload"

        )

    )

    signature=(

        audit_record.get(

            "signature"

        )

    )

    return verify_signature(

        payload,

        signature,

    )


def finalise_audit(

    audit_record:

    Mapping[str,Any],

)->Dict[str,Any]:

    verified=(

        verify_audit_record(

            audit_record

        )

    )

    if not verified:

        return {

            "audit_complete":

            False,

            "reason":

            "AUDIT_VERIFICATION_FAILED",

        }

    return {

        "audit_complete":

        True,

        "audit_locked":

        True,

        "audit_verified":

        True,

  }
