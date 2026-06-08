from __future__ import annotations

from typing import Any
from typing import Dict
from typing import Mapping

from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.pqc import sign_payload
from sbp_lex.security.pqc import verify_signature


REQUIRED_LICENSE_FIELDS=[

    "license_id",

    "license_scope",

    "license_state",

    "deployment_boundary",

    "expiry_state",

]


VALID_LICENSE_STATES=[

    "VALID",

    "DENIED",

    "SUSPENDED",

    "EXPIRED",

]


VALID_EXPIRY_STATES=[

    "ACTIVE",

    "EXPIRED",

]


def build_licensing_gate(

    licensing:

    Mapping[str,Any],

)->Dict[str,Any]:

    missing=[]

    for field in REQUIRED_LICENSE_FIELDS:

        if licensing.get(field) is None:

            missing.append(field)

    if missing:

        return {

            "valid":False,

            "reason":"LICENSE_FIELDS_MISSING",

            "missing":missing,

        }

    state=licensing.get(

        "license_state"

    )

    expiry=licensing.get(

        "expiry_state"

    )

    if state not in VALID_LICENSE_STATES:

        return {

            "valid":False,

            "reason":

            "INVALID_LICENSE_STATE",

        }

    if expiry not in VALID_EXPIRY_STATES:

        return {

            "valid":False,

            "reason":

            "INVALID_EXPIRY_STATE",

        }

    payload={

        field:

        licensing.get(field)

        for field

        in REQUIRED_LICENSE_FIELDS

    }

    digest=generate_digest(

        payload

    )

    signature=sign_payload(

        payload

    )

    verified=verify_signature(

        payload,

        signature,

    )

    return {

        "valid":verified,

        "license_hash":digest,

        "signature":signature,

        "payload":payload,

    }


def verify_licensing_gate(

    licensing_gate:

    Mapping[str,Any],

)->bool:

    payload=(

        licensing_gate.get(

            "payload"

        )

    )

    signature=(

        licensing_gate.get(

            "signature"

        )

    )

    return verify_signature(

        payload,

        signature,

    )


def evaluate_license(

    licensing_gate:

    Mapping[str,Any],

)->Dict[str,Any]:

    verified=(

        verify_licensing_gate(

            licensing_gate

        )

    )

    if not verified:

        return {

            "allowed":False,

            "reason":

            "LICENSE_INVALID",

        }

    payload=(

        licensing_gate.get(

            "payload",

            {},

        )

    )

    state=payload.get(

        "license_state"

    )

    expiry=payload.get(

        "expiry_state"

    )

    if state!="VALID":

        return {

            "allowed":False,

            "reason":

            f"LICENSE_{state}",

        }

    if expiry!="ACTIVE":

        return {

            "allowed":False,

            "reason":

            "LICENSE_EXPIRED",

        }

    return {

        "allowed":True,

        "license_verified":True,

  }
