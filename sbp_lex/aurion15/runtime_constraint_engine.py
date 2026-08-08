from __future__ import annotations

from typing import Any
from typing import Dict
from typing import Mapping

from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.pqc import sign_payload
from sbp_lex.security.pqc import verify_signature


REQUIRED_RUNTIME_FIELDS=[

    "candidate_hash",

    "constraint_state",

    "threshold_state",

    "governance_state",

    "execution_state",

]


VALID_CONSTRAINT_STATES=[

    "VALID",

    "DENIED",

    "ESCALATED",

]


def build_runtime_constraint(

    runtime:

    Mapping[str,Any],

)->Dict[str,Any]:

    missing=[]

    for field in REQUIRED_RUNTIME_FIELDS:

        if runtime.get(field) is None:

            missing.append(field)

    if missing:

        return {

            "valid":False,

            "reason":

            "RUNTIME_FIELDS_MISSING",

            "missing":missing,

        }

    state=runtime.get(

        "constraint_state"

    )

    if (

        state

        not in

        VALID_CONSTRAINT_STATES

    ):

        return {

            "valid":False,

            "reason":

            "INVALID_RUNTIME_STATE",

        }

    payload={

        field:

        runtime.get(field)

        for field

        in REQUIRED_RUNTIME_FIELDS

    }

    digest=generate_digest(

        payload

    )

    signature=sign_payload(

        payload,

    )

    verified=verify_signature(

        payload,

        signature,

    )

    return {

        "valid":False,

        "reason":"NON_CANONICAL_RUNTIME_HELPER_NO_AUTHORITY",

        "integrity_verified":verified,

        "execution_convergence_eligible":False,

        "runtime_hash":

        digest,

        "signature":

        signature,

        "payload":

        payload,

    }


def verify_runtime_constraint(

    runtime_record:

    Mapping[str,Any],

)->bool:

    payload=(

        runtime_record.get(

            "payload"

        )

    )

    signature=(

        runtime_record.get(

            "signature"

        )

    )

    return verify_signature(

        payload,

        signature,

    )


def evaluate_runtime_constraint(

    runtime_record:

    Mapping[str,Any],

)->Dict[str,Any]:

    verified=(

        verify_runtime_constraint(

            runtime_record

        )

    )

    if not verified:

        return {

            "allowed":False,

            "reason":

            "RUNTIME_INVALID",

        }

    return {

        "allowed":False,

        "reason":"NON_CANONICAL_RUNTIME_HELPER_NO_AUTHORITY",

        "integrity_verified":True,

        "execution_convergence_eligible":False,

}
