from __future__ import annotations

from typing import Any
from typing import Dict
from typing import Mapping

from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.pqc import sign_payload
from sbp_lex.security.pqc import verify_signature


REQUIRED_EXECUTION_FIELDS = [

    "request_fingerprint",

    "state_hash",

    "decision",

    "pipeline_mode",

    "convergence_hash",

    "master_token",

]


def build_execution_attestation(

    state: Mapping[
        str,
        Any,
    ],

) -> Dict[
    str,
    Any,
]:

    missing = []

    for field in (

        REQUIRED_EXECUTION_FIELDS

    ):

        if (

            state.get(

                field

            )

            is None

        ):

            missing.append(

                field

            )

    if missing:

        return {

            "valid":

            False,

            "reason":

            "EXECUTION_FIELD_MISSING",

            "missing":

            missing,

        }

    payload = {

        field:

        state.get(

            field

        )

        for field

        in REQUIRED_EXECUTION_FIELDS

    }

    payload[

        "audit_hash"

    ] = state.get(

        "audit_hash"

    )

    payload[

        "node_quorum"

    ] = state.get(

        "node_quorum"

    )

    payload[

        "timestamp"

    ] = state.get(

        "execution_timestamp"

    )

    digest = (

        generate_digest(

            payload

        )

    )

    signature = (

        sign_payload(

            payload

        )

    )

    verified = (

        verify_signature(

            payload,

            signature,

        )

    )

    return {

        "valid":

        verified,

        "attestation_hash":

        digest,

        "signature":

        signature,

        "payload":

        payload,

    }


def verify_execution_attestation(

    state: Mapping[
        str,
        Any,
    ],

    attestation:

    Mapping[
        str,
        Any,
    ],

) -> bool:

    rebuilt = (

        build_execution_attestation(

            state

        )

    )

    return (

        rebuilt.get(

            "attestation_hash"

        )

        ==

        attestation.get(

            "attestation_hash"

        )

)
