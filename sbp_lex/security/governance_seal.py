from __future__ import annotations

from typing import Any
from typing import Dict
from typing import Mapping

from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.pqc import sign_payload
from sbp_lex.security.pqc import verify_signature


REQUIRED_GOVERNANCE_FIELDS = [

    "request_fingerprint",

    "authority_token",

    "governance_result",

    "procedural_truth",

    "classification_result",

    "licensing_result",

    "state_hash",

]


def build_governance_seal(

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

        REQUIRED_GOVERNANCE_FIELDS

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

            "GOVERNANCE_FIELDS_MISSING",

            "missing":

            missing,

        }

    payload = {

        field:

        state.get(

            field

        )

        for field

        in REQUIRED_GOVERNANCE_FIELDS

    }

    payload[

        "pipeline_mode"

    ] = state.get(

        "pipeline_mode"

    )

    payload[

        "governance_timestamp"

    ] = state.get(

        "governance_timestamp"

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

        "seal_hash":

        digest,

        "signature":

        signature,

        "payload":

        payload,

    }


def verify_governance_seal(

    state: Mapping[
        str,
        Any,
    ],

    seal:

    Mapping[
        str,
        Any,
    ],

) -> bool:

    rebuilt = (

        build_governance_seal(

            state

        )

    )

    return (

        rebuilt.get(

            "seal_hash"

        )

        ==

        seal.get(

            "seal_hash"

        )

  )
