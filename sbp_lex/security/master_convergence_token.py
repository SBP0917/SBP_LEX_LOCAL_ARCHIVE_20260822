from __future__ import annotations

from typing import Any
from typing import Dict
from typing import Mapping

from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.pqc import sign_payload
from sbp_lex.security.pqc import verify_signature


REQUIRED_CORE_TOKENS = [

    "authority",

    "procedural_truth",

    "classification",

    "licensing",

    "governance",

    "domain",

    "aurion",

    "execution_boundary",

]

REQUIRED_BUNDLE_TOKENS = [

    "threshold_bundle",

    "token_bundle",

]


def build_master_convergence_token(

    state: Mapping[
        str,
        Any,
    ],

) -> Dict[
    str,
    Any,
]:

    tokens = state.get(

        "tokens",

        {},

    )

    missing = []

    for token in (

        REQUIRED_CORE_TOKENS

        +

        REQUIRED_BUNDLE_TOKENS

    ):

        if token not in tokens:

            missing.append(

                token

            )

    if missing:

        return {

            "valid":

            False,

            "reason":

            "MISSING_TOKEN",

            "missing":

            missing,

        }

    payload = {

        "request_fingerprint":

        state.get(

            "request_fingerprint"

        ),

        "state_hash":

        state.get(

            "state_hash"

        ),

        "pipeline_mode":

        state.get(

            "pipeline_mode"

        ),

        "token_bundle":

        tokens.get(

            "token_bundle"

        ),

        "threshold_bundle":

        tokens.get(

            "threshold_bundle"

        ),

        "governance":

        tokens.get(

            "governance"

        ),

        "classification":

        tokens.get(

            "classification"

        ),

        "licensing":

        tokens.get(

            "licensing"

        ),

        "execution_boundary":

        tokens.get(

            "execution_boundary"

        ),

    }

    token_hash = (

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

        "master_token":

        token_hash,

        "signature":

        signature,

        "payload":

        payload,

    }


def verify_master_token(

    state: Mapping[

        str,

        Any,

    ],

    master_token:

    Mapping[

        str,

        Any,

    ],

) -> bool:

    rebuilt = (

        build_master_convergence_token(

            state

        )

    )

    return (

        rebuilt.get(

            "master_token"

        )

        ==

        master_token.get(

            "master_token"

        )

      )
