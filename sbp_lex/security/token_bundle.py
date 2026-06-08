from __future__ import annotations

from typing import Any
from typing import Dict
from typing import Mapping

from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.pqc import sign_payload
from sbp_lex.security.pqc import verify_signature


REQUIRED_TOKENS = [

    "authority",

    "procedural_truth",

    "classification",

    "licensing",

    "governance",

    "domain",

    "aurion",

    "execution_boundary",

]


def build_token_bundle(

    tokens: Mapping[
        str,
        Any,
    ],

) -> Dict[
    str,
    Any,
]:

    missing = []

    for token in (

        REQUIRED_TOKENS

    ):

        if (

            token

            not in

            tokens

        ):

            missing.append(

                token

            )

    if missing:

        return {

            "valid":

            False,

            "reason":

            "TOKEN_MISSING",

            "missing":

            missing,

        }

    payload = {

        token:

        tokens.get(

            token

        )

        for token

        in REQUIRED_TOKENS

    }

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

        "bundle_digest":

        digest,

        "signature":

        signature,

        "payload":

        payload,

    }


def verify_token_bundle(

    tokens:

    Mapping[

        str,

        Any,

    ],

    token_bundle:

    Mapping[

        str,

        Any,

    ],

) -> bool:

    rebuilt = (

        build_token_bundle(

            tokens

        )

    )

    return (

        rebuilt.get(

            "bundle_digest"

        )

        ==

        token_bundle.get(

            "bundle_digest"

        )

  )
