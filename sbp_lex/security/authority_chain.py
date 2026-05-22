from __future__ import annotations

from typing import Any
from typing import Dict
from typing import Mapping
from typing import List

from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.pqc import sign_payload
from sbp_lex.security.pqc import verify_signature


REQUIRED_AUTHORITY_FIELDS = [

    "jurisdiction",

    "authority_source",

    "authority_scope",

    "authority_state",

]


VALID_AUTHORITY_STATES = [

    "VALID",

    "DENIED",

    "ESCALATED",

]


def build_authority_chain(

    authority: Mapping[
        str,
        Any,
    ],

) -> Dict[
    str,
    Any,
]:

    missing = []

    for field in (

        REQUIRED_AUTHORITY_FIELDS

    ):

        if (

            authority.get(

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

            "AUTHORITY_FIELDS_MISSING",

            "missing":

            missing,

        }

    state = authority.get(

        "authority_state"

    )

    if (

        state

        not in

        VALID_AUTHORITY_STATES

    ):

        return {

            "valid":

            False,

            "reason":

            "INVALID_AUTHORITY_STATE",

        }

    payload = {

        field:

        authority.get(

            field

        )

        for field

        in REQUIRED_AUTHORITY_FIELDS

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

        "authority_hash":

        digest,

        "signature":

        signature,

        "payload":

        payload,

    }


def verify_authority_chain(

    authority_chain:

    Mapping[

        str,

        Any,

    ],

) -> bool:

    payload = (

        authority_chain.get(

            "payload"

        )

    )

    signature = (

        authority_chain.get(

            "signature"

        )

    )

    return (

        verify_signature(

            payload,

            signature,

        )

    )


def evaluate_authority_stack(

    chains:

    List[

        Mapping[

            str,

            Any,

        ]

    ],

) -> Dict[

    str,

    Any,

]:

    failures = []

    hashes = []

    for (

        index,

        chain,

    ) in enumerate(

        chains

    ):

        verified = (

            verify_authority_chain(

                chain

            )

        )

        if (

            not verified

        ):

            failures.append(

                f"AUTHORITY_INVALID:{index}"

            )

        hashes.append(

            chain.get(

                "authority_hash"

            )

        )

    return {

        "valid":

        len(

            failures

        )

        ==

        0,

        "authority_stack":

        generate_digest(

            hashes

        ),

        "failures":

        failures,

  }
