from __future__ import annotations

from copy import deepcopy
from typing import Any
from typing import Dict
from typing import Mapping
from typing import List

from sbp_lex.security.pqc import generate_digest


GENESIS_HASH = "SBP_LEX_GENESIS"


def initialise_hash_chain(

    state: Mapping[
        str,
        Any,
    ],

) -> Dict[
    str,
    Any,
]:

    working = deepcopy(

        dict(

            state

        )

    )

    working[

        "hash_chain"

    ] = [

        {

            "stage":

            "GENESIS",

            "previous_hash":

            None,

            "payload_hash":

            GENESIS_HASH,

            "hash":

            generate_digest(

                GENESIS_HASH

            ),

        }

    ]

    return working


def append_hash_stage(

    state: Mapping[
        str,
        Any,
    ],

    *,

    stage: str,

    payload: Mapping[
        str,
        Any,
    ],

) -> Dict[
    str,
    Any,
]:

    working = deepcopy(

        dict(

            state

        )

    )

    chain = working.get(

        "hash_chain",

        [],

    )

    if not chain:

        raise RuntimeError(

            "HASH_CHAIN_UNINITIALISED"

        )

    previous = chain[-1]

    payload_hash = (

        generate_digest(

            payload

        )

    )

    chain_hash = (

        generate_digest(

            {

                "stage":

                stage,

                "previous":

                previous[

                    "hash"

                ],

                "payload":

                payload_hash,

            }

        )

    )

    chain.append(

        {

            "stage":

            stage,

            "previous_hash":

            previous[

                "hash"

            ],

            "payload_hash":

            payload_hash,

            "hash":

            chain_hash,

        }

    )

    working[

        "hash_chain"

    ] = chain

    return working


def verify_hash_chain(

    state: Mapping[
        str,
        Any,
    ],

) -> Dict[
    str,
    Any,
]:

    chain = state.get(

        "hash_chain",

        [],

    )

    failures: List[
        str
    ] = []

    if not chain:

        failures.append(

            "HASH_CHAIN_MISSING"

        )

    for index in range(

        1,

        len(

            chain

        ),

    ):

        previous = chain[

            index - 1

        ]

        current = chain[

            index

        ]

        if (

            current.get(

                "previous_hash"

            )

            !=

            previous.get(

                "hash"

            )

        ):

            failures.append(

                f"HASH_LINK_BROKEN:{index}"

            )

    return {

        "valid":

        len(

            failures

        )

        ==

        0,

        "failures":

        failures,

  }
