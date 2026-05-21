from __future__ import annotations

from copy import deepcopy
from typing import Any
from typing import Dict
from typing import List
from typing import Mapping

from sbp_lex.security.pqc import generate_digest


MINIMUM_NODE_QUORUM = 3


def validate_node_quorum(

    node_results: List[
        Mapping[
            str,
            Any,
        ]
    ],

) -> Dict[str, Any]:

    if (

        len(node_results)

        <

        MINIMUM_NODE_QUORUM

    ):

        return {

            "verified":

            False,

            "reason":

            "INSUFFICIENT_NODE_QUORUM",

            "required":

            MINIMUM_NODE_QUORUM,

            "received":

            len(node_results),

        }

    convergence_hashes = []

    decisions = []

    audit_hashes = []

    for node in node_results:

        convergence_hashes.append(

            node.get(

                "convergence_hash"

            )

        )

        decisions.append(

            node.get(

                "decision"

            )

        )

        audit_hashes.append(

            node.get(

                "audit_hash"

            )

        )

    convergence_valid = (

        len(

            set(

                convergence_hashes

            )

        )

        ==

        1

    )

    decision_valid = (

        len(

            set(

                decisions

            )

        )

        ==

        1

    )

    audit_valid = (

        len(

            set(

                audit_hashes

            )

        )

        ==

        1

    )

    payload = {

        "convergence":

        convergence_hashes,

        "decision":

        decisions,

        "audit":

        audit_hashes,

    }

    quorum_hash = (

        generate_digest(

            payload

        )

    )

    verified = all(

        [

            convergence_valid,

            decision_valid,

            audit_valid,

        ]

    )

    return {

        "verified":

        verified,

        "quorum_hash":

        quorum_hash,

        "node_count":

        len(

            node_results

        ),

        "convergence_valid":

        convergence_valid,

        "decision_valid":

        decision_valid,

        "audit_valid":

        audit_valid,

    }


def freeze_node_result(

    node_result:

    Mapping[

        str,

        Any,

    ],

) -> Dict[str, Any]:

    frozen = deepcopy(

        dict(

            node_result

        )

    )

    frozen[

        "node_hash"

    ] = generate_digest(

        frozen

    )

    return frozen
