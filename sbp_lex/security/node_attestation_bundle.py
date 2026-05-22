from __future__ import annotations

from typing import Any
from typing import Dict
from typing import Mapping
from typing import List

from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.pqc import sign_payload
from sbp_lex.security.pqc import verify_signature


MINIMUM_ATTESTATION_COUNT = 3


def build_node_attestation_bundle(

    node_attestations:

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

    if (

        len(

            node_attestations

        )

        <

        MINIMUM_ATTESTATION_COUNT

    ):

        return {

            "valid":

            False,

            "reason":

            "INSUFFICIENT_NODE_ATTESTATION",

            "required":

            MINIMUM_ATTESTATION_COUNT,

            "received":

            len(

                node_attestations

            ),

        }

    hashes = []

    signatures = []

    nodes = []

    failures = []

    for (

        index,

        node,

    ) in enumerate(

        node_attestations

    ):

        attestation = (

            node.get(

                "attestation_hash"

            )

        )

        signature = (

            node.get(

                "signature"

            )

        )

        payload = (

            node.get(

                "payload"

            )

        )

        verified = (

            verify_signature(

                payload,

                signature,

            )

        )

        if (

            not verified

        ):

            failures.append(

                f"INVALID_SIGNATURE:{index}"

            )

        hashes.append(

            attestation

        )

        signatures.append(

            signature

        )

        nodes.append(

            node.get(

                "node_id"

            )

        )

    payload = {

        "nodes":

        nodes,

        "hashes":

        hashes,

        "signatures":

        signatures,

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

        (

            verified

            and

            len(

                failures

            )

            ==

            0

        ),

        "bundle_hash":

        digest,

        "signature":

        signature,

        "payload":

        payload,

        "failures":

        failures,

    }


def verify_node_bundle(

    node_bundle:

    Mapping[

        str,

        Any,

    ],

) -> bool:

    payload = (

        node_bundle.get(

            "payload"

        )

    )

    signature = (

        node_bundle.get(

            "signature"

        )

    )

    return (

        verify_signature(

            payload,

            signature,

        )

      )
