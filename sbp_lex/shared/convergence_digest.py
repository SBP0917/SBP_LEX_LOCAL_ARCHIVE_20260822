from __future__ import annotations

from typing import Any
from typing import Dict
from typing import Mapping

from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.pqc import sign_payload
from sbp_lex.security.pqc import verify_signature


CONVERGENCE_FIELDS = [

    "request_fingerprint",

    "state_hash",

    "classification_result",

    "licensing_result",

    "governance_result",

    "domain_result",

    "aurion15_result",

    "execution_result",

    "decision",

]


def build_convergence_digest(

    state: Mapping[str, Any],

) -> Dict[str, Any]:

    tokens = state.get(

        "tokens",

        {},

    )

    payload = {

        field:

        state.get(field)

        for field

        in CONVERGENCE_FIELDS

    }

    payload.update(

        {

            "threshold_bundle_hash":

            tokens.get(

                "threshold_bundle",

                {},

            ).get(

                "digest"

            ),

            "token_bundle_hash":

            tokens.get(

                "token_bundle",

                {},

            ).get(

                "digest"

            ),

            "hash_chain_tail":

            state.get(

                "hash_chain",

                [{}],

            )[-1].get(

                "hash"

            )

            if state.get(

                "hash_chain"

            )

            else "GENESIS",

        }

    )

    convergence_hash = generate_digest(

        payload

    )

    signature = sign_payload(

        payload

    )

    verified = verify_signature(

        payload,

        signature,

    )

    return {

        "payload":

        payload,

        "convergence_hash":

        convergence_hash,

        "signature":

        signature,

        "verified":

        verified,

    }


def verify_convergence_digest(

    state: Mapping[str, Any],

    digest_record:

    Mapping[str, Any],

) -> bool:

    rebuilt = build_convergence_digest(

        state

    )

    return (

        rebuilt.get(

            "convergence_hash"

        )

        ==

        digest_record.get(

            "convergence_hash"

        )

  )
