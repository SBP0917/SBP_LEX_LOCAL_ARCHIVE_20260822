from __future__ import annotations

from typing import Any
from typing import Dict
from typing import Mapping
from typing import List

from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.pqc import sign_payload
from sbp_lex.security.pqc import verify_signature


MINIMUM_CANDIDATE_SCORE=0.80


def resolve_candidates(

    candidates:

    List[

        Mapping[

            str,

            Any,

        ]

    ],

)->Dict[str,Any]:

    if not candidates:

        return {

            "valid":False,

            "reason":

            "NO_CANDIDATES",

        }

    ranked=sorted(

        candidates,

        key=lambda x:

        x.get(

            "score",

            0,

        ),

        reverse=True,

    )

    selected=ranked[0]

    if (

        selected.get(

            "score",

            0,

        )

        <

        MINIMUM_CANDIDATE_SCORE

    ):

        return {

            "valid":False,

            "reason":

            "INSUFFICIENT_CONFIDENCE",

        }

    payload={

        "candidate":

        selected.get(

            "candidate_id"

        ),

        "score":

        selected.get(

            "score"

        ),

        "constraints":

        selected.get(

            "constraints"

        ),

        "path":

        selected.get(

            "path"

        ),

    }

    digest=generate_digest(

        payload

    )

    signature=sign_payload(

        payload

    )

    verified=verify_signature(

        payload,

        signature,

    )

    return {

        "valid":False,

        "reason":"NON_CANONICAL_AURION_HELPER_NO_AUTHORITY",

        "integrity_verified":verified,

        "execution_convergence_eligible":False,

        "candidate_hash":

        digest,

        "signature":

        signature,

        "payload":

        payload,

        "selected":

        selected,

    }


def verify_candidate_resolution(

    candidate_record:

    Mapping[

        str,

        Any,

    ],

)->bool:

    payload=(

        candidate_record.get(

            "payload"

        )

    )

    signature=(

        candidate_record.get(

            "signature"

        )

    )

    return verify_signature(

        payload,

        signature,

    )


def evaluate_candidate(

    candidate_record:

    Mapping[

        str,

        Any,

    ],

)->Dict[str,Any]:

    verified=(

        verify_candidate_resolution(

            candidate_record

        )

    )

    if not verified:

        return {

            "allowed":False,

            "reason":

            "CANDIDATE_INVALID",

        }

    return {

        "allowed":False,

        "reason":"NON_CANONICAL_AURION_HELPER_NO_AUTHORITY",

        "integrity_verified":True,

        "execution_convergence_eligible":False,

}
