from __future__ import annotations

from typing import Any
from typing import Dict
from typing import Mapping

from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.pqc import sign_payload
from sbp_lex.security.pqc import verify_signature


REQUIRED_PROCEDURAL_FIELDS=[

    "corroboration_score",

    "freshness_state",

    "source_validation",

    "consistency_validation",

    "threshold_state",

]


VALID_FRESHNESS=[

    "VALID",

    "STALE",

    "EXPIRED",

]


def build_truth_anchor(

    truth:Mapping[str,Any],

)->Dict[str,Any]:

    missing=[]

    for field in REQUIRED_PROCEDURAL_FIELDS:

        if truth.get(field) is None:

            missing.append(field)

    if missing:

        return {

            "valid":False,

            "reason":"TRUTH_FIELDS_MISSING",

            "missing":missing,

        }

    freshness=truth.get(

        "freshness_state"

    )

    if freshness not in VALID_FRESHNESS:

        return {

            "valid":False,

            "reason":"INVALID_FRESHNESS",

        }

    payload={

        field:

        truth.get(field)

        for field

        in REQUIRED_PROCEDURAL_FIELDS

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

        "valid":verified,

        "truth_hash":digest,

        "signature":signature,

        "payload":payload,

    }


def verify_truth_anchor(

    truth_anchor:

    Mapping[str,Any],

)->bool:

    payload=truth_anchor.get(

        "payload"

    )

    signature=truth_anchor.get(

        "signature"

    )

    return verify_signature(

        payload,

        signature,

    )


def evaluate_truth_state(

    truth_anchor:

    Mapping[str,Any],

)->Dict[str,Any]:

    verified=

    verify_truth_anchor(

        truth_anchor

    )

    if not verified:

        return {

            "allowed":False,

            "reason":

            "TRUTH_INVALID",

        }

    payload=truth_anchor.get(

        "payload",

        {},

    )

    freshness=payload.get(

        "freshness_state"

    )

    if freshness!="VALID":

        return {

            "allowed":False,

            "reason":

            f"FRESHNESS_{freshness}",

        }

    threshold=payload.get(

        "threshold_state"

    )

    if threshold!="SATISFIED":

        return {

            "allowed":False,

            "reason":

            "CORROBORATION_FAILURE",

        }

    return {

        "allowed":True,

        "truth_verified":True,

  }
