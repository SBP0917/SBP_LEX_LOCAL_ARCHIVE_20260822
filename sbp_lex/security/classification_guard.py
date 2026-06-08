from __future__ import annotations

from typing import Any
from typing import Dict
from typing import Mapping

from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.pqc import sign_payload
from sbp_lex.security.pqc import verify_signature


REQUIRED_CLASSIFICATION_FIELDS=[

    "autonomy_class",

    "operational_scope",

    "environment_modifier",

    "deployment_authority",

    "classification_state",

]


VALID_CLASSIFICATION_STATES=[

    "VALID",

    "DENIED",

    "RESTRICTED",

]


def build_classification_guard(

    classification:

    Mapping[str,Any],

)->Dict[str,Any]:

    missing=[]

    for field in REQUIRED_CLASSIFICATION_FIELDS:

        if classification.get(field) is None:

            missing.append(field)

    if missing:

        return {

            "valid":False,

            "reason":"CLASSIFICATION_FIELDS_MISSING",

            "missing":missing,

        }

    state=classification.get(

        "classification_state"

    )

    if (

        state

        not in

        VALID_CLASSIFICATION_STATES

    ):

        return {

            "valid":False,

            "reason":

            "INVALID_CLASSIFICATION_STATE",

        }

    payload={

        field:

        classification.get(field)

        for field

        in REQUIRED_CLASSIFICATION_FIELDS

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

        "classification_hash":digest,

        "signature":signature,

        "payload":payload,

    }


def verify_classification_guard(

    classification_guard:

    Mapping[str,Any],

)->bool:

    payload=(

        classification_guard.get(

            "payload"

        )

    )

    signature=(

        classification_guard.get(

            "signature"

        )

    )

    return verify_signature(

        payload,

        signature,

    )


def evaluate_classification(

    classification_guard:

    Mapping[str,Any],

)->Dict[str,Any]:

    verified=(

        verify_classification_guard(

            classification_guard

        )

    )

    if not verified:

        return {

            "allowed":False,

            "reason":

            "CLASSIFICATION_INVALID",

        }

    payload=(

        classification_guard.get(

            "payload",

            {},

        )

    )

    state=payload.get(

        "classification_state"

    )

    if state!="VALID":

        return {

            "allowed":False,

            "reason":

            f"CLASSIFICATION_{state}",

        }

    return {

        "allowed":True,

        "classification_verified":True,

  }
