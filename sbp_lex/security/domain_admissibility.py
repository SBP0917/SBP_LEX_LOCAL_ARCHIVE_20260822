from __future__ import annotations

from typing import Any
from typing import Dict
from typing import Mapping

from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.pqc import sign_payload
from sbp_lex.security.pqc import verify_signature


REQUIRED_DOMAIN_FIELDS=[

    "legal_domain",

    "operational_domain",

    "risk_domain",

    "environment_state",

    "domain_state",

]


VALID_DOMAIN_STATES=[

    "VALID",

    "DENIED",

    "ESCALATED",

]


def build_domain_admissibility(

    domain:

    Mapping[str,Any],

)->Dict[str,Any]:

    missing=[]

    for field in REQUIRED_DOMAIN_FIELDS:

        if domain.get(field) is None:

            missing.append(field)

    if missing:

        return {

            "valid":False,

            "reason":

            "DOMAIN_FIELDS_MISSING",

            "missing":missing,

        }

    state=domain.get(

        "domain_state"

    )

    if state not in VALID_DOMAIN_STATES:

        return {

            "valid":False,

            "reason":

            "INVALID_DOMAIN_STATE",

        }

    payload={

        field:

        domain.get(field)

        for field

        in REQUIRED_DOMAIN_FIELDS

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

        "reason":"NON_CANONICAL_DOMAIN_HELPER_NO_AUTHORITY",

        "integrity_verified":verified,

        "execution_convergence_eligible":False,

        "domain_hash":digest,

        "signature":signature,

        "payload":payload,

    }


def verify_domain(

    domain_record:

    Mapping[str,Any],

)->bool:

    payload=(

        domain_record.get(

            "payload"

        )

    )

    signature=(

        domain_record.get(

            "signature"

        )

    )

    return verify_signature(

        payload,

        signature,

    )


def evaluate_domain(

    domain_record:

    Mapping[str,Any],

)->Dict[str,Any]:

    verified=(

        verify_domain(

            domain_record

        )

    )

    if not verified:

        return {

            "allowed":False,

            "reason":

            "DOMAIN_INVALID",

        }

    return {

        "allowed":False,

        "reason":"NON_CANONICAL_DOMAIN_HELPER_NO_AUTHORITY",

        "integrity_verified":True,

        "execution_convergence_eligible":False,

}
