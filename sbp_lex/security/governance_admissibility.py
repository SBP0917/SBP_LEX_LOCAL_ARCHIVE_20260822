from __future__ import annotations

from typing import Any
from typing import Dict
from typing import Mapping

from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.pqc import sign_payload
from sbp_lex.security.pqc import verify_signature


REQUIRED_GOVERNANCE_FIELDS=[

    "authority_state",

    "procedural_truth",

    "classification_state",

    "license_state",

    "risk_state",

    "governance_decision",

]


VALID_DECISIONS=[

    "ALLOW",

    "DENY",

    "ESCALATE",

]


def build_governance_admissibility(

    governance:

    Mapping[str,Any],

)->Dict[str,Any]:

    missing=[]

    for field in REQUIRED_GOVERNANCE_FIELDS:

        if governance.get(field) is None:

            missing.append(field)

    if missing:

        return {

            "valid":False,

            "reason":

            "GOVERNANCE_FIELDS_MISSING",

            "missing":missing,

        }

    decision=governance.get(

        "governance_decision"

    )

    if decision not in VALID_DECISIONS:

        return {

            "valid":False,

            "reason":

            "INVALID_DECISION",

        }

    payload={

        field:

        governance.get(field)

        for field

        in REQUIRED_GOVERNANCE_FIELDS

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

        "governance_hash":digest,

        "signature":signature,

        "payload":payload,

    }


def verify_governance(

    governance_record:

    Mapping[str,Any],

)->bool:

    payload=(

        governance_record.get(

            "payload"

        )

    )

    signature=(

        governance_record.get(

            "signature"

        )

    )

    return verify_signature(

        payload,

        signature,

    )


def evaluate_governance(

    governance_record:

    Mapping[str,Any],

)->Dict[str,Any]:

    verified=(

        verify_governance(

            governance_record

        )

    )

    if not verified:

        return {

            "allowed":False,

            "reason":

            "GOVERNANCE_INVALID",

        }

    payload=(

        governance_record.get(

            "payload",

            {},

        )

    )

    decision=payload.get(

        "governance_decision"

    )

    if decision!="ALLOW":

        return {

            "allowed":False,

            "reason":

            f"GOVERNANCE_{decision}",

        }

    return {

        "allowed":True,

        "governance_verified":True,

  }
