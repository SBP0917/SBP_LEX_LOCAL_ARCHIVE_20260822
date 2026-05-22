from __future__ import annotations

from typing import Any
from typing import Dict
from typing import Mapping


REQUIRED_EXECUTION_REQUIREMENTS=[

    "authority_verified",

    "truth_verified",

    "classification_verified",

    "license_verified",

    "governance_verified",

    "domain_verified",

    "runtime_verified",

    "master_token",

    "execution_attestation",

]


FAIL_CLOSED_DECISION="DENY"


def evaluate_execution_gate(

    execution_state:

    Mapping[str,Any],

)->Dict[str,Any]:

    failures=[]

    for field in (

        REQUIRED_EXECUTION_REQUIREMENTS

    ):

        value=(

            execution_state.get(

                field

            )

        )

        if value in [

            None,

            False,

            "",

        ]:

            failures.append(

                field

            )

    if failures:

        return {

            "allowed":False,

            "decision":

            FAIL_CLOSED_DECISION,

            "reason":

            "EXECUTION_REQUIREMENTS_FAILED",

            "failures":

            failures,

        }

    return {

        "allowed":True,

        "decision":

        execution_state.get(

            "decision",

            "ALLOW",

        ),

        "execution_verified":

        True,

    }


def validate_execution_integrity(

    execution_state:

    Mapping[str,Any],

)->Dict[str,Any]:

    required=[

        "state_hash",

        "audit_hash",

        "convergence_hash",

        "pipeline_mode",

    ]

    failures=[]

    for field in required:

        if (

            execution_state.get(

                field

            )

            is None

        ):

            failures.append(

                field

            )

    if failures:

        return {

            "valid":False,

            "failures":

            failures,

        }

    return {

        "valid":True,

    }


def enforce_execution_boundary(

    execution_state:

    Mapping[str,Any],

)->Dict[str,Any]:

    gate=(

        evaluate_execution_gate(

            execution_state

        )

    )

    integrity=(

        validate_execution_integrity(

            execution_state

        )

    )

    if (

        not gate[

            "allowed"

        ]

        or

        not integrity[

            "valid"

        ]

    ):

        return {

            "allowed":False,

            "decision":

            FAIL_CLOSED_DECISION,

            "boundary_locked":

            True,

        }

    return {

        "allowed":True,

        "boundary_locked":

        False,

  }
