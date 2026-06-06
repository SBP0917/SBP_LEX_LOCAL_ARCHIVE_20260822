from __future__ import annotations

from typing import Any
from typing import Dict
from typing import Mapping


FAIL_CLOSED_UNKNOWN = "UNKNOWN"

REQUIRED_STATE_FIELDS = [

    "request_fingerprint",

    "state_hash",

    "pipeline_mode",

    "decision",

]

VALID_DECISIONS = [

    "ALLOW",

    "DENY",

    "ESCALATE",

]


def validate_fail_closed(

    state: Mapping[
        str,
        Any,
    ],

) -> Dict[
    str,
    Any,
]:

    failures = []

    for field in (

        REQUIRED_STATE_FIELDS

    ):

        value = state.get(

            field

        )

        if (

            value is None

            or

            value == ""

        ):

            failures.append(

                f"MISSING:{field}"

            )

            continue

        if (

            value

            ==

            FAIL_CLOSED_UNKNOWN

        ):

            failures.append(

                f"UNKNOWN:{field}"

            )

    decision = state.get(

        "decision"

    )

    if (

        decision

        not in

        VALID_DECISIONS

    ):

        failures.append(

            "INVALID_DECISION"

        )

    hash_chain = state.get(

        "hash_chain"

    )

    if (

        not hash_chain

    ):

        failures.append(

            "HASH_CHAIN_MISSING"

        )

    frozen_sections = state.get(

        "frozen_sections"

    )

    if (

        frozen_sections

        is None

    ):

        failures.append(

            "FREEZE_LAYER_MISSING"

        )

    if failures:

        return {

            "allowed":

            False,

            "decision":

            "DENY",

            "fail_closed":

            True,

            "failures":

            failures,

        }

    return {

        "allowed":

        True,

        "decision":

        state.get(

            "decision"

        ),

        "fail_closed":

        False,

        "failures":

        [],

    }


def force_fail_closed(

    reason: str,

) -> Dict[

    str,

    Any,

]:

    return {

        "allowed":

        False,

        "decision":

        "DENY",

        "fail_closed":

        True,

        "reason":

        reason,

  }
