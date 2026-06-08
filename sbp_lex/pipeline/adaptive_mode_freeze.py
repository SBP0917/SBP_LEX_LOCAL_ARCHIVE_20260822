from __future__ import annotations

from copy import deepcopy
from typing import Any
from typing import Dict
from typing import Mapping

from sbp_lex.security.pqc import generate_digest


ALLOWED_PIPELINE_MODES = [

    "MODE_1_FULL_MIRRORED",

    "MODE_2_SPLIT_VALIDATOR",

    "MODE_3_SINGLE_CONSTRAINED",

]


def freeze_pipeline_mode(

    state: Mapping[
        str,
        Any,
    ],

) -> Dict[
    str,
    Any,
]:

    working = deepcopy(

        dict(

            state

        )

    )

    mode = working.get(

        "pipeline_mode"

    )

    if (

        mode

        not in

        ALLOWED_PIPELINE_MODES

    ):

        return {

            "valid":

            False,

            "reason":

            "INVALID_PIPELINE_MODE",

            "allowed_modes":

            ALLOWED_PIPELINE_MODES,

        }

    freeze_hash = (

        generate_digest(

            {

                "request":

                working.get(

                    "request_fingerprint"

                ),

                "mode":

                mode,

                "state_hash":

                working.get(

                    "state_hash"

                ),

            }

        )

    )

    working[

        "adaptive_mode_freeze"

    ] = {

        "pipeline_mode":

        mode,

        "freeze_hash":

        freeze_hash,

        "locked":

        True,

    }

    return {

        "valid":

        True,

        "freeze":

        working[

            "adaptive_mode_freeze"

        ],

    }


def verify_pipeline_mode(

    state: Mapping[

        str,

        Any,

    ],

) -> bool:

    freeze = state.get(

        "adaptive_mode_freeze"

    )

    if (

        not freeze

    ):

        return False

    rebuilt = (

        generate_digest(

            {

                "request":

                state.get(

                    "request_fingerprint"

                ),

                "mode":

                state.get(

                    "pipeline_mode"

                ),

                "state_hash":

                state.get(

                    "state_hash"

                ),

            }

        )

    )

    return (

        rebuilt

        ==

        freeze.get(

            "freeze_hash"

        )

    )


def enforce_mode_lock(

    state: Mapping[

        str,

        Any,

    ],

) -> Dict[

    str,

    Any,

]:

    valid = (

        verify_pipeline_mode(

            state

        )

    )

    if (

        not valid

    ):

        return {

            "allowed":

            False,

            "reason":

            "PIPELINE_MODE_DRIFT",

        }

    return {

        "allowed":

        True,

  }
