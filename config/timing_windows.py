from __future__ import annotations

from datetime import datetime
from typing import Any
from typing import Dict
from typing import Mapping


DEFAULT_STAGE_WINDOWS = {

    "hard_entry_gate": 2,

    "state_construction": 3,

    "collective_attachment": 3,

    "root_of_trust": 5,

    "procedural_truth": 5,

    "classification": 3,

    "licensing": 3,

    "governance": 5,

    "grc": 3,

    "domain_wrap": 3,

    "aurion": 5,

    "execution_gate": 3,

    "audit": 3,

}


def validate_timing_window(

    *,

    stage: str,

    start_time: datetime,

    end_time: datetime,

    limits:

    Mapping[

        str,

        int,

    ]

    |

    None = None,

) -> Dict[

    str,

    Any,

]:

    windows = (

        limits

        or

        DEFAULT_STAGE_WINDOWS

    )

    maximum = windows.get(

        stage,

        5,

    )

    elapsed = (

        end_time

        -

        start_time

    ).total_seconds()

    valid = (

        elapsed

        <=

        maximum

    )

    return {

        "stage":

        stage,

        "elapsed":

        elapsed,

        "limit":

        maximum,

        "valid":

        valid,

        "action":

        (

            "ALLOW"

            if valid

            else

            "ESCALATE"

        ),

    }


def validate_pipeline_windows(

    timings:

    Mapping[

        str,

        tuple[

            datetime,

            datetime,

        ],

    ],

) -> Dict[

    str,

    Any,

]:

    failures = []

    results = {}

    for (

        stage,

        values,

    ) in timings.items():

        start,

        end = values

        result = (

            validate_timing_window(

                stage=stage,

                start_time=start,

                end_time=end,

            )

        )

        results[

            stage

        ] = result

        if (

            not

            result[

                "valid"

            ]

        ):

            failures.append(

                stage

            )

    return {

        "valid":

        len(

            failures

        )

        ==

        0,

        "failures":

        failures,

        "results":

        results,

      }
