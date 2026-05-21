from __future__ import annotations

from copy import deepcopy
from typing import Any
from typing import Dict
from typing import Mapping

from sbp_lex.security.pqc import generate_digest


FREEZE_STAGES = {

    "root_of_trust",

    "classification",

    "licensing",

    "governance",

    "domain_wrap",

    "aurion_runtime",

    "execution_gate",

    "audit",

}


def freeze_state_section(

    state: Mapping[str, Any],

    *,

    stage: str,

    section: Mapping[str, Any],

) -> Dict[str, Any]:

    if stage not in FREEZE_STAGES:

        raise ValueError(

            f"Invalid freeze stage: {stage}"

        )

    working_state = deepcopy(

        dict(state)

    )

    frozen_section = deepcopy(

        dict(section)

    )

    section_hash = generate_digest(

        {

            "stage": stage,

            "section": frozen_section,

        }

    )

    working_state.setdefault(

        "frozen_sections",

        {},

    )[stage] = {

        "stage":

        stage,

        "section_hash":

        section_hash,

        "section":

        frozen_section,

    }

    working_state.setdefault(

        "audit_trace",

        [],

    ).append(

        {

            "stage":

            stage,

            "event":

            "STATE_SECTION_FROZEN",

            "section_hash":

            section_hash,

        }

    )

    return working_state


def verify_frozen_sections(

    state: Mapping[str, Any],

) -> tuple[bool, list[str]]:

    failures = []

    frozen_sections = state.get(

        "frozen_sections",

        {},

    )

    if not isinstance(

        frozen_sections,

        Mapping,

    ):

        return (

            False,

            [

                "frozen_section_invalid"

            ],

        )

    for (

        stage,

        frozen,

    ) in frozen_sections.items():

        rebuilt_hash = generate_digest(

            {

                "stage":

                stage,

                "section":

                frozen.get(

                    "section"

                ),

            }

        )

        if (

            rebuilt_hash

            !=

            frozen.get(

                "section_hash"

            )

        ):

            failures.append(

                f"frozen_section_hash_mismatch:{stage}"

            )

    return (

        len(failures) == 0,

        failures,

)
