from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from typing import Any
from typing import Dict
from typing import Mapping
from typing import List

from sbp_lex.security.pqc import generate_digest


class PipelineReplayLedger:

    def __init__(

        self,

    ) -> None:

        self._ledger: List[
            Dict[str, Any]
        ] = []


    def append(

        self,

        state: Mapping[
            str,
            Any,
        ],

    ) -> Dict[str, Any]:

        entry = {

            "timestamp":

            datetime.utcnow().isoformat(),

            "request_fingerprint":

            state.get(

                "request_fingerprint"

            ),

            "pipeline_mode":

            state.get(

                "pipeline_mode"

            ),

            "decision":

            state.get(

                "decision"

            ),

            "state_hash":

            state.get(

                "state_hash"

            ),

            "audit_hash":

            state.get(

                "audit_hash"

            ),

            "convergence_hash":

            state.get(

                "pipeline_convergence",

                {},

            ).get(

                "convergence_hash"

            ),

        }

        entry[

            "ledger_hash"

        ] = generate_digest(

            entry

        )

        self._ledger.append(

            deepcopy(

                entry

            )

        )

        return entry


    def verify(

        self,

    ) -> tuple[

        bool,

        list[str],

    ]:

        failures = []

        for (

            index,

            item,

        ) in enumerate(

            self._ledger

        ):

            rebuilt = {

                key:

                value

                for (

                    key,

                    value,

                )

                in item.items()

                if key

                !=

                "ledger_hash"

            }

            rebuilt_hash = (

                generate_digest(

                    rebuilt

                )

            )

            if (

                rebuilt_hash

                !=

                item.get(

                    "ledger_hash"

                )

            ):

                failures.append(

                    f"ledger_corruption:{index}"

                )

        return (

            len(

                failures

            )

            == 0,

            failures,

        )


    def export(

        self,

    ) -> List[

        Dict[

            str,

            Any,

        ]

    ]:

        return deepcopy(

            self._ledger

        )


    def size(

        self,

    ) -> int:

        return len(

            self._ledger

      )
