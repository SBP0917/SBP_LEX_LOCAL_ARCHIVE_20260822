from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from typing import Any
from typing import Dict
from typing import List
from typing import Mapping

from sbp_lex.security.pqc import generate_digest


class DivergenceRegistry:

    def __init__(

        self,

    ) -> None:

        self._registry: List[
            Dict[str, Any]
        ] = []


    def register(

        self,

        *,

        divergence_type: str,

        stage: str,

        expected: Any,

        actual: Any,

        severity: str,

        request_fingerprint:

        str |

        None = None,

    ) -> Dict[str, Any]:

        record = {

            "timestamp":

            datetime.utcnow().isoformat(),

            "divergence_type":

            divergence_type,

            "stage":

            stage,

            "expected":

            deepcopy(

                expected

            ),

            "actual":

            deepcopy(

                actual

            ),

            "severity":

            severity,

            "request_fingerprint":

            request_fingerprint,

        }

        record[

            "divergence_hash"

        ] = generate_digest(

            record

        )

        self._registry.append(

            record

        )

        return record


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

            self._registry

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

                "divergence_hash"

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

                    "divergence_hash"

                )

            ):

                failures.append(

                    f"DIVERGENCE_REGISTRY_CORRUPTION:{index}"

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

            self._registry

        )


    def count(

        self,

    ) -> int:

        return len(

            self._registry

        )


    def by_severity(

        self,

        severity:

        str,

    ) -> List[

        Dict[

            str,

            Any,

        ]

    ]:

        return [

            item

            for item

            in self._registry

            if (

                item.get(

                    "severity"

                )

                ==

                severity

            )

          ]
