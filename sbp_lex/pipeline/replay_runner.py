from __future__ import annotations

from copy import deepcopy
from typing import Any
from typing import Dict
from typing import Mapping

from sbp_lex.pipeline.dual_runner import run_dual_pipeline
from sbp_lex.security.pqc import generate_digest


REPLAY_COMPARISON_FIELDS = [

    "request_fingerprint",

    "state_hash",

    "pipeline_mode",

    "decision",

    "execution_result",

    "audit_hash",

]


def run_replay_check(

    *,

    request: Mapping[str, Any],

    pre_context_signals: Mapping[str, Any] | None = None,

    replay_count: int = 2,

) -> Dict[str, Any]:

    if replay_count < 2:

        replay_count = 2

    replay_runs = []

    for _ in range(replay_count):

        result = run_dual_pipeline(

            deepcopy(dict(request)),

            deepcopy(
                dict(pre_context_signals)
            )
            if pre_context_signals
            else None,

        )

        replay_runs.append(result)

    summaries = []

    for run in replay_runs:

        summaries.append(

            build_replay_summary(run)

        )

    reference = summaries[0]

    mismatches = []

    for index, summary in enumerate(

        summaries[1:],

        start=1,

    ):

        for field in REPLAY_COMPARISON_FIELDS:

            if (

                summary.get(field)

                !=

                reference.get(field)

            ):

                mismatches.append(

                    {

                        "run":

                        index,

                        "field":

                        field,

                        "expected":

                        reference.get(field),

                        "actual":

                        summary.get(field),

                    }

                )

    replay_payload = {

        "replay_count":

        replay_count,

        "matched":

        len(mismatches) == 0,

        "reference":

        reference,

        "runs":

        summaries,

        "mismatches":

        mismatches,

    }

    replay_hash = generate_digest(

        replay_payload

    )

    return {

        "matched":

        len(mismatches) == 0,

        "replay_hash":

        replay_hash,

        "reference":

        reference,

        "runs":

        summaries,

        "mismatches":

        mismatches,

    }


def build_replay_summary(

    state: Mapping[str, Any],

) -> Dict[str, Any]:

    convergence = state.get(

        "pipeline_convergence",

        {},

    )

    return {

        "request_fingerprint":

        state.get(

            "request_fingerprint"

        ),

        "state_hash":

        state.get(

            "state_hash"

        ),

        "pipeline_mode":

        state.get(

            "pipeline_mode"

        ),

        "decision":

        state.get(

            "decision"

        ),

        "execution_result":

        state.get(

            "execution_result"

        ),

        "audit_hash":

        state.get(

            "audit_hash"

        ),

        "convergence_hash":

        convergence.get(

            "convergence_hash"

        ),

                    }
