from __future__ import annotations

from typing import Any
from typing import Dict
from typing import Mapping

from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.pqc import sign_payload
from sbp_lex.security.pqc import verify_signature


REQUIRED_THRESHOLDS = [

    "consequentiality",

    "financial",

    "corroboration",

    "autonomy_boundary",

    "escalation",

]


def build_threshold_bundle(

    thresholds: Mapping[
        str,
        Any,
    ],

) -> Dict[
    str,
    Any,
]:

    missing = []

    for threshold in (

        REQUIRED_THRESHOLDS

    ):

        if (

            threshold

            not in

            thresholds

        ):

            missing.append(

                threshold

            )

    if missing:

        return {

            "valid":

            False,

            "reason":

            "THRESHOLD_MISSING",

            "missing":

            missing,

        }

    payload = {

        threshold:

        thresholds.get(

            threshold

        )

        for threshold

        in REQUIRED_THRESHOLDS

    }

    digest = (

        generate_digest(

            payload

        )

    )

    signature = (

        sign_payload(

            payload

        )

    )

    verified = (

        verify_signature(

            payload,

            signature,

        )

    )

    return {

        "valid":

        verified,

        "bundle_digest":

        digest,

        "signature":

        signature,

        "payload":

        payload,

    }


def verify_threshold_bundle(

    thresholds:

    Mapping[

        str,

        Any,

    ],

    threshold_bundle:

    Mapping[

        str,

        Any,

    ],

) -> bool:

    rebuilt = (

        build_threshold_bundle(

            thresholds

        )

    )

    return (

        rebuilt.get(

            "bundle_digest"

        )

        ==

        threshold_bundle.get(

            "bundle_digest"

        )

    )
