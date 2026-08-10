from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence

from sbp_lex.config.environment import environment_security_report
from sbp_lex.recovery.common import atomic_json
from sbp_lex.security.pqc import (
    PQC_SIGNATURE_VERSION,
    generate_digest,
    pqc_provider_status,
    sign_payload,
    verify_signature,
)


ACTIVATION_PREFLIGHT_VERSION = "PASS9_PQC_OPERATOR_ACTIVATION_PREFLIGHT_V1"
TRUST_CLASSIFICATIONS = frozenset({
    "OWNER_AUTHORISED_OPERATOR",
    "ISOLATED_TEST_TRUST",
})


def build_activation_preflight(*, trust_classification: str) -> dict[str, Any]:
    if trust_classification not in TRUST_CLASSIFICATIONS:
        raise ValueError("activation_trust_classification_invalid")
    environment = environment_security_report()
    provider = pqc_provider_status()
    round_trip = False
    failure: str | None = None
    challenge = {
        "activation_preflight_version": ACTIVATION_PREFLIGHT_VERSION,
        "purpose": "NON_AUTHORITATIVE_SIGN_VERIFY_CHALLENGE",
        "trust_classification": trust_classification,
        "authority_granted": False,
    }
    try:
        signature = sign_payload(challenge)
        round_trip = (
            signature.get("signature_version") == PQC_SIGNATURE_VERSION
            and verify_signature(challenge, signature)
        )
    except Exception as exc:
        failure = type(exc).__name__
    private_key_material_recorded = False
    assertions = {
        "environment_security_valid": environment["valid"] is True,
        "provider_available": provider["provider_available"] is True,
        "trusted_signing_key_available": (
            provider["trusted_signing_key_available"] is True
        ),
        "migration_profile_ready": provider["migration_profile_ready"] is True,
        "sign_verify_round_trip": round_trip,
        "private_key_material_not_recorded": not private_key_material_recorded,
    }
    payload = {
        "activation_preflight_version": ACTIVATION_PREFLIGHT_VERSION,
        "trust_classification": trust_classification,
        "provider": provider["provider"],
        "provider_version": provider["provider_version"],
        "signature_algorithm": provider["signature_algorithm"],
        "crypto_profile_version": provider["crypto_profile_version"],
        "verification_policy_version": provider["verification_policy_version"],
        "trusted_signing_key_fingerprint": provider[
            "trusted_signing_key_fingerprint"
        ],
        "environment_warning_count": len(environment["warnings"]),
        "environment_warnings": environment["warnings"],
        "migration_profile_error": provider["migration_profile_error"],
        "round_trip_failure_class": failure,
        "assertions": assertions,
        "private_key_material_recorded": private_key_material_recorded,
        "runtime_authority_granted": False,
        "owner_authorisation_claim": (
            trust_classification == "OWNER_AUTHORISED_OPERATOR"
        ),
    }
    payload["pass_status"] = (
        "PASS" if all(payload["assertions"].values()) else "FAIL"
    )
    return {**payload, "preflight_digest": generate_digest(payload)}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Pass 9 operator activation preflight (records no private key)",
    )
    parser.add_argument(
        "--trust-classification",
        choices=tuple(sorted(TRUST_CLASSIFICATIONS)),
        required=True,
    )
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    result = build_activation_preflight(
        trust_classification=args.trust_classification,
    )
    if args.output:
        atomic_json(Path(args.output), result)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["pass_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
