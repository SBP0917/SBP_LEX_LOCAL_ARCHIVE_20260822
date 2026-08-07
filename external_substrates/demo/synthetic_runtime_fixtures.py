from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from external_substrates.shared.digest import digest_mapping
from external_substrates.shared.signing import sign_payload
from external_substrates.shared.synthetic_runtime import canonical_package


def _reseal(package: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(dict(package))
    body = {
        key: deepcopy(value)
        for key, value in result.items()
        if key not in {"digest", "signature"}
    }
    result["digest"] = digest_mapping(body)
    result["signature"] = sign_payload({
        key: deepcopy(value)
        for key, value in result.items()
        if key != "signature"
    })
    return result


def build_controlled_fixture_set(
    skg_package: Mapping[str, Any],
    dtn_package: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    """Return the named deterministic Pass 2 raw-external fixture corpus."""
    skg = deepcopy(dict(skg_package))
    dtn = deepcopy(dict(dtn_package))

    request_mismatch = deepcopy(dtn)
    request_mismatch["request_fingerprint"] = "mismatched-request"
    request_mismatch = _reseal(request_mismatch)

    eie_mismatch = deepcopy(dtn)
    eie_mismatch["eie_digest"] = "0" * 64
    eie_mismatch = _reseal(eie_mismatch)

    digest_mismatch = deepcopy(skg)
    digest_mismatch["digest"] = "0" * 64

    signature_mismatch = deepcopy(dtn)
    signature_mismatch["signature"] = "f" * 64

    jurisdiction_conflict = deepcopy(dtn)
    jurisdiction_conflict["jurisdiction"]["jurisdiction_id"] = "CONFLICT"
    jurisdiction_conflict = _reseal(jurisdiction_conflict)

    authority_conflict = deepcopy(dtn)
    authority_conflict["authority_reference"] = "conflicting-authority"
    authority_conflict = _reseal(authority_conflict)

    forbidden_authority = deepcopy(skg)
    forbidden_authority["runtime_authority"] = "external"
    forbidden_authority = _reseal(forbidden_authority)

    valid = {
        "raw_skg": canonical_package(skg),
        "raw_dtn": canonical_package(dtn),
    }
    return {
        "valid_skg_package": {"raw_skg": valid["raw_skg"]},
        "valid_dtn_package": {"raw_dtn": valid["raw_dtn"]},
        "valid_paired_package": deepcopy(valid),
        "malformed_package": {"raw_skg": "{", "raw_dtn": valid["raw_dtn"]},
        "stale_package": {
            **deepcopy(valid),
            "validation_time": "2026-08-07T00:05:01Z",
        },
        "replayed_package": {**deepcopy(valid), "repeat_count": 2},
        "request_mismatch": {
            "raw_skg": valid["raw_skg"],
            "raw_dtn": canonical_package(request_mismatch),
        },
        "eie_mismatch": {
            "raw_skg": valid["raw_skg"],
            "raw_dtn": canonical_package(eie_mismatch),
        },
        "digest_mismatch": {
            "raw_skg": canonical_package(digest_mismatch),
            "raw_dtn": valid["raw_dtn"],
        },
        "signature_mismatch": {
            "raw_skg": valid["raw_skg"],
            "raw_dtn": canonical_package(signature_mismatch),
        },
        "jurisdiction_conflict": {
            "raw_skg": valid["raw_skg"],
            "raw_dtn": canonical_package(jurisdiction_conflict),
        },
        "authority_conflict": {
            "raw_skg": valid["raw_skg"],
            "raw_dtn": canonical_package(authority_conflict),
        },
        "forbidden_authority_leakage": {
            "raw_skg": canonical_package(forbidden_authority),
            "raw_dtn": valid["raw_dtn"],
        },
        "provider_mode_activation_attempt": {
            **deepcopy(valid),
            "provider_configuration": {
                "provider_mode": "live",
                "url": "https://provider.example",
                "api_key": "forbidden",
                "production_sensor_feed": True,
            },
        },
    }
