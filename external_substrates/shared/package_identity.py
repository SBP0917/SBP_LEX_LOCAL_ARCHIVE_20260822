from __future__ import annotations

from typing import Sequence

from external_substrates.shared.digest import digest_mapping


def package_identity(
    *, package_type: str, package_version: str, request_fingerprint: str,
    issued_at: str, source_digests: Sequence[str], transport_identity: str,
) -> str:
    return digest_mapping(
        {
            "package_type": package_type,
            "package_version": package_version,
            "request_fingerprint": request_fingerprint,
            "issued_at": issued_at,
            "source_digests": sorted(source_digests),
            "transport_identity": transport_identity,
        }
    )
