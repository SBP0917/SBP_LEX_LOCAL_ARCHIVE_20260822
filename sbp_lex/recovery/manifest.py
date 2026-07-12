from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Mapping

from sbp_lex.security.pqc import generate_digest

from .common import (
    AUTHORITY_DOMAINS,
    DESKTOP_SCOPE,
    HEX40,
    HEX64,
    IDENTIFIER,
    RECOVERY_VERSION,
    RecoveryError,
    bound_payload,
    validate_bound,
)
from .inventory import validate_inventory

MANIFEST_VERSION = "R1_DESKTOP_V1_SEALED_BACKUP_MANIFEST_V1"
DOMAIN_MANIFEST_VERSION = "R1_DESKTOP_V1_DOMAIN_MANIFEST_V1"
MANIFEST_FIELDS = frozenset({
    "manifest_version", "recovery_version", "desktop_scope", "backup_identifier",
    "repository_commit", "measured_baseline_identifier", "runtime_identity",
    "creation_timestamp", "generation", "predecessor_backup_identifier",
    "authority_domains", "artefact_inventory", "domain_manifests", "aggregate_digest",
})
DOMAIN_FIELDS = frozenset({
    "domain_manifest_version", "authority_domain", "generation", "artefacts", "domain_digest"
})


def _timestamp(value: str | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise RecoveryError("backup_timestamp_invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise RecoveryError("backup_timestamp_invalid")
    return parsed.replace(microsecond=0).isoformat()


def _domain_manifests(inventory: Mapping[str, Any], generation: int) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for artefact in inventory["artefacts"]:
        grouped.setdefault(artefact["authority_domain"], []).append({
            "logical_name": artefact["logical_name"],
            "relative_recovery_path": artefact["relative_recovery_path"],
            "digest": artefact["current_digest"],
            "sequence": artefact["sequence"],
            "predecessor_identity": artefact["predecessor_identity"],
        })
    results: list[dict[str, Any]] = []
    for domain in AUTHORITY_DOMAINS:
        if domain not in grouped:
            continue
        payload = {
            "domain_manifest_version": DOMAIN_MANIFEST_VERSION,
            "authority_domain": domain,
            "generation": generation,
            "artefacts": sorted(grouped[domain], key=lambda item: item["logical_name"]),
        }
        payload["domain_digest"] = generate_digest(payload)
        results.append(payload)
    return results


def create_manifest(
    inventory: Mapping[str, Any], *, repository_commit: str,
    measured_baseline_identifier: str, runtime_identity: str, generation: int,
    creation_timestamp: str | None = None,
    predecessor_backup_identifier: str | None = None,
    backup_identifier: str | None = None,
) -> dict[str, Any]:
    checked = validate_inventory(inventory)
    timestamp = _timestamp(creation_timestamp)
    if not isinstance(repository_commit, str) or not HEX40.fullmatch(repository_commit):
        raise RecoveryError("repository_commit_invalid")
    if not isinstance(measured_baseline_identifier, str) or not IDENTIFIER.fullmatch(measured_baseline_identifier):
        raise RecoveryError("measured_baseline_identifier_invalid")
    if not isinstance(runtime_identity, str) or not HEX64.fullmatch(runtime_identity):
        raise RecoveryError("runtime_identity_invalid")
    if not isinstance(generation, int) or generation <= 0:
        raise RecoveryError("backup_generation_invalid")
    if predecessor_backup_identifier is not None and not IDENTIFIER.fullmatch(predecessor_backup_identifier):
        raise RecoveryError("predecessor_backup_identifier_invalid")
    identity_seed = {
        "repository_commit": repository_commit,
        "measured_baseline_identifier": measured_baseline_identifier,
        "runtime_identity": runtime_identity,
        "generation": generation,
        "creation_timestamp": timestamp,
        "inventory_digest": checked["aggregate_digest"],
        "predecessor_backup_identifier": predecessor_backup_identifier,
    }
    expected_identifier = f"R1_BACKUP_{generation:08d}_{generate_digest(identity_seed)[:24].upper()}"
    identifier = backup_identifier or expected_identifier
    if identifier != expected_identifier or not IDENTIFIER.fullmatch(identifier):
        raise RecoveryError("backup_identifier_invalid")
    domains = _domain_manifests(checked, generation)
    payload = {
        "manifest_version": MANIFEST_VERSION,
        "recovery_version": RECOVERY_VERSION,
        "desktop_scope": DESKTOP_SCOPE,
        "backup_identifier": identifier,
        "repository_commit": repository_commit,
        "measured_baseline_identifier": measured_baseline_identifier,
        "runtime_identity": runtime_identity,
        "creation_timestamp": timestamp,
        "generation": generation,
        "predecessor_backup_identifier": predecessor_backup_identifier,
        "authority_domains": [item["authority_domain"] for item in domains],
        "artefact_inventory": checked,
        "domain_manifests": domains,
    }
    payload["aggregate_digest"] = generate_digest(payload)
    return bound_payload(payload)


def validate_manifest(value: Mapping[str, Any]) -> dict[str, Any]:
    payload = validate_bound(value, label="backup_manifest")
    if set(payload) != MANIFEST_FIELDS:
        raise RecoveryError("backup_manifest_payload_schema_invalid")
    if payload.get("manifest_version") != MANIFEST_VERSION or payload.get("recovery_version") != RECOVERY_VERSION:
        raise RecoveryError("backup_manifest_version_invalid")
    if payload.get("desktop_scope") != DESKTOP_SCOPE:
        raise RecoveryError("foreign_desktop_package")
    repository_commit = payload.get("repository_commit")
    runtime_identity = payload.get("runtime_identity")
    baseline = payload.get("measured_baseline_identifier")
    generation = payload.get("generation")
    timestamp = payload.get("creation_timestamp")
    predecessor = payload.get("predecessor_backup_identifier")
    if not isinstance(repository_commit, str) or not HEX40.fullmatch(repository_commit):
        raise RecoveryError("repository_commit_invalid")
    if not isinstance(runtime_identity, str) or not HEX64.fullmatch(runtime_identity):
        raise RecoveryError("runtime_identity_invalid")
    if not isinstance(baseline, str) or not IDENTIFIER.fullmatch(baseline):
        raise RecoveryError("measured_baseline_identifier_invalid")
    if not isinstance(generation, int) or generation <= 0:
        raise RecoveryError("backup_generation_invalid")
    _timestamp(timestamp)
    if predecessor is not None and (not isinstance(predecessor, str) or not IDENTIFIER.fullmatch(predecessor)):
        raise RecoveryError("predecessor_backup_identifier_invalid")
    inventory = validate_inventory(payload.get("artefact_inventory", {}))
    domains = payload.get("domain_manifests")
    authority_domains = payload.get("authority_domains")
    if not isinstance(domains, list) or not domains or not isinstance(authority_domains, list):
        raise RecoveryError("authority_domains_invalid")
    seen: set[str] = set()
    by_name = {item["logical_name"]: item for item in inventory["artefacts"]}
    covered: set[str] = set()
    for domain in domains:
        if not isinstance(domain, Mapping) or set(domain) != DOMAIN_FIELDS:
            raise RecoveryError("domain_manifest_schema_invalid")
        name = domain.get("authority_domain")
        if name not in AUTHORITY_DOMAINS or name in seen:
            raise RecoveryError("authority_domain_substitution")
        if domain.get("domain_manifest_version") != DOMAIN_MANIFEST_VERSION or domain.get("generation") != generation:
            raise RecoveryError("domain_manifest_generation_invalid")
        artefacts = domain.get("artefacts")
        if not isinstance(artefacts, list) or not artefacts:
            raise RecoveryError("domain_manifest_empty")
        for item in artefacts:
            if not isinstance(item, Mapping) or set(item) != {
                "logical_name", "relative_recovery_path", "digest", "sequence", "predecessor_identity"
            }:
                raise RecoveryError("domain_artefact_schema_invalid")
            source = by_name.get(item.get("logical_name"))
            if source is None or source["authority_domain"] != name:
                raise RecoveryError("authority_domain_substitution")
            expected = {
                "logical_name": source["logical_name"],
                "relative_recovery_path": source["relative_recovery_path"],
                "digest": source["current_digest"],
                "sequence": source["sequence"],
                "predecessor_identity": source["predecessor_identity"],
            }
            if dict(item) != expected or source["logical_name"] in covered:
                raise RecoveryError("domain_artefact_binding_invalid")
            covered.add(source["logical_name"])
        domain_payload = {key: json.loads(json.dumps(item)) for key, item in domain.items() if key != "domain_digest"}
        if domain.get("domain_digest") != generate_digest(domain_payload):
            raise RecoveryError("domain_manifest_digest_invalid")
        seen.add(str(name))
    if covered != set(by_name) or authority_domains != [item["authority_domain"] for item in domains]:
        raise RecoveryError("authority_domain_coverage_invalid")
    aggregate_payload = {key: json.loads(json.dumps(item)) for key, item in payload.items() if key != "aggregate_digest"}
    if payload.get("aggregate_digest") != generate_digest(aggregate_payload):
        raise RecoveryError("backup_aggregate_digest_invalid")
    seed = {
        "repository_commit": repository_commit,
        "measured_baseline_identifier": baseline,
        "runtime_identity": runtime_identity,
        "generation": generation,
        "creation_timestamp": timestamp,
        "inventory_digest": inventory["aggregate_digest"],
        "predecessor_backup_identifier": predecessor,
    }
    expected_identifier = f"R1_BACKUP_{generation:08d}_{generate_digest(seed)[:24].upper()}"
    if payload.get("backup_identifier") != expected_identifier:
        raise RecoveryError("backup_identifier_invalid")
    return payload
