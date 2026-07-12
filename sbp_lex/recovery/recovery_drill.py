from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Sequence

from sbp_lex.security.pqc import generate_digest

from .backup import create_backup, validate_backup_package
from .common import RecoveryError, atomic_json, sha256_bytes
from .inventory import ArtifactSpec, build_inventory
from .restore import preflight_restore, restore_backup

DRILL_VERSION = "R1_DESKTOP_V1_RECOVERY_DRILL_V1"
DRILL_COMMIT = "1" * 40
DRILL_BASELINE = "DESKTOP_V1_R1_DRILL_BASELINE_01"
DRILL_RUNTIME_IDENTITY = "2" * 64


def _write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


def _ledger() -> bytes:
    records: list[dict[str, Any]] = []
    previous: str | None = None
    for sequence, event in ((1, "created"), (2, "sealed")):
        payload = {"sequence": sequence, "event": event, "previous_hash": previous}
        record = {**payload, "record_hash": generate_digest(payload)}
        records.append(record)
        previous = record["record_hash"]
    return b"".join(
        (json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        for item in records
    )


def _fixture(root: Path) -> tuple[Path, tuple[ArtifactSpec, ...]]:
    source = root / "source"
    values = {
        "configuration/config.json": b'{"mode":"desktop-v1","nodes":false}\n',
        "security/trust.json": b'{"identity":"local","state":"approved"}\n',
        "external/replay.jsonl": _ledger(),
        "execution/capabilities.jsonl": _ledger(),
        "audit/ledger.jsonl": _ledger(),
        "measured/baseline.json": b'{"baseline":"approved","generation":1}\n',
        "local_trust/evidence.json": b'{"status":"valid","changes":0}\n',
        "formal/assurance.json": b'{"authority":"non-authoritative","status":"valid"}\n',
    }
    for relative, raw in values.items():
        _write(source / relative, raw)
    specs = (
        ArtifactSpec("configuration.foundation", "configuration", "configuration/config.json", "configuration/config.json", "REQUIRED", "PUBLIC_EVIDENCE", "json", 1, None, 100, "strict_json", "configuration_authority"),
        ArtifactSpec("security.trust", "security_state", "security/trust.json", "security/trust.json", "REQUIRED", "PROTECTED_PRIVATE", "json", 1, None, 200, "strict_json", "security_authority"),
        ArtifactSpec("external.replay", "external_identity_replay", "external/replay.jsonl", "external/replay.jsonl", "REQUIRED", "PROTECTED_PRIVATE", "jsonl", 1, None, 300, "jsonl_hash_chain", "external_authority"),
        ArtifactSpec("execution.capabilities", "execution_integrity", "execution/capabilities.jsonl", "execution/capabilities.jsonl", "REQUIRED", "PROTECTED_PRIVATE", "jsonl", 1, None, 400, "jsonl_hash_chain", "execution_authority"),
        ArtifactSpec("audit.ledger", "audit_attestations", "audit/ledger.jsonl", "audit/ledger.jsonl", "REQUIRED", "PROTECTED_PRIVATE", "jsonl", 1, None, 500, "jsonl_hash_chain", "audit_authority"),
        ArtifactSpec("measured.baseline", "measured_startup", "measured/baseline.json", "measured/baseline.json", "REQUIRED", "PUBLIC_EVIDENCE", "json", 1, None, 600, "strict_json", "measured_authority"),
        ArtifactSpec("local_trust.evidence", "local_trust", "local_trust/evidence.json", "local_trust/evidence.json", "REQUIRED", "PUBLIC_EVIDENCE", "json", 1, None, 700, "strict_json", "local_trust_authority"),
        ArtifactSpec("formal.assurance", "formal_assurance", "formal/assurance.json", "formal/assurance.json", "REQUIRED", "PUBLIC_EVIDENCE", "json", 1, None, 800, "strict_json", "formal_authority"),
    )
    return source, specs


def run_recovery_drill(root: Path) -> dict[str, Any]:
    drill_root = root.resolve(strict=False)
    if drill_root.exists() and any(drill_root.iterdir()):
        raise RecoveryError("recovery_drill_root_not_empty")
    drill_root.mkdir(parents=True, exist_ok=True)
    source, specs = _fixture(drill_root)
    inventory = build_inventory(source, specs)
    backup = drill_root / "sealed_backup"
    manifest = create_backup(
        source,
        inventory,
        backup,
        repository_commit=DRILL_COMMIT,
        measured_baseline_identifier=DRILL_BASELINE,
        runtime_identity=DRILL_RUNTIME_IDENTITY,
        generation=1,
        approved_backup_root=drill_root,
        creation_timestamp="2026-01-01T00:00:00+00:00",
    )
    verified = validate_backup_package(backup)
    destination_root = drill_root / "approved_restore_roots"
    destination_root.mkdir()
    destination = destination_root / "restored"
    preflight_restore(
        backup,
        destination,
        approved_destination_root=destination_root,
        expected_repository_commit=DRILL_COMMIT,
        expected_measured_baseline_identifier=DRILL_BASELINE,
        expected_runtime_identity=DRILL_RUNTIME_IDENTITY,
    )
    restored = restore_backup(
        backup,
        destination,
        approved_destination_root=destination_root,
        expected_repository_commit=DRILL_COMMIT,
        expected_measured_baseline_identifier=DRILL_BASELINE,
        expected_runtime_identity=DRILL_RUNTIME_IDENTITY,
        fresh_process_commands=((
            sys.executable,
            "-c",
            "import json,os; from pathlib import Path; root=Path(os.environ['SBP_LEX_RECOVERY_GENERATION_ROOT']); assert json.loads((root/'configuration/config.json').read_text())['nodes'] is False",
        ),),
    )
    corrupt = drill_root / "corrupt_backup"
    shutil.copytree(backup, corrupt)
    first = verified["artefact_inventory"]["artefacts"][0]
    corrupt_member = corrupt / "domains" / first["authority_domain"] / first["sensitivity_class"].lower() / first["relative_recovery_path"]
    corrupt_member.write_bytes(corrupt_member.read_bytes() + b"corrupt")
    corruption_rejected = False
    try:
        validate_backup_package(corrupt)
    except RecoveryError:
        corruption_rejected = True
    replay_rejected = False
    try:
        restore_backup(
            backup,
            destination,
            approved_destination_root=destination_root,
            expected_repository_commit=DRILL_COMMIT,
            expected_measured_baseline_identifier=DRILL_BASELINE,
            expected_runtime_identity=DRILL_RUNTIME_IDENTITY,
        )
    except RecoveryError:
        replay_rejected = True
    if not corruption_rejected or not replay_rejected:
        raise RecoveryError("recovery_drill_adversarial_failure")
    result = {
        "drill_version": DRILL_VERSION,
        "status": "RECOVERY_DRILL_PASS",
        "backup_identifier": manifest["backup_identifier"],
        "inventory_digest": inventory["aggregate_digest"],
        "manifest_digest": verified["aggregate_digest"],
        "restored_generation": restored["generation"],
        "restored_artefacts": restored["artefact_count"],
        "fresh_process_validated": len(restored["fresh_process_results"]) == 1,
        "corruption_rejected": corruption_rejected,
        "replay_rejected": replay_rejected,
        "live_state_modified": False,
    }
    result["result_digest"] = generate_digest(result)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the bounded Desktop V1 local recovery drill")
    parser.add_argument("--root", required=True)
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    result = run_recovery_drill(Path(args.root))
    if args.output:
        atomic_json(Path(args.output).resolve(strict=False), result)
    print("RECOVERY_DRILL_PASS")
    print(f"backup_identifier={result['backup_identifier']}")
    print(f"result_digest={result['result_digest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
