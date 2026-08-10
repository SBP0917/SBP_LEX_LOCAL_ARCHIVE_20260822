from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import tempfile
from pathlib import Path

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TEST_STORE = REPOSITORY_ROOT / "runtime_artifacts" / "pytest_integrity_store.jsonl"
TEST_CHECKPOINT = TEST_STORE.with_suffix(TEST_STORE.suffix + ".checkpoint.json")
TEST_SIGNING_SEED = (
    "7c0da3172937f61df7e29fa7fb4fa132"
    "c7b1660ce3f8cd5f781c5d5a281f8930"
)
from sbp_lex.security.pqc_provider import derive_signing_keypair

_, TEST_SIGNING_PUBLIC_KEY = derive_signing_keypair(
    bytes.fromhex(TEST_SIGNING_SEED), "ML-DSA",
)
TEST_SIGNING_PUBLIC_KEY_B64 = base64.b64encode(
    TEST_SIGNING_PUBLIC_KEY
).decode("ascii")
TEST_SIGNING_KEY_FINGERPRINT = hashlib.sha256(
    TEST_SIGNING_PUBLIC_KEY
).hexdigest()
TEST_MEASURED_STARTUP_TEMP = tempfile.TemporaryDirectory(
    prefix="sbp-lex-pytest-measured-",
)
TEST_MEASURED_STARTUP_ROOT = Path(TEST_MEASURED_STARTUP_TEMP.name)
TEST_BASELINE = TEST_MEASURED_STARTUP_ROOT / "approved_runtime_baselines.json"
TEST_MEASUREMENT_STATE = TEST_MEASURED_STARTUP_ROOT / "state"
TEST_LOCAL_TRUST_ROOT = TEST_MEASURED_STARTUP_ROOT / "local_trust"


for artifact in (TEST_STORE, TEST_CHECKPOINT):
    artifact.unlink(missing_ok=True)

os.environ["SBP_LEX_INTEGRITY_STORE"] = "runtime_artifacts/pytest_integrity_store.jsonl"
os.environ["SBP_LEX_SIGNING_SECRET"] = TEST_SIGNING_SEED
os.environ[
    "SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY"
] = TEST_SIGNING_PUBLIC_KEY_B64
os.environ[
    "SBP_LEX_EXPECTED_SIGNER_FINGERPRINT"
] = TEST_SIGNING_KEY_FINGERPRINT
os.environ["SBP_LEX_PQC_MIGRATION_STATUS"] = "MIGRATED_APPROVED"
os.environ[
    "SBP_LEX_PQC_MIGRATION_APPROVAL_REFERENCE"
] = "TEST_ONLY_EPHEMERAL_PASS9_APPROVAL"
os.environ["SBP_LEX_SIGNING_KEY_ID"] = "PASS9_TEST_MLDSA65_KEY_01"
os.environ[
    "SBP_LEX_SIGNING_KEY_ACTIVATED_AT"
] = "2026-08-09T00:00:00+00:00"
os.environ[
    "SBP_LEX_SIGNING_KEY_EXPIRES_AT"
] = "2099-12-31T23:59:59+00:00"
os.environ["SBP_LEX_REVOKED_SIGNING_KEY_FINGERPRINTS"] = "NONE"
os.environ[
    "SBP_LEX_APPROVED_LEGACY_ARCHIVE_POLICIES"
] = "PASS9_ARCHIVE_READ_POLICY_01"
os.environ["SBP_LEX_APPROVED_RUNTIME_BASELINE_PATH"] = str(TEST_BASELINE)
os.environ["SBP_LEX_MEASURED_STARTUP_STATE_ROOT"] = str(
    TEST_MEASUREMENT_STATE
)
os.environ["SBP_LEX_LOCAL_TRUST_EVIDENCE_ROOT"] = str(TEST_LOCAL_TRUST_ROOT)


def _configure_test_repository_anchor() -> None:
    result = subprocess.run(
        ["git", "rev-list", "--max-parents=0", "HEAD"],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    anchor = result.stdout.strip()
    if result.returncode != 0 or len(anchor) != 40:
        raise RuntimeError("test_repository_anchor_unavailable")
    from sbp_lex.supply_chain import provenance

    provenance.TRUSTED_REPOSITORY_ANCHOR_COMMIT = anchor


_configure_test_repository_anchor()

from sbp_lex.runtime.measured_startup import (  # noqa: E402
    baseline_record,
    create_baseline_store,
    measure_runtime,
    write_baseline_store,
)

write_baseline_store(
    TEST_BASELINE,
    create_baseline_store(baseline_record(
        "DESKTOP_V1_PYTEST_TRUST_ROOT_01",
        measure_runtime(REPOSITORY_ROOT),
        sequence=1,
        status="APPROVED",
        approval_reference="TEST_ONLY_EPHEMERAL_TRUST_ROOT",
    )),
)


def _build_test_local_trust_evidence() -> None:
    from sbp_lex.formal.assurance import write_artifact
    from sbp_lex.local_trust.adversarial_negative_harness import (
        build_adversarial_harness,
        write_adversarial_harness,
    )
    from sbp_lex.local_trust.constitutional_gates import (
        build_constitutional_gate_result,
        write_constitutional_gate_result,
    )
    from sbp_lex.local_trust.evidence_chain import (
        build_local_evidence_chain,
        write_local_evidence_chain,
    )
    from sbp_lex.local_trust.execution_envelope import (
        build_execution_environment_envelope,
        write_execution_envelope,
    )
    from sbp_lex.local_trust.local_trust_capstone import (
        build_local_trust_capstone,
        write_local_trust_capstone,
    )
    from sbp_lex.local_trust.manifest import (
        build_local_trust_manifest,
        write_local_trust_manifest,
    )
    from sbp_lex.local_trust.regression_matrix import (
        build_local_trust_regression_matrix,
        write_local_trust_regression_matrix,
    )
    from sbp_lex.local_trust.release_integrity import (
        build_release_integrity_bundle,
    )
    from sbp_lex.local_trust.toolchain_guard import (
        build_toolchain_guard,
        write_toolchain_guard,
    )
    from sbp_lex.local_trust.validation_dossier import build_validation_dossier

    write_artifact(
        TEST_LOCAL_TRUST_ROOT
        / "outputs/phq_formal_architecture_assurance.json",
        REPOSITORY_ROOT,
    )
    write_local_trust_manifest(
        build_local_trust_manifest(REPOSITORY_ROOT),
        repository_root=REPOSITORY_ROOT,
    )
    write_execution_envelope(
        build_execution_environment_envelope(REPOSITORY_ROOT),
        repository_root=REPOSITORY_ROOT,
    )
    write_local_evidence_chain(
        build_local_evidence_chain(REPOSITORY_ROOT),
        repository_root=REPOSITORY_ROOT,
    )
    write_local_trust_regression_matrix(
        build_local_trust_regression_matrix(REPOSITORY_ROOT),
        repository_root=REPOSITORY_ROOT,
    )
    write_constitutional_gate_result(
        build_constitutional_gate_result(REPOSITORY_ROOT),
        repository_root=REPOSITORY_ROOT,
    )
    write_toolchain_guard(
        build_toolchain_guard(REPOSITORY_ROOT),
        repository_root=REPOSITORY_ROOT,
    )
    write_local_trust_capstone(
        build_local_trust_capstone(REPOSITORY_ROOT),
        repository_root=REPOSITORY_ROOT,
    )
    release = build_release_integrity_bundle(REPOSITORY_ROOT)
    if release["release_status"] != "RELEASE_INTEGRITY_PASS":
        raise RuntimeError(
            f"test_release_integrity_setup_failed:{release['manifest']['validation_failures']}"
        )
    write_adversarial_harness(
        build_adversarial_harness(REPOSITORY_ROOT),
        repository_root=REPOSITORY_ROOT,
    )
    dossier = build_validation_dossier(REPOSITORY_ROOT)
    if dossier["dossier_status"] != "VALIDATION_DOSSIER_READY":
        raise RuntimeError(
            f"test_dossier_setup_failed:{dossier['manifest']['validation_failures']}"
        )


_build_test_local_trust_evidence()


@pytest.fixture(autouse=True)
def _isolated_controlled_reentry_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sbp_lex.security import domain_aurion_evidence

    monkeypatch.setattr(
        domain_aurion_evidence,
        "_CONTROLLED_REENTRY_REPLAY_REGISTRY",
        domain_aurion_evidence._ControlledReentryReplayRegistry(),
    )


def pytest_sessionfinish(session: object, exitstatus: int) -> None:
    os.environ.pop("SBP_LEX_INTEGRITY_STORE", None)
    os.environ.pop("SBP_LEX_SIGNING_SECRET", None)
    os.environ.pop("SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY", None)
    os.environ.pop("SBP_LEX_EXPECTED_SIGNER_FINGERPRINT", None)
    os.environ.pop("SBP_LEX_PQC_MIGRATION_STATUS", None)
    os.environ.pop("SBP_LEX_PQC_MIGRATION_APPROVAL_REFERENCE", None)
    os.environ.pop("SBP_LEX_SIGNING_KEY_ID", None)
    os.environ.pop("SBP_LEX_SIGNING_KEY_ACTIVATED_AT", None)
    os.environ.pop("SBP_LEX_SIGNING_KEY_EXPIRES_AT", None)
    os.environ.pop("SBP_LEX_REVOKED_SIGNING_KEY_FINGERPRINTS", None)
    os.environ.pop("SBP_LEX_APPROVED_LEGACY_ARCHIVE_POLICIES", None)
    os.environ.pop("SBP_LEX_APPROVED_RUNTIME_BASELINE_PATH", None)
    os.environ.pop("SBP_LEX_MEASURED_STARTUP_STATE_ROOT", None)
    os.environ.pop("SBP_LEX_LOCAL_TRUST_EVIDENCE_ROOT", None)
    for artifact in (TEST_STORE, TEST_CHECKPOINT):
        artifact.unlink(missing_ok=True)
    TEST_MEASURED_STARTUP_TEMP.cleanup()
