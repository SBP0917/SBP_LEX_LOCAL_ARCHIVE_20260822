# PVPL-02 Evidence-Grade Local Proof Verification Layer Report

Status: Repository-contained PVPL implementation pass. Local/private, runtime-detached, publication-inactive.

## What PVPL Now Does

PVPL-02 upgrades the Public Verification Publication Layer from skeleton scaffolding into a local proof verification layer for university review. It can collect local evidence metadata, build digest-bound proof manifests, build digest-bound proof bundles, verify bundle and evidence integrity, detect local tampering, write reviewer-readable proof reports, and run a static boundary check.

## What PVPL Does Not Do

PVPL does not publish externally, use blockchain, use a public ledger, use cloud publication, connect to live systems, become runtime authority, alter audit records, rewrite evidence, issue runtime decisions, or claim certified/production proof.

## CLI Commands

- `python -m sbp_pvpl.cli --runtime-root . --summary`
- `python -m sbp_pvpl.cli --collect-evidence --runtime-root .`
- `python -m sbp_pvpl.cli --build-manifest --runtime-root . --out runtime_artifacts/pvpl_02/proof_manifest.json`
- `python -m sbp_pvpl.cli --build-bundle --runtime-root . --out runtime_artifacts/pvpl_02/proof_bundle.json`
- `python -m sbp_pvpl.cli --verify-bundle --runtime-root . --bundle runtime_artifacts/pvpl_02/proof_bundle.json`
- `python -m sbp_pvpl.cli --write-report --runtime-root . --bundle runtime_artifacts/pvpl_02/proof_bundle.json --out runtime_artifacts/pvpl_02/proof_report.md`
- `python -m sbp_pvpl.cli --boundary-check --runtime-root .`

## Proof Manifest Fields

The manifest uses `manifest_type: PVPL_LOCAL_PROOF_MANIFEST` and records repository root, evidence scope, evidence entries, required evidence summary, missing/present counts, proof policy, inactive publication fields, `runtime_authority: NONE`, `manifest_payload_digest`, `manifest_digest`, and digest-only signature mode.

## Proof Bundle Fields

The bundle uses `bundle_type: PVPL_LOCAL_PROOF_BUNDLE` and records the proof manifest, evidence snapshot, reviewer summary, verification instructions, boundary statement, `bundle_payload_digest`, and `bundle_digest`.

## Verification Statuses

PVPL-02 uses `PROOF_OK`, `PROOF_INCOMPLETE`, `PROOF_TAMPER_DETECTED`, `PROOF_BLOCKED_RUNTIME_BOUNDARY`, `PROOF_INVALID`, and `PROOF_WARNING`. It does not use runtime decision statuses.

## Tamper Detection Coverage

Tests cover bundle field mutation, manifest digest mutation, evidence file mutation after bundle creation, missing required evidence, and forbidden publication/cloud/blockchain/ledger activation.

## Boundary Enforcement

The boundary checker verifies that PVPL is not imported by `main.py` or `sbp_lex/`, PVPL statuses do not equal runtime decision terms, publication/blockchain/ledger/cloud defaults remain inactive, external publication target remains `NONE`, and PVPL does not modify audit authority files.

## Runtime Detachment Proof

PVPL remains invoked through `python -m sbp_pvpl.cli`. No `sbp_pvpl` import is added to `main.py` or `sbp_lex/`. PVPL reports `runtime_authority: NONE` and `publication_active: false`.

## ODA Boundary

No ODA code is changed by PVPL-02. The optional ODA-02 support bundle is inspected only as local evidence if present.

## Validation Results

- `python -m compileall -q .`: PASS.
- `python -m pytest -q tests/pvpl --basetemp runtime_artifacts/pytest_tmp_pvpl02`: PASS, `23 passed`.
- `python -m pytest -q tests/oda --basetemp runtime_artifacts/pytest_tmp_pvpl02_oda`: PASS, `34 passed`.
- `python -m pytest -q tests/test_pqc_01_provider_contract.py --basetemp runtime_artifacts/pytest_tmp_pvpl02_pqc`: PASS, `10 passed`.
- `python -m pytest -q --basetemp runtime_artifacts/pytest_tmp_pvpl02_full`: PASS, `672 passed in 228.48s`.
- PVPL CLI summary: PASS, returned `PROOF_OK`.
- PVPL CLI collect evidence: PASS, collected `8` evidence entries.
- PVPL CLI build manifest: PASS, wrote `runtime_artifacts/pvpl_02/proof_manifest.json`.
- PVPL CLI build bundle: PASS, wrote `runtime_artifacts/pvpl_02/proof_bundle.json`.
- PVPL CLI verify bundle: PASS, `PROOF_OK`.
- PVPL CLI write report: PASS, wrote `runtime_artifacts/pvpl_02/proof_report.md`.
- PVPL CLI boundary check: PASS, `PROOF_OK`, zero findings.
- `python main.py`: PASS, returned `ALLOW`, `EXECUTE`, convergence matched.
- `python main.py replay`: PASS, `matched: true`.
