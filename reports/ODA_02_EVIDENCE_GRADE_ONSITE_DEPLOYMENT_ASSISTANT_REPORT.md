# ODA-02 Evidence-Grade Onsite Deployment Assistant Report

Status: Repository-contained ODA implementation pass. Support-only; runtime-detached.

## What ODA Now Does

ODA-02 upgrades the Onsite Deployment Assistant from a skeleton into a local evidence assistant for university review and pilot hand-holding. It can:

- scan local deployment health and Git state;
- inspect dependency and PQC provider availability;
- answer deterministic local support questions from a controlled query map;
- create a digest-bound local support bundle;
- prepare maintenance work-package recommendations;
- record owner approval limits;
- run a static boundary check for ODA/runtime separation.

## What ODA Does Not Do

ODA does not govern traversal, execute runtime decisions, mutate SBP-LEX runtime authority, alter pipeline order, change governance, install signed maintenance packages, open a remote shell, auto-repair files, publish evidence externally, or claim production deployment readiness.

## CLI Commands

- `python -m sbp_oda.cli --health --runtime-root .`
- `python -m sbp_oda.cli --diagnostics --runtime-root .`
- `python -m sbp_oda.cli --support-bundle --runtime-root . --out runtime_artifacts/oda_02/support_bundle.json`
- `python -m sbp_oda.cli --query what_is_oda --runtime-root .`
- `python -m sbp_oda.cli --query pqc_provider_status --runtime-root .`
- `python -m sbp_oda.cli --boundary-check --runtime-root .`
- `python -m sbp_oda.cli --maintenance-plan validation_dossier_drift --runtime-root .`

## Support Bundle Fields

The ODA-02 support bundle uses `bundle_type: ODA_LOCAL_SUPPORT_BUNDLE` and includes repository status, dependency status, PQC provider status, PVPL presence, local-trust presence, validation-dossier recorded status, safe reviewer commands, blocked capabilities, owner approval policy, maintenance policy summary, boundary status, deterministic query index, and `support_bundle_digest`.

The digest is SHA-256 over canonical JSON excluding `support_bundle_digest`.

## Boundary Enforcement

The boundary checker verifies that ODA is not imported by `main.py` or `sbp_lex/`, ODA statuses do not use runtime decision terms, remote shell remains prohibited, auto-apply paths are not active, signed package receipt remains blocked, and ODA does not contain runtime-authority file mutation paths.

## Owner Approval Limits

Owner approval records who/what/when/reason, but approval does not grant execution authority. Canonical/runtime authority requests remain blocked even with owner approval.

## Maintenance Planner Limits

Maintenance output is a recommendation/work-package only. Every plan has `auto_apply_allowed: false` and `execution_authority: NONE`. Runtime-authority findings are marked as canonical boundary risk and require owner review outside ODA.

## Runtime Detachment Proof

ODA remains invoked by `python -m sbp_oda.cli`. No `sbp_oda` import is added to `main.py` or `sbp_lex/`. ODA reports `runtime_authority: NONE` and never emits `ALLOW`, `DENY`, `ESCALATE`, `EXECUTE`, or `HALT` as ODA statuses.

## Tests Added Or Updated

- `tests/oda/test_oda02_evidence_grade.py`
- `tests/oda/test_support_bundle_builder.py`
- `tests/oda/test_maintenance_policy.py`
- `tests/oda/test_owner_approval_gate.py`

## Validation Results

- `python -m compileall -q .`: PASS.
- `python -m pytest -q tests/oda --basetemp runtime_artifacts/pytest_tmp_oda02`: PASS, `34 passed`.
- `python -m pytest -q tests/test_pqc_01_provider_contract.py --basetemp runtime_artifacts/pytest_tmp_oda02_pqc`: PASS, `10 passed`.
- `python -m pytest -q tests/pvpl --basetemp runtime_artifacts/pytest_tmp_oda02_pvpl`: PASS, `14 passed`.
- `python -m pytest -q --basetemp runtime_artifacts/pytest_tmp_oda02_full`: PASS, `663 passed in 321.36s`.
- ODA CLI health: PASS, `HARNESS_OK`.
- ODA CLI diagnostics: PASS, JSON returned with dirty-tree warning and `runtime_authority: NONE`.
- ODA CLI support bundle: PASS, wrote `runtime_artifacts/oda_02/support_bundle.json`.
- ODA CLI query `what_is_oda`: PASS, deterministic JSON answer.
- ODA CLI query `pqc_provider_status`: PASS, `PQC_PROVIDER_AVAILABLE`, `cryptography 49.0.0`, no certification claim.
- ODA CLI boundary check: PASS, `HARNESS_OK`, zero findings.
- ODA CLI maintenance plan `validation_dossier_drift`: PASS, `HARNESS_REPAIR_RECOMMENDED`, `auto_apply_allowed: false`, `execution_authority: NONE`.
- `python main.py`: PASS, returned `ALLOW`, `EXECUTE`, convergence matched.
- `python main.py replay`: PASS, `matched: true`.
