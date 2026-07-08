# Pilot Package Technical Install Manual Draft

Draft status: technical reviewer guide draft only.

The final pilot package has not been created yet. This guide describes the
current repository-level commands and the expected shape of a later local/private
pilot package.

## Purpose

This guide helps a technical reviewer, university staff member, developer, or
validator inspect and run the SBP_LEX_DUAL_V6 Desktop V1 validation slice.

## Scope

This guide covers:

- local/private Desktop V1 validation
- evidence and report inspection
- basic runtime smoke checks
- replay smoke checks
- focused and full tests
- Phase 19A and Phase 19B evidence review

This guide does not cover production deployment, public deployment, cloud
runtime, distributed governance, nodes, quorum, canon promotion, or runtime
authority expansion.

## Repository / Package Assumptions

Current repository name: `SBP0917/SBP_LEX_DUAL_V6`.

Final pilot package status: NOT CREATED.

Until the final pilot package exists, use the repository root as the working
folder. After final assembly, the package filename, top-level folder name, and
checksum must be filled in from the final package record.

## System Requirements

Expected reviewer environment:

- Windows PowerShell or equivalent terminal.
- Python 3 available on PATH or provided by an approved runtime bundle.
- Local filesystem access to the repository or final pilot package.
- No cloud service, public node, quorum, or distributed runtime required.

## Python / Runtime Assumptions

The repository currently has:

- `requirements.txt`
- no `pyproject.toml`
- `pytest>=8.0.0`
- `cryptography>=49.0.0`

Use an isolated virtual environment if the final pilot package instructions
require one. The final package must confirm exact runtime setup.

## How To Obtain The Package Once Assembled

Placeholder until final package exists:

1. Obtain the final pilot package from the repository owner or approved handoff
   route.
2. Verify the final filename and checksum against the final assembly record.
3. Extract it into a local folder.
4. Do not rename internal folders unless the final guide says to.

## Folder Layout Overview

Important current repository paths:

- `main.py` - local runtime entry point.
- `requirements.txt` - Python dependency list.
- `reports/` - validation and phase reports.
- `docs/phase19b/` - Phase 19B scope/evidence/approval records.
- `docs/pilot_package/` - pilot package planning documents.
- `fixtures/phase19a/` - Phase 19A schemas, examples, and failure cases.
- `tests/` - automated test suite.
- `sbp_lex/phase19a/` - Phase 19A support utilities.

Do not use `baselines/` as active pilot-package evidence.

## Setup Steps

From the repository or final package root:

```powershell
python --version
python -m pip install -r requirements.txt
```

If the final pilot package ships a different runtime command, follow the final
package guide instead.

## Dependency Setup

Install only dependencies listed in `requirements.txt` unless a later final
pilot-package instruction says otherwise.

Current dependency file includes `pytest` and `cryptography>=49.0.0`.

## Running `main.py`

From the repository root:

```powershell
python main.py
```

Expected shape: JSON output including fields such as `decision`,
`execution_result`, `pipeline_mode`, `audit_hash`, and `convergence_matched`.

## Running Replay

```powershell
python main.py replay
```

Expected shape: JSON replay output with a matched result when the controlled
sample replay is stable.

## Running Focused Tests

Recommended focused checks:

```powershell
python -m pytest -q tests/test_phase19a_bounded_translator.py
python -m pytest -q tests/test_phase_18_5_authority_boundary.py
python -m pytest -q tests/test_phase_15_5b_integration.py
```

These checks cover Phase 19A bounded translation, authority boundaries, and
integration order.

## Running Full Tests

Optional full suite:

```powershell
python -m pytest -q
```

If the local temporary folder causes permission issues, the final pilot package
may provide an in-repo `--basetemp` command. This remains a final-package gap.

## Reports Location

Primary reports:

- `reports/PHASE19A_OWNER_CLOSURE_01_REPORT.md`
- `reports/PHASE19A_IMPLEMENTATION_01_REPORT.md`
- `reports/PHASE19A_IMPLEMENTATION_02_REPORT.md`
- `reports/PHASE19B_EVIDENCE_PACKAGE_01_REPORT.md`
- `reports/PHASE19B_OWNER_REVIEW_01_REPORT.md`
- `reports/PHASE19B_PILOT_ASSEMBLY_PREP_01_REPORT.md`

## Fixtures Location

Phase 19A fixtures:

- `fixtures/phase19a/README.md`
- `fixtures/phase19a/failure_mode_cases.json`
- `fixtures/phase19a/schemas/`
- `fixtures/phase19a/examples/`

## Verifying Phase 19A / Phase 19B Evidence

Review in this order:

1. `docs/phase19b/PHASE19B_SCOPE_LOCK.md`
2. `docs/phase19b/PHASE19B_EVIDENCE_PACKAGE_MANIFEST.md`
3. `docs/pilot_package/PILOT_PACKAGE_VALIDATION_CLAIMS_MATRIX.md`
4. Phase 19A implementation reports.
5. Phase 19A fixtures and tests.
6. ODA/PVPL/SIM reports as detached support evidence only.

## What Success Looks Like

For smoke checks:

- `python main.py` exits without an exception.
- `python main.py replay` exits without an exception and reports replay match.
- focused pytest commands pass.

## Common Failures

- `python` not found: Python is not installed, not on PATH, or the final runtime
  was not selected.
- `No module named pytest`: dependencies were not installed.
- `No module named cryptography`: dependencies were not installed or are too old.
- test temp permission errors: use a final-package-approved `--basetemp`
  command if provided.

## Troubleshooting

1. Confirm you are in the repository or final package root.
2. Confirm `requirements.txt` exists.
3. Confirm Python runs.
4. Reinstall dependencies from `requirements.txt`.
5. Run the focused tests before full pytest.
6. Stop and ask the owner for help if runtime code appears modified or missing.

## What Not To Modify

Do not modify:

- `main.py`
- `sbp_lex/`
- `tests/`
- `fixtures/phase19a/`
- `docs/canonical_blueprint_series/`
- `baselines/`
- generated `runtime_artifacts/`

## Desktop V1 Boundary

Desktop V1 remains local/private and bounded. It has no active nodes, no quorum,
no distributed governance, and no cloud runtime assumption.

## Security / Sensitivity Notes

Raw implementation code and runtime files may require summary or owner approval
before external distribution. Do not add secrets, credentials, private keys, or
deployment scripts to the pilot package.

## Not-Production Disclaimer

This is not production deployment and does not claim production readiness.

## Not-Public-Deployment Disclaimer

This is not public deployment, public release, cloud deployment, public ledger
publication, or blockchain publication.

## Later Update Notes

After final pilot package creation, update this guide with:

- final package filename
- final folder structure
- final checksum/hash
- confirmed install command
- confirmed smoke-test command
- confirmed replay command
- screenshots if approved
- final known-errors list
