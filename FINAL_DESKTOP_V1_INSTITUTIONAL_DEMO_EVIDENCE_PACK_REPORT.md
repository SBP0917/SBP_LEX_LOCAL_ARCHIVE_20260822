# Final Desktop V1 Institutional Demo Evidence Pack Report

## Phase

Phase 15 - Desktop V1 Institutional Demonstration and Evidence Pack

## Baseline

`15_desktop_v1_institutional_demo_evidence_pack`

## Changed files

- `docs/demo_evidence_pack/00_DEMO_PACK_README.md`
- `docs/demo_evidence_pack/01_EXECUTIVE_DEMONSTRATION_SCRIPT.md`
- `docs/demo_evidence_pack/02_AUDITOR_REVIEWER_WALKTHROUGH.md`
- `docs/demo_evidence_pack/03_INVESTOR_SAFE_DEMONSTRATION_FLOW.md`
- `docs/demo_evidence_pack/04_TECHNICAL_EVIDENCE_PACK.md`
- `docs/demo_evidence_pack/05_RUNTIME_INTEGRITY_EVIDENCE.md`
- `docs/demo_evidence_pack/06_CONVERGENCE_AND_REPLAY_EVIDENCE.md`
- `docs/demo_evidence_pack/07_AUDIT_EXPORT_EVIDENCE.md`
- `docs/demo_evidence_pack/08_PASS_DENY_ESCALATE_DEMO_EXAMPLES.md`
- `docs/demo_evidence_pack/09_WHAT_THIS_IS_AND_IS_NOT.md`
- `docs/demo_evidence_pack/SCREENSHOT_CAPTURE_GUIDE.md`
- `FINAL_DESKTOP_V1_INSTITUTIONAL_DEMO_EVIDENCE_PACK_REPORT.md`

## Evidence pack files created

PASS. All ten required numbered documents were created under
`docs/demo_evidence_pack/`, together with a manual screenshot capture guide.

## Demonstration materials created

- non-technical executive demonstration script
- step-by-step auditor and reviewer walkthrough
- controlled investor-safe demonstration flow
- technical evidence map
- runtime integrity evidence explanation
- convergence and replay evidence explanation
- audit and export evidence explanation
- clearly labelled illustrative status examples
- explicit V1 capability and claims boundary
- manual screenshot capture and evidence-handling guide

## Screenshot status

Automated screenshots were not captured. The local dashboard server started,
but Windows denied creation of the sandboxed in-app browser process. No
screenshot files are claimed. `SCREENSHOT_CAPTURE_GUIDE.md` records the manual
capture steps, filenames, privacy controls, and evidence limitations.

## Runtime verification

PASS.

- Compilation completed with exit code 0.
- Direct runtime completed with decision `ALLOW`, execution result `EXECUTE`,
  pipeline mode `MODE_2_SPLIT_VALIDATOR`, and matched convergence.
- Replay completed with two matched runs and zero mismatches.
- Direct pytest passed all 23 tests.
- The Windows test runner passed all 23 tests using Python 3.14.5.
- The smoke check passed health, canonical traversal, dual-pipeline
  convergence, local mode, runtime status, integrity, environment security,
  and dashboard checks.

## Dashboard verification

PASS.

- Dashboard and supplied background image returned their expected media types.
- An adjacent arbitrary static image path was denied.
- Dashboard source retained the observability/no-execution-authority boundary.
- The fixed controlled approved demo action remains present.
- The editable arbitrary request generator remains absent.
- Dual Adaptive Deterministic Pipelines and the animated pipeline visual remain
  present.

## Commands executed

- `python -m compileall -q .` - PASS, exit code 0.
- `python main.py` - PASS, exit code 0.
- `python main.py replay` - PASS, exit code 0; two matched runs and zero
  mismatches.
- `python -m pytest -q` - PASS; 23 passed in 0.80 seconds.
- `scripts\run_tests.bat` - PASS; 23 passed in 1.10 seconds on Python 3.14.5.
- `python scripts\smoke_check.py --launch --host 127.0.0.1 --port 8765
  --expected-mode local --exit-after-check` - PASS.
- Independent localhost HTTP route checks - PASS.
- Active Python runtime source topology phrase scan - PASS.
- Dashboard authority and action marker scan - PASS.

## Commands not executable

The in-app browser screenshot process could not start because Windows returned
access denied while creating its sandboxed process. This affected optional
screenshot automation only. All required runtime, route, test, smoke, and
source verification commands were executable and passed.

## Live route results

- `GET /dashboard` - `200`, `text/html; charset=utf-8`.
- `GET /desktop/static/images/sbp_lex_background.png` - `200`, `image/png`.
- `GET /desktop/static/images/not_allowed.png` - `404`, `application/json`.
- `GET /health` - `200`, `application/json`; `ok=true`, mode `local`, client
  `127.0.0.1`.
- `GET /runtime/integrity` - `200`, `application/json`; status contract valid,
  environment mode `local`, environment security valid.

## Remaining blockers

No release blocker remains. Optional automated screenshots remain unavailable
in this execution environment and can be added later using the manual guide.

The active Python runtime source scan found zero occurrences of
`node_quorum`, `node_attestation`, `node_signature`, `distributed node`,
`distributed quorum`, and `multi-node convergence`.

The scan retained two explicit `Dual Adaptive Deterministic Pipelines` markers
and five localhost/private markers. Dashboard checks found zero `requestBox`
markers and retained `Controlled Operator Actions`, `Run Approved Demo`, the
no-execution-authority statement, and the pipeline visual.

## Exact next human steps

1. Review and merge the Phase 15 draft pull request.
2. Download or extract the merged `main` release.
3. Follow `docs/demo_evidence_pack/00_DEMO_PACK_README.md`.
4. Run the demonstration using
   `01_EXECUTIVE_DEMONSTRATION_SCRIPT.md` or
   `02_AUDITOR_REVIEWER_WALKTHROUGH.md`.
5. If screenshots are required, follow `SCREENSHOT_CAPTURE_GUIDE.md` and
   record the repository commit and capture environment.
6. Retain exported JSON and verification output with the review record.

## Architecture confirmation

- Runtime remains authoritative.
- Dashboard remains observability-only.
- No nodes are added.
- No cloud is added.
- No distributed runtime topology is added.
- Governance, admissibility, and execution authority are not moved.
- Replay, audit, and chronology remain unchanged.
- Localhost/private posture is preserved.
- Dual Adaptive Deterministic Pipelines are preserved.
