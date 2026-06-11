# Technical Evidence Pack

## Evidence map

| Evidence point | Verification method |
| --- | --- |
| Repository structure | Inspect root, `sbp_lex/`, `docs/`, `scripts/`, and `tests/` |
| Runtime launch | `python main.py server 8000` |
| Dashboard | `GET /dashboard` |
| Health | `GET /health` |
| Runtime integrity | `GET /runtime/integrity` |
| Background image | `GET /desktop/static/images/sbp_lex_background.png` |
| Static path restriction | Adjacent unapproved image path must be denied |
| Compilation | `python -m compileall -q .` |
| Direct runtime | `python main.py` |
| Replay | `python main.py replay` |
| Python tests | `python -m pytest -q` |
| Windows test runner | `scripts\run_tests.bat` |
| End-to-end smoke check | `scripts\smoke_check.py --launch --host 127.0.0.1 --port 8765 --expected-mode local --exit-after-check` |
| Topology wording | Scan active Python source for prohibited phrases |
| Request control | Confirm editable arbitrary request generator is absent |
| Demonstration control | Confirm fixed approved demo action is present |

## Interpretation

Passing results establish repeatable local V1 behavior for this repository
state. They do not establish production certification, external deployment
fitness, or third-party assurance.

The exact measured Phase 15 outcomes are recorded in
`FINAL_DESKTOP_V1_INSTITUTIONAL_DEMO_EVIDENCE_PACK_REPORT.md`.
