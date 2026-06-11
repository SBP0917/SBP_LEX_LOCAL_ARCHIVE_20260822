# Desktop V1 Operator Release Lock

## Baseline

`14_desktop_v1_operator_release_lock`

## Purpose

This release packages the completed SBP-LEX Desktop V1 institutional operator
console into a stable, recoverable, beginner-runnable handoff baseline.

## Repository structure

- `main.py`: direct runtime entry point
- `sbp_lex/`: canonical runtime and dashboard package
- `scripts/`: launch, test, and smoke-check helpers
- `tests/`: runtime and dashboard verification
- `docs/`: supporting contracts and interface documentation
- root Markdown files: security, release, operator, and baseline records

## Install dependencies

From the extracted folder containing `main.py`:

```text
python -m pip install -r requirements.txt
```

## Run directly

```text
python main.py server 8000
```

## Run using the Windows script

```text
scripts\run_desktop_runtime.bat
```

The direct beginner method is `python main.py server 8000`.

## Local URLs

- Dashboard: `http://127.0.0.1:8000/dashboard`
- Health: `http://127.0.0.1:8000/health`
- Runtime integrity: `http://127.0.0.1:8000/runtime/integrity`

## Dashboard panels

- Operator landing: runtime mode, posture, health, decision, pipeline mode,
  latest traversal, and audit reference.
- Runtime integrity: chronology, event bus, replay ledger, connector recovery,
  persistence, environment, and security posture.
- Pipeline timeline: retained Pipeline A stages and available Pipeline B
  deterministic validator summary.
- Convergence proof: pipeline mode, parity result, convergence hash, and replay
  comparison status.
- Execution admissibility: final decision, execution result, gate verification,
  admissibility status, and token failures.
- Audit continuity: controlled runtime record, audit reference, replay ledger,
  exports, and event count.
- Replay comparison: latest deterministic comparison and ledger reference.
- Animated pipeline visual: active, idle, pass, escalate, deny, and fail state
  representation using existing runtime values.

## Approved demo action

Select **Run Approved Demo Traversal** in the controlled operator actions panel.
It uses the fixed approved Desktop V1 sample payload. The dashboard does not
provide an editable arbitrary request generator.

## Exports

Use the controlled actions to export:

- latest runtime result
- replay ledger
- traversal events

The browser downloads JSON files for local review and handoff.

## Stop the runtime

Return to the command window and press `Ctrl+C`.

## Troubleshooting

- Cannot connect: confirm the runtime command is still running.
- Command window closed: start the runtime again.
- Python not found: install Python 3.10+ and add it to PATH.
- Pytest not found: install requirements.
- Dependencies unavailable: retry from a permitted network.
- Pip warnings: inspect the final result and verify with pytest.
- Port 8000 busy: run `python main.py server 8773`, then open
  `http://127.0.0.1:8773/dashboard`.
- OneDrive locks files: extract into a normal local folder.
- Firewall warning: permit local/private access only.
- Dashboard missing: use the exact `/dashboard` path and correct port.
- Background missing: verify the exact secured image route documented in
  `LOCAL_OPERATOR_GUIDE.md`.

## Architecture confirmation

The canonical runtime remains authoritative. The dashboard remains
observability-only. Governance, admissibility, execution, chronology, replay,
audit, and convergence behavior are unchanged. Dual Adaptive Deterministic
Pipelines and localhost/private posture remain intact. No nodes, cloud, quorum,
or distributed runtime topology are introduced.
