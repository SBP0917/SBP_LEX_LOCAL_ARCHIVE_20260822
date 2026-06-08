# Local Operator Guide

## Runtime posture

The V1 desktop runtime is local-first and binds to `127.0.0.1` by default.
Keep `SBP_LEX_API_SECURITY_MODE=local` for loopback-only operation.

For any non-local deployment, use private mode with a strong API token and
signing secret as described in `DEPLOYMENT_SECURITY.md`.

## Commands

Run the local runtime and smoke checks:

```text
scripts\run_desktop_runtime.bat
```

Run the full test suite:

```text
scripts\run_tests.bat
```

Run the canonical sample traversal:

```text
python main.py
```

Run deterministic replay verification:

```text
python main.py replay
```

## Preserved V1 constraints

- The canonical runtime remains the execution authority.
- Dual Adaptive Deterministic Pipelines and parity convergence remain active.
- Execution gating remains fail-closed.
- Audit and replay integrity remain mandatory.
- The active runtime contains no node or distributed quorum topology.
