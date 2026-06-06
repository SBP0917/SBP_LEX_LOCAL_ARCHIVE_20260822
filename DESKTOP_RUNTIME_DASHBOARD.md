# Desktop Runtime Dashboard

## Purpose

The desktop dashboard is the local operator interface for the V1 canonical runtime prototype.

It exposes runtime state without changing governance authority.

## Active Path

```text
Desktop Dashboard
→ Local Runtime API
→ Canonical Runtime
→ Dual Adaptive Deterministic Pipelines
→ Parity / Convergence
→ Execution Gate
→ Audit + Observability
```

## Dashboard Functions

- Runtime health display.
- Traversal event display.
- Pipeline/parity/convergence display.
- Execution decision display.
- Audit/replay display.
- Controlled sample traversal request.
- Controlled replay request.
- JSON export for latest runtime snapshot.
- JSON export for replay ledger.
- JSON export for traversal events.

## Local Start

```bash
python3 main.py server
```

Then open:

```text
http://127.0.0.1:8000/dashboard
```

## Authority Boundary

The dashboard is an operator interface only.

Execution authority remains inside the canonical runtime.
