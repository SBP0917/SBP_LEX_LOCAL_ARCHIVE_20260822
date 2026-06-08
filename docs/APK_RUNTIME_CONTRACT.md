# SBP-LEX V1 APK Runtime Contract

## Topology

```text
APK
→ Connector Fabric
→ Canonical Runtime
→ Pipeline A / Pipeline B
→ Parity / Convergence
→ Governance Validation
→ Execution Admissibility
→ Audit + Observability
```

## APK authority

The APK is observational and orchestration-oriented only.

It must not:

- authorise execution
- mutate runtime state
- bypass connector validation
- rewrite audit records
- alter parity/convergence

## Runtime authority

Execution authority exists only inside the canonical runtime.

## Required API endpoints

```text
GET  /health
GET  /runtime/status
GET  /runtime/events
GET  /runtime/integrity
GET  /apk/contract
POST /runtime/traverse
POST /runtime/replay
POST /connector/envelope
POST /connector/build-envelope
```

## Required runtime status contract

```text
runtime_id
api_security_mode
traversal_count
chronology_valid
event_bus_valid
replay_ledger_valid
connector_recovery_valid
persistence_valid
```
