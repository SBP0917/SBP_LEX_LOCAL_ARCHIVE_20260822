# SBP-LEX V1 APK / Connector Contract

Active V1 topology:

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

## Runtime endpoints

```text
GET  /health
GET  /runtime/status
GET  /runtime/events?after=<sequence>
POST /runtime/traverse
POST /runtime/replay
POST /connector/build-envelope
POST /connector/envelope
GET  /connector/checkpoints
```

## Runtime traverse payload

```json
{
  "request_id": "apk-request-001",
  "request": {
    "action": "test_action",
    "payload": {},
    "context": {},
    "resolved_authority": "test_authority",
    "jurisdiction": "AU-PACIFIC",
    "safety_profile": {
      "human_safety": 1,
      "irreversibility": 1,
      "cascading_impact": 1,
      "financial_operational": 1
    }
  }
}
```

## APK rule

The APK remains observational and orchestration-oriented only.

Execution authority exists only inside the canonical runtime.
