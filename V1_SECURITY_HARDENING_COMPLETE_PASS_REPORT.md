# SBP-LEX DUAL V6 — V1 Security Hardening Complete Pass Report

Active baseline used: execution gate strictness hardened runtime.

Scope preserved:

- Canonical runtime remains active authority.
- Pipeline A / Pipeline B parity remains active.
- APK remains observational and orchestration-oriented only.
- Execution authority remains inside the canonical runtime.
- V1 topology was not expanded.

## Hardening passes completed in this round

1. Replay / audit determinism deep pass
2. Connector recovery / interruption hardening
3. Full adversarial test harness
4. Runtime observability hardening
5. Deployment hardening for Railway/local server
6. Secrets/environment hardening
7. Persistence/storage integrity hardening
8. APK connector contract validation

## Files added or changed

```text
sbp_lex/runtime/event_bus.py
sbp_lex/runtime/canonical_runtime.py
sbp_lex/connector/recovery.py
sbp_lex/connector/fabric.py
sbp_lex/audit/pipeline_replay_ledger.py
sbp_lex/persistence/__init__.py
sbp_lex/persistence/integrity_store.py
sbp_lex/api/apk_contract.py
sbp_lex/api/server.py
sbp_lex/api/access_control.py
sbp_lex/config/environment.py
sbp_lex/pipeline/replay_runner.py
tests/test_adversarial_runtime.py
requirements.txt
Procfile
railway.toml
.env.example
DEPLOYMENT_SECURITY.md
docs/APK_RUNTIME_CONTRACT.md
```

## Attack surfaces closed

- Deep replay mismatch across audit finalisation and controlled outcome.
- Connector duplicate request replay.
- Connector rejection without recovery record.
- Connector runtime exception without recorded interruption trace.
- Event bus unbounded payload exposure.
- Event stream integrity not being directly verified.
- Runtime status missing integrity verification surfaces.
- Missing persistent integrity store for runtime summary records.
- Deployment without documented private API mode.
- Missing APK runtime contract endpoint.
- Missing environment/security configuration report.

## Tests run

```text
python3 -m compileall -q .
python3 main.py
python3 main.py replay
pytest -q
GET /health
GET /runtime/integrity
GET /apk/contract
repository removed-topology wording search
```

## Test result

```text
runtime = PASS
replay = PASS
adversarial tests = PASS
strictness tests = PASS
API health = PASS
runtime integrity endpoint = PASS
APK contract endpoint = PASS
removed-topology wording search = CLEAN
```

## Runtime result

```text
decision = ALLOW
execution_result = EXECUTE
pipeline_mode = MODE_2_SPLIT_VALIDATOR
convergence_matched = true
token_failures = []
```

## Current security position

The repository is now a stronger V1 canonical runtime baseline with:

- deterministic replay checks across audit and controlled outcome,
- hardened connector recovery records,
- adversarial runtime tests,
- verified runtime event observability,
- local/private deployment guidance,
- environment security reporting,
- append-only persistence integrity records,
- APK/runtime contract validation.

## Remaining later hardening areas

- Real persistent database backend.
- External secret manager integration.
- TLS/reverse proxy deployment configuration.
- Long-running soak tests.
- External security review.
