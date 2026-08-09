# Pass 8 Fault-Injection Matrix

Status: focused matrix implemented

Harness: `PASS8_DESKTOP_V1_TEST_FAULT_INJECTION_V1`

Activation: constructor opt-in and `SBP_LEX_TEST_FAULT_INJECTION=1`

The injector is unavailable in normal runtime. Every activation is deterministic,
digest-bound, test-only, records `authority_granted=false`, returns or raises a
controlled fault, and produces `execution_result=HALT`. A request-fingerprint
mismatch does not activate a configured fault.

## Critical seams

| # | Seam | Expected result |
|---:|---|---|
| 1 | measured startup | startup/recovery fails closed |
| 2 | EIE validation | ingress rejected |
| 3 | SKG contract validation | pre-context rejected |
| 4 | DTN contract validation | pre-context rejected |
| 5 | bridge validation | bridge result rejected |
| 6 | hard entry | governed state not constructed |
| 7 | state construction | full re-entry required |
| 8 | collective attachment | attachment rejected |
| 9 | Root of Trust | authority validation fails closed |
| 10 | Procedural Truth | control path halts |
| 11 | classification | no inferred class is accepted |
| 12 | licensing | no licence is inferred |
| 13 | Governance | no Governance result is manufactured |
| 14 | GRC | compliance result rejected |
| 15 | Domain | candidate fails; bounded new candidate only |
| 16 | Aurion | candidate fails; bounded new candidate only |
| 17 | token verification | token rejected |
| 18 | hash-chain append | state cannot advance |
| 19 | execution gate | no execution convergence |
| 20 | capability issuance | no capability minted |
| 21 | capability consumption | no effect authority consumed |
| 22 | synthetic effect acknowledgement | effect remains unconfirmed; no auto-retry |
| 23 | audit finalisation | non-executing evidence repair only |
| 24 | replay write | replay evidence incomplete; no authority change |
| 25 | persistence write | atomic failure/quarantine path |
| 26 | security integrity ledger write | ledger fails closed |
| 27 | shutdown | recovery required; pending authority invalidated |
| 28 | backup | no partial package publication |
| 29 | restore | candidate restore not authoritative |
| 30 | cryptographic provider lookup | mandatory verification rejected |
| 31 | signature creation | signed object not created |
| 32 | signature verification | protected object rejected |

Focused tests parameterize all 32 seams with the exception class and assert one
activation record, HALT, and no authority. This is one focused test case per
critical seam.

## Fault classes

| Class group | Injected classes | Safe behavior |
|---|---|---|
| Call/control | exception, timeout, interrupted operation, process-termination simulation | raises `InjectedFault`; caller must fail closed/recover |
| Return integrity | malformed, missing, stale, duplicated return | explicit invalid value plus fault record; never authority |
| Byte/write integrity | corrupted bytes, partial write | explicit invalid bytes plus fault record; validation/quarantine required |
| Local resource | permission denied, memory allocation failure, thread creation failure, disk exhaustion, file-handle exhaustion | raises `InjectedFault`; bounded rejection |
| Provider/key | provider unavailable, wrong provider, wrong algorithm metadata, invalid key ID, revoked key | explicit invalid crypto result or exception; no fallback |
| Entropy/time | clock-source failure, nonce-source failure | raises `InjectedFault`; freshness/anti-replay path fails closed |

All 22 declared classes are parameterized in the focused suite. Return-class
faults carry their associated fault record. Exception-class faults expose the
same record on `InjectedFault`. Both forms assert `test_only=true` and
`authority_granted=false`.

## Test and evidence linkage

- Implementation: `sbp_lex/runtime/fault_injection.py`
- Focused test: `tests/test_runtime_pass8_resource_fault_soak.py`
- Resource snapshot: `outputs/runtime/pass_08_resource_budget_snapshot.json`
- Operational evidence: `outputs/runtime/pass_08_operational_resilience_evidence.json`

The fault harness does not alter architecture roles, traversal order, decisions,
or effect semantics. It introduces no live external dependency and cannot be
enabled by a fault specification alone.
