# PHQ Formal Deterministic Architecture Report

## Mission scope

PHQ adds a machine-checkable architectural formalisation and detached assurance subsystem for SBP-LEX Dual V6 Desktop V1. It models and verifies the owner-declared architecture as implemented. It does not replace, reorder, reinterpret, or expand the runtime architecture.

- Starting commit: `27c73c2b99d08e8e9bdbec874be279e1f4103dcf`
- Ending commit: the new local PHQ commit containing this report; its immutable hash is recorded in the task return because a commit cannot contain its own hash
- Scope: Desktop V1 local/private single-host runtime only
- Remote integration: explicitly excluded
- Push: prohibited for this mission

## Files and assurance artefacts

The implementation is bounded to:

- `sbp_lex/formal/model.py` — explicit formal states, transition records, H7 lifecycle reuse, and causal-lineage nodes
- `sbp_lex/formal/verifier.py` — executable invariant, impossible-state, conservation, lineage, safe-convergence, mode-law, transition, determinism, and runtime-snapshot assurance
- `sbp_lex/formal/assurance.py` — reproducible signed formal-assurance evidence builder and validator
- `sbp_lex/formal/schemas/` — strict formal-state, transition-record, and lineage-node schemas
- `tests/test_phq_formal_deterministic_architecture.py` — deterministic property, mutation, adversarial, mode, lineage, conservation, and integration coverage
- `outputs/phq_formal_architecture_assurance.json` — signed durable assurance evidence
- `sbp_lex/local_trust/critical_paths.py` — protection of PHQ sources, schemas, report, and output

The final committed file count and commit hash are recorded in the task return.

## Formalisation boundary

PHQ is a detached, non-authoritative assurance layer. Its results always record `authority_granted=false`. It cannot issue Classification, Licensing, Governance, GRC, Domain, Aurion, or execution authority; cannot issue H7 capabilities; cannot mutate canonical state; cannot execute; and cannot replace H7, H8, Local Trust, or the runtime.

The assurance layer may model, validate, compare, reject invalid representations, and produce tamper-evident evidence. Its stable owner identifier is `SBP_LEX_DESKTOP_V1_DETACHED_FORMAL_ASSURANCE`.

## Canonical state model

The model defines 30 controlled architectural states. It covers the complete owner-declared ingress and canonical traversal, H7 capability issuance/reservation/execution outcomes, audit finalisation, and the safe states `DENIED`, `ESCALATED`, `HALTED`, and `PERSISTENTLY_INOPERABLE`.

Each `FormalState` explicitly represents:

- architectural, decision, H7 capability, terminal, convergence, pipeline-mode, and audit state;
- required evidence and causal predecessor;
- request, EIE, canonical-state, runtime, baseline, and measurement bindings;
- tokens, authority, permissions, constraints, identities, evidence, pipeline summaries, H7 artefacts, topology, assurance requirements, and audit lineage.

Unknown state identifiers, result identifiers, model versions, modes, convergence values, capability values, fields, and missing mandatory bindings fail closed. No uncontrolled string result or undocumented hidden flag is accepted.

## Legal transition system

The model contains 105 explicit transition records. Every record declares its identifier, source, destination, preconditions, evidence, tokens, bindings, permitted modes, failure destination, terminal status, authority owner, and audit requirement.

The transition verifier rejects every undeclared edge, stage reversal, stage skip, pipeline-doctrine change, binding substitution, downstream restoration of failure, and arbitrary re-entry. Execution edges reuse the actual H7 state names and transition semantics rather than defining a competing capability lifecycle.

## Illegal-transition and impossible-state handling

Illegal or contradictory representations produce deterministic `FormalViolation` records containing a stable code, component, safe destination, and detail digest. They never produce authority.

Checks include missing upstream PASS/ALLOW results, incomplete token stack, failed convergence, missing measured-startup approval, request/state/EIE/runtime/baseline transplantation, completion without consumption, completion after cancellation or revocation, ambiguous completion promoted to success, expired active capabilities, missing execution attestation, false successful audit, external authority, alternative state construction, and invalid topology.

## Architectural invariants

Executable invariants enforce:

- external non-authority for External System, Adapter, EIE, SKG, DTN, UI, Viewer, APK, ODA, and PVPL;
- canonical-state singularity;
- State Construction before collective attachment;
- collective attachment before Root of Trust;
- Root of Trust before Procedural Truth;
- Procedural Truth before Classification;
- Classification before Licensing;
- Licensing before Governance;
- Governance before GRC;
- GRC before Domain;
- Domain before Aurion;
- Aurion before Execution Gate;
- Execution Gate before Audit;
- H7 integrity and audit continuity;
- Desktop V1 local/private single-host and zero-node topology.

## Conservation laws

The verifier compares consecutive formal states and detects:

- authority or permission expansion;
- licensing broadening;
- removed or weakened H7-compatible constraints;
- downstream restoration of denial;
- identity, request, EIE, state, runtime, or baseline substitution;
- evidence provenance, source, schema, signature, package, or dependency mutation;
- silent Classification decrease;
- consequence-tier downgrade;
- corroboration reduction;
- audit-lineage deletion or rewrite.

Equal or narrowed authority, permission, licensing, and constraints are accepted. A broader state requires a fresh complete traversal outside the compared lineage.

## Causal-lineage model

The causal model covers 22 ordered node types from external request through native protocol, adapter, EIE, SKG, DTN, Hard Entry, canonical state, collective attachment, Root of Trust, Procedural Truth, Classification, Licensing, Governance, GRC, Domain, Aurion, Execution Gate, H7 capability, execution result, execution attestation, and audit.

Every node is digest-bound to its immediate predecessor and to the request fingerprint, canonical state hash, EIE digest, runtime identity, measured baseline, and evidence. Verification rejects missing or unknown predecessors, duplicates, cycles, prohibited forks, reordering, truncation, stale evidence, binding mismatch, token transplantation, and execution-attestation transplantation.

## Safe-state convergence

Every declared failure class maps deterministically to a bounded safe destination. Unknown failure converges to `PERSISTENTLY_INOPERABLE`. No emergency execution, temporary allow, operator shortcut, approximate convergence, or automatic retry of ambiguous execution exists in the formal specification.

Safe-state results are audit-visible, replay-verifiable, non-restorative downstream, and cannot independently execute.

## Pipeline-mode laws

The exact existing modes are formalised:

- `MODE_1_FULL_MIRRORED` requires two complete pipelines, identical request/EIE/state and outcome bindings, exact parity, and matched convergence. Approximate or probabilistic parity is rejected.
- `MODE_2_SPLIT_VALIDATOR` keeps Pipeline A primary and Pipeline B validator-only. Pipeline B cannot independently authorise, weaken Pipeline A, override Governance, or permit execution after required validation failure.
- `MODE_3_SINGLE_CONSTRAINED` requires one active deterministic traversal with every mandatory control layer and rejects use where a stronger mode is required.

All modes preserve the same authority doctrine, mandatory layers, H7 integrity, audit, failure propagation, and persistent-inoperability behavior.

## Property-based assurance evidence

No new dependency was introduced. Deterministic generated-sequence tests use a fixed seed (`917`) and recorded bounds. They generate legal canonical prefixes and illegal edges, proving within the implemented test domain that legal sequences do not skip stages and undeclared transitions cannot progress.

Repeated formal verification, map-key reordering, signed artefact reconstruction, and formal replay produce stable digests for identical inputs.

## Mutation-protection verification

Isolated synthetic mutations cover removal or alteration of Classification-before-Licensing, Governance-before-GRC, upstream Domain clearance, Aurion self-authorisation, Mode 1 exact parity, request/state bindings, token stage, H7 single use, cancellation, constraint continuity, audit presence, external state construction, attachment order, Root-of-Trust precedence, and direct downstream re-entry. Production files are not mutated by these tests.

Each weakening produces a formal rejection or a failed transition/property assertion.

## H7 integration

PHQ imports the actual H7 capability states, terminal states, transitions, constraint-continuity predicate, capability verifier, and post-execution attestation verifier. It does not duplicate or supersede H7 lifecycle authority. A capability represented to PHQ must remain request-, EIE-, state-, pipeline-, runtime-, baseline-, measurement-, target-, operation-, parameter-, constraint-, temporal-, revocation-, cancellation-, and audit-bound under H7.

## H8 and measured-baseline transition

PHQ source and schemas fall under H8 software/schema measurement. The final measured baseline is deliberately proposed and approved only after this report, the PHQ output, all protected sources, schemas, and rebuilt Local Trust evidence are final. The exact final baseline identifier and runtime identity are recorded in the task return.

The existing signed, acyclic, sequence-increasing baseline lineage and rollback protections remain unchanged.

## Verification status at report finalisation

Completed before protected evidence refresh:

- targeted PHQ suite: 227 passed;
- focused PHQ + H7 + H8 suite: 389 passed;
- PHQ assurance build/validate/show: `PHQ_FORMAL_ASSURANCE_VALID`;
- formal specification digest: `fc9c1c7be6c7252c72bea5eae962b153a0c4cef5d29ea7756f45e71528c1d586`;
- architectural states: 30;
- explicit transition records: 105;
- assurance authority: false;
- compile check for the PHQ package: pass;
- diff check: pass.

The mandated full direct suite, batch wrapper, Local Trust build/validate/compare, constitutional gates, toolchain guard, release integrity, adversarial harness, validation dossier, capstone, measured startup, real runtime, replay, commit, and post-commit verification occur after this protected report is final. Their factual results are recorded in the final task return.

## Architecture assessment and no-node confirmation

No runtime stage, traversal order, operational component purpose, pipeline implementation, token authority, execution rule, or audit authority was changed. PHQ adds only subordinate assurance. No distributed node, quorum, mesh, cloud authority, governance-node authority, or cognitive pipeline was introduced.

## Remaining limitations

- This is an executable machine-checkable architectural formalisation with property and mutation assurance; it is not a claim of complete mathematical proof by a recognised theorem prover or model checker.
- Generated properties are bounded by the explicit deterministic test domain and fixed examples.
- PHQ verifies representations supplied to it. It does not intercept runtime execution and has no authority to do so.
- The runtime’s operational controls, H7, H8, and Local Trust remain the enforcement authorities; PHQ does not replace them.
- Hardware-backed monotonicity and externally anchored host-compromise detection remain outside Desktop V1.

## Repository preservation

- Remote divergence: `origin/main` remains at `cb99c3c65f59ec043be98f28bc91a78ef0719cd7`; its remote-only README commit is not integrated or modified.
- Stash: the existing Phase 19D-D stash is not applied, modified, or deleted.
- Cognitive branch: `phase19e-cognitive-pipelines-experimental` and its separate worktree are untouched.
- Push status: no push is permitted or performed in this mission.
