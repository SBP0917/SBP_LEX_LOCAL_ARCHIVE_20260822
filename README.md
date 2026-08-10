# SBP-LEX Dual V6 Desktop V1

SBP-LEX Dual V6 Desktop V1 is a deterministic AI-governance and execution-control engineering baseline. It evaluates bounded requests through a fixed authority-first control sequence and permits execution only when every required decision, binding, integrity check, and audit condition is satisfied.

Desktop V1 is intentionally local-first, private, single-host, and no-node. It does not depend on distributed consensus, cloud authority, remote governance nodes, or cognitive pipeline functionality.

## Engineering posture

The runtime is designed around these properties:

- deterministic processing and replay;
- fail-closed handling of invalid, incomplete, contradictory, stale, or unverifiable state;
- authority-first evaluation before downstream governance and execution;
- exact request, state, identity, evidence, policy, and execution bindings;
- no downstream restoration of an upstream denial or invalid state;
- auditable outcomes and tamper-evident engineering evidence;
- measured startup before runtime execution;
- explicit approved runtime identity and drift detection;
- local operation within the Desktop V1 trust boundary.

## Canonical control architecture

The owner-declared control flow is fixed:

```text
External System
-> Native Format / Protocol
-> Adapter Translation
-> Execution Intent Envelope (EIE)
-> SKG verification
-> DTN contextual verification
-> Hard Entry Gate
-> State Construction
-> Collective Signal Attachment
-> Root of Trust
-> Procedural Truth
-> Classification
-> Licensing
-> Governance
-> GRC
-> Domain
-> Aurion
-> Execution Gate
-> Audit
```

External inputs, adapters, evidence packages, viewers, and support tooling do not possess canonical runtime or execution authority. State Construction remains the sole canonical internal state-construction point.

## Runtime assurance

### Measured startup and runtime identity

Before execution is permitted, Desktop V1 measures approved software, configuration, policies, schemas, dependencies, trust evidence, environment posture, and runtime components. Measurements are compared with an explicitly approved baseline. Critical, unknown, corrupted, rolled-back, or unexplained drift fails closed.

The approved measured state produces a deterministic runtime identity. Baseline changes require explicit approval and preserve signed lineage; changed measurements are never accepted automatically.

### Deterministic replay

Replay evaluates the same bounded request through the same canonical controls and compares decision-relevant fields. Mismatches are reported and do not establish execution legitimacy.

### External trust boundary

External identities, signed packages, transport context, trust stores, and replay state are validated before they can contribute bounded evidence. External substrates remain non-authoritative and cannot create governed internal state or execution authority.

### Cryptographic integrity

Security-relevant tokens, evidence, capabilities, attestations, baselines, and assurance artefacts are digest-bound and signed under the repository's cryptographic provider policy. Required provider or verification failures fail closed. Cryptographic evidence supports integrity and provenance; this repository does not claim third-party certification.

## H7 — deterministic execution integrity

H7 protects the boundary between an approved canonical traversal and an external effect. Execution uses a strict, single-use capability lifecycle:

```text
PENDING -> ACTIVE -> RESERVED -> EXECUTING -> terminal state
```

Terminal states include `COMPLETED`, `FAILED`, `CANCELLED`, `EXPIRED`, `REVOKED`, `AMBIGUOUS`, and `RETIRED` where applicable.

Capabilities are bound to the approved request, EIE, canonical state, pipeline results, convergence, target, operation, normalized parameters, constraints, adapter, runtime identity, measured baseline, and audit lineage. Reservation and consumption are durable and race-safe. Cancellation, revocation, expiry, mid-execution invalidation, incomplete completion evidence, or ambiguous effects cannot be promoted to successful completion.

## PHQ — formal deterministic architecture

PHQ provides a detached, non-authoritative, machine-checkable architectural formalisation. It defines explicit architectural states, declared transitions, impossible-state detection, invariants, conservation laws, causal lineage, safe-state convergence, and equivalence laws for the three Desktop V1 pipeline modes.

PHQ also supplies deterministic property-based assurance and mutation-protection tests. It can model, verify, reject, and report; it cannot issue decisions, tokens, governance outcomes, or execution capabilities, and it cannot mutate runtime state.

PHQ is executable assurance over the implemented model. It is not presented as a complete mathematical proof by an external theorem prover or as a certification.

## Repository assurance

The repository maintains a local evidence chain comprising:

- **Local Trust** — protected manifests, evidence comparison, regression evidence, release integrity, validation dossier, adversarial negative testing, and capstone evidence;
- **Constitutional Gates** — machine-enforced architectural and repository invariants;
- **Toolchain Guard** — approved toolchain, dependency, command, and provenance checks;
- **Release Integrity** — digest-bound release manifests and artefact indexes;
- **Formal Assurance** — PHQ state, transition, lineage, property, mutation, and deterministic evidence.

Changes to protected source, policy, schema, documentation, or evidence require deliberate reconciliation. Unknown or unexplained changes are rejected rather than silently incorporated.

## Pipeline modes

Desktop V1 supports three deterministic assurance modes:

- full dual mirrored traversal;
- primary traversal with validator assurance;
- constrained single-pipeline traversal.

Modes may vary redundancy and validation depth. They do not change mandatory authority law, Procedural Truth, Classification, Licensing, Governance, GRC, Domain, Aurion limits, Execution Gate requirements, H7 integrity, audit continuity, or failure propagation.

## Scope

This repository represents the Desktop V1 engineering baseline. It is intended for technical review, reproducible local verification, and continued bounded engineering work.

Desktop V1 does not claim public deployment readiness, commercial certification, regulatory approval, or complete formal proof. Deployment-sensitive configuration, credentials, private trust material, and operational infrastructure are outside the repository landing-page scope.

Experimental cognitive work remains isolated from the canonical Desktop V1 runtime.

## Integrated Video Studio

Desktop V1 includes SBP Video Studio 0.2 as a general-purpose, local scene and
video construction application. Start the normal Windows launcher,
`scripts\run_desktop_runtime.bat`, open the UI Cockpit, and select **Video
Studio**. The editor owns a deterministic scene manifest and supports scene
graphs, environment and object construction, cameras, lighting, shaders,
animation, VFX, HUD/data graphics, audio synchronization hooks, imported assets,
and Blender/FFmpeg render export.

Video Studio runs as a separate loopback companion with `runtime_authority:
"NONE"`. Its Cockpit adapter reads detached observability snapshots only and
preserves slower rehearsal, full-speed traversal, and constructed scenario
presentation modes. It cannot make governance decisions, authorize execution,
or mutate canonical runtime state. See `docs/VIDEO_GENERATOR.md`.

## Local verification

From an approved local environment:

```text
scripts\run_double_triple_assurance.bat
```

That default command is the sole pre-handover gate. It runs the complete suite
once, the startup-to-terminal linkage suite in three fresh processes, strict
schema/static/dependency/Git checks, and the production evidence and
repository-bound R4 verification chain. A source-only or evidence-only
diagnostic run does not authorize handover.

For ordinary development diagnostics:

```text
python -m compileall -q .
python -m pytest -q
scripts\run_tests.bat
python main.py
python main.py replay
```

Additional repository commands validate measured startup, Local Trust, evidence comparison, Constitutional Gates, Toolchain Guard, Release Integrity, the validation dossier, adversarial negative evidence, PHQ formal assurance, and the capstone baseline.

The production ML-DSA public verification key and its expected SHA-256
fingerprint must be obtained through a separate authenticated channel. The
handover package cannot establish its own trust root.
