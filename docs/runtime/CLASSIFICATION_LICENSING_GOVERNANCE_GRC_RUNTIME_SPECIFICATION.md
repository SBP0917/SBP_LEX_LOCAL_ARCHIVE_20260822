# Classification → Licensing → Governance → GRC runtime specification

Status: Pass 5 bounded runtime contract. It operationalises the existing
blueprints without changing architecture or owner canon.

## Mandatory order and authority

The only admissible order is:

`certified PT → Classification → Licensing → Governance → GRC → Domain ingress`

Each stage consumes earlier authority and may constrain, deny, or escalate. No
stage manufactures execution permission, weakens the computed consequence tier,
raises the classified autonomy ceiling, broadens the licensed scope, changes the
resolved authority, or overrides certified PT.

## Closed stage evidence

Classification, Licensing, Governance, and GRC each emit exactly one signed
`desktop-v1.governed-stage-evidence.v1` record per traversal attempt. The record
binds:

- request fingerprint, EIE digest, traversal ID, and state hash entering stage;
- the hash-chain head entering finalisation;
- consequence tier and corroboration requirement;
- Root/PT and applicable governed upstream token/evidence digests;
- exact stage result, deterministic reason, and complete stage projection;
- a deterministic logical index and nonce.

The existing stage token, when the stage is eligible, binds the evidence digest
and exact stage projection. DENY or ESCALATE never retains an eligibility token.
The final stage hash entry binds the signed evidence digest and projection digest.

## Classification contract

- The AP/ACF precheck declaration is immutable into Classification.
- `autonomy_level` and `autonomy_ceiling` are non-Boolean integers in `0..100`.
- The effective ceiling is no greater than the existing AP/ACF class-profile
  default. A declaration may tighten but cannot raise that ceiling.
- Level cannot exceed the effective ceiling.
- Class, subclass, profile, environment, exposure, scope, restrictions,
  escalation flag, warnings, result, reason, and pipeline mode are one signed
  decision projection.
- Environmental escalation remains represented by the existing Classification
  flag and is decided by the existing Governance rules; Classification does not
  acquire Governance authority.

## Licensing contract

- A licence state must be explicit. Existing British/American aliases are
  reconciled; conflicting declarations fail closed.
- Accepted states remain exactly `DECLARED_VALID`, `VALID`, and
  `GOVERNANCE_MANAGED`.
- Structured licence declarations are normalized only if they survive the
  existing Hard Entry injection checks as a closed state wrapper; reserved or
  unsupported fields/shapes fail closed at Hard Entry or Licensing.
- The classified operational scope, context scope, requested scope, permitted
  scope set, and environment constraints must agree. No implicit hierarchy is
  used to justify broadening.
- The autonomy and scope assessments, normalized licence state/source, final
  scope, result, reason, failures, and Classification bindings are signed.

## Governance and GRC contract

- Governance preserves `ALLOW`, `DENY`, and `ESCALATE` exactly.
- Every Governance outcome has signed evidence and a hash-bound history entry.
  Only ALLOW receives a Governance eligibility token.
- GRC validates the complete governed upstream chain. ALLOW requires a valid
  Governance token; DENY/ESCALATE require valid signed Governance evidence and
  cannot be converted to PASS.
- GRC binds the structured outcome, governed re-entry assessment, Governance
  history, safe-state flags, and failures. Invalid upstream state is atomically
  normalized to DENY/HALT before GRC evidence is issued.
- Identical denied requests and retries without explicit material-change
  evidence remain inoperative under the existing re-entry rules. The signed GRC
  record prevents later deletion/substitution of the assessed history.

## Governed Domain handoff

Before any Domain candidate or engine is evaluated, Domain ingress requires:

- valid canonical request/control-chain/Root/PT state;
- exact Classification, Licensing, Governance, and GRC evidence/token lineage;
- Governance `ALLOW` and GRC `PASS`;
- intact hash chain, live state hash, tier, autonomy, authority, and scope
  continuity.

Failure produces a controlled Domain escalation with zero Domain attempts and no
Domain token. Domain reasoning itself is outside this specification.

## Determinism and evidence

Replay and dual-pipeline convergence compare the same Pass 5 projection:
results, reasons, state/evidence digests, governed token digests, constraint
snapshot, Governance history digest, and governed re-entry digest. Any mismatch
is exact, visible, and fail-closed; near-match reconciliation is never used.
