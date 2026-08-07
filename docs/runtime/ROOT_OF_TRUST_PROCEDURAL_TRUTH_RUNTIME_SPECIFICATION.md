# Root of Trust and Procedural Truth Runtime Specification

Status: Runtime Pass 4 Desktop V1 implementation contract.

## Purpose and scope

This specification defines the deterministic repository-side contract for the
Root of Trust, Procedural Truth evidentiary sufficiency, and threshold
conditioning. It applies to the local/private Dual V6 Desktop V1 runtime.

The canonical traversal remains:

`Validated canonical state -> Collective Signal Attachment -> Root of Trust -> Procedural Truth -> Classification -> Licensing -> Governance -> GRC -> Domain Wrap -> Aurion -> Execution Gate -> Audit / Replay / Telemetry`

This pass does not change architectural ownership or downstream decision
authority. SKG and DTN remain external, context-only substrates. The runtime
uses only validated synthetic local packages and introduces no live provider,
credential, cloud, node, mesh, quorum, or distributed-runtime linkage.

## Canonical boundary entering Root

Root accepts only the state emitted by the sealed `PreparedPipelineBoundary`
after Hard Entry, canonical state construction, collective attachment, and the
AP-ACF precheck. Before the first Root substage, the runtime verifies:

- the current canonical state hash;
- Hard Entry admission and protected-state fields;
- request fingerprint and canonical request identity;
- canonical EIE structure and digest;
- validated SKG, DTN, and bridge references;
- the collective projection digest, signature, freshness, nonce, request and
  EIE bindings;
- the one-time collective attachment hash and signature;
- authority and jurisdiction agreement;
- the PT envelope digest and its admitted request/EIE/substrate bindings.

The attachment contains a closed `root_trust_material` projection. It carries
only authority, attestation, and truth facts already established by the signed
local context and the validated synthetic SKG/DTN/bridge boundary. Its
`validation_basis` records those validation statuses and digests. The
projection cannot govern, classify, license, or authorise execution.

## Locked Root chain

The Root engine executes exactly once and in this order:

1. `anchor_validation`
2. `attestation`
3. `attestation_consensus`
4. `truth_anchor`
5. `truth_continuity`
6. `truth_expiry`
7. `truth_revocation`

Each substage consumes the same captured Root-input basis. Each emits a
deterministic PASS or FAIL record into the existing Root hash-chain stage.
Execution stops on the first failed substage. A later Root substage is never
called after failure.

### Anchor validation

Anchor validation requires exact request, EIE, collective signal, authority,
jurisdiction, substrate-validation, and attachment agreement. Authority must
be resolved and legitimate on the admitted SKG validation basis. An authority
assertion in a collective signal does not manufacture runtime authority.

### Attestation and exact consensus

Every applicable attestation is checked for identity, subject, issuing
authority, jurisdiction, request, EIE, collective signal, timestamp, validity
interval, nonce, status, revocation state, digest, and signature/boundary
integrity. Desktop single-attestation mode passes only when its one mandatory
attestation is valid.

Consensus is an exact deterministic agreement check. All applicable valid
attestations must identify the same admitted request, EIE, authority,
jurisdiction, and collective statement digest. There is no score, percentage,
weight, tolerance, or near-match result.

### Truth anchor and continuity

The truth anchor is constructed only after successful anchor, attestation, and
consensus stages. It binds the captured Root input, authority and attestation
identities, collective signal, PT envelope, entering state hash, audit-chain
head, token-chain reference, timestamp, and nonce. Its digest and signature
are verified before continuity is established.

Truth continuity requires the existing hash chain to remain valid and requires
the truth predecessor/reference, request, EIE, authority, attestation,
collective signal, and Root-input identities to remain unchanged.

### Expiry and revocation

Expiry uses the admitted deterministic logical clock and closed validity
intervals. Future, stale, or expired authority, attestation, collective, or
truth material fails. Revocation uses signed/admitted authority, attestation,
and truth status; mutable module globals do not constitute the decision basis.

## Aggregate Root evidence and token eligibility

Every Root attempt creates one signed `root_of_trust_evidence` record. The
payload includes:

- request fingerprint and EIE digest;
- canonical state hash entering Root;
- collective signal and attachment digests;
- authority, jurisdiction, and attestation identities;
- admitted validation basis, timestamps, and nonces;
- exact ordered substage results;
- Root result, reason, and stopped stage;
- PT-envelope and audit/token-chain references.

`root_evidence_digest` is the digest of the signed payload. The compatibility
`root_of_trust_evidence_anchor` remains available, but the aggregate record is
the authoritative downstream validation object. The authority token is issued
only after the complete chain passes and binds the aggregate Root digest and
continuity identities.

On failure, Root invalidates compatibility anchorage, removes authority and PT
eligibility tokens, clears any PT PASS state, records persistent
inoperability, and requires full corrected retraversal. Root never repairs
invalid upstream evidence.

## Procedural Truth entry contract

PT can run only after a successful, fully verified aggregate Root record and a
valid authority token. PT revalidates the Root record against the current
request, EIE, collective signal, PT envelope, and captured Root state. This
prevents post-Root envelope/source substitution and cross-request or cross-EIE
Root reuse.

The one authoritative PT path remains:

`evidence_validation -> threshold_conditioning -> corroboration -> procedural_consistency -> final PT certification`

PT does not classify, license, govern, perform Domain/Aurion reasoning, or
authorise execution.

## Source assessment and qualifying-evidence law

PT constructs one deterministic assessment for every evidence entry. A source
qualifies only when all applicable predicates pass:

- source identity and evidence content are well formed;
- evidence digest/integrity is valid;
- verification and attestation are valid;
- provenance and chain of custody are valid;
- freshness/runtime validity is valid;
- consistency and contradiction handling are valid;
- authority and jurisdiction are valid;
- the evidence is relevant to the canonical action/claim;
- request, EIE, and collective-signal bindings match;
- the source is independent under the existing source identity model.

Missing trust properties are never silently assumed true. A property may be
recorded as valid only when it was explicit in the source or was
deterministically established by the admitted signed synthetic boundary; the
assessment records that derivation basis. An explicit false or conflicting
binding always wins and makes the entry non-qualifying.

Independence uses the existing provenance identity keys. A stable source URI
is preferred; otherwise the stable source ID/name is used. Duplicate entries
and aliases with the same detectable provenance identity are excluded from the
unique qualifying count and recorded separately. Entry count alone never
certifies PT.

## Evidentiary sufficiency

The PT evidence assessment is a distinct deterministic state. It records total
entries, well-formed entries, unique qualifying identities, duplicates,
rejections and reasons, identity summary, evidence-set digest, verification,
attestation, freshness, provenance, relevance, consistency, completeness,
active tier, required corroboration, and observed corroboration.

Sufficiency passes only when the evidence set is relevant, source-bound,
provenance-valid, temporally valid, internally consistent, contradiction-safe,
complete for the requested action and active tier, and contains the required
number of unique qualifying sources. Sufficient count cannot override another
failed dimension.

The controlled outcomes remain `PT_PASS`, `PT_REFINE`, `PT_ESCALATE`, and
`PT_FAIL`. A final runtime PT result is PASS only for `PT_PASS` with a
`CERTIFIED` sufficiency record.

## Threshold conditioning

The four consequence factors are integers in the closed range 0 through 3:

- `human_safety`
- `irreversibility`
- `cascading_impact`
- `financial_operational`

The active value is their maximum. A value of 3 maps to TOP, 2 maps to MEDIUM,
and 0 or 1 maps to LOW. The minimum unique corroboration floors are fixed:

| Tier | Qualifying sources |
|---|---:|
| LOW | 2 |
| MEDIUM | 3 |
| TOP | 5 |

The preserved AUD financial bands are:

- LOW through AUD 499.99;
- MEDIUM from AUD 500.00 through AUD 49,999.99;
- TOP from AUD 50,000.00.

Financial input must be finite and non-negative. It can raise the maximum
factor but cannot lower a higher human-safety, irreversibility, or cascading
factor.

The sealed, digested, and token-bound threshold-conditioning record captures factor inputs,
financial basis, previous tier, current tier, high-water tier, transition,
corroboration requirement, EIE/Root/evidence bindings, and monotonicity result.
Only LOW-to-MEDIUM, LOW-to-TOP, MEDIUM-to-TOP, or same-tier transitions are
valid in an existing traversal. A downgrade requires a newly admitted,
governed full retraversal; direct mutation remains ineligible.

## PT evidence and tokens

Final certification is built before token issuance. A PT token and applicable
threshold tokens are issued only after certified PT PASS. The signed
`procedural_truth_evidence` payload binds:

- request fingerprint, EIE digest, collective signal digest, and Root digest;
- state hash at PT certification;
- source counts, identities, assessment and sufficiency digests;
- factor values, tier, transition/high-water state;
- required and observed corroboration;
- PT result, outcome, reason, stage, timestamp, and deterministic nonce.

The PT token repeats the required continuity fields and binds the PT evidence
digest. Existing threshold tokens retain their architecture; verification now
compares signed component values, tier, corroboration requirement, stage, and
bundle hashes with the live sealed threshold state. Same-request stale semantic
reuse fails even when a token signature remains cryptographically valid.

## Downstream invariant

Classification and every immediate later-stage entry use one Root/PT
eligibility validator. It verifies the aggregate Root record, PT evidence,
authority and PT tokens, certification, tier/corroboration state, and threshold
bundle. A direct stage call cannot restore a Root/PT-invalid state.

The guard changes no downstream decision authority. Classification, Licensing,
Governance, GRC, Domain, Aurion, and Execution Gate retain their native work;
they simply receive no eligible state when Root or PT is invalid.

## Determinism, parity, replay, and lineage

Both pipelines materialize the same sealed boundary. Exact initial parity
covers EIE, authority material, collective digest, source set, safety factors,
initial tier, and corroboration requirement. Exact result parity covers Root
result/reason/digest, PT result/outcome/digest, unique qualifying count,
sufficiency, tier, and required/observed corroboration. No tolerance or
near-match reconciliation exists. Any applicable mismatch halts and escalates
under the existing convergence contract.

Replay compares the same Root/PT fields and their deterministic reasons and
digests. The existing hash chain receives aggregate Root and PT lineage entries
with prior hash, request/EIE/state bindings, results, counts, tier, sufficiency,
and evidence digests. Audit stores the signed records and bounded lineage
projections; this is Pass 4 evidence, not a redesign of the Pass 7 audit
architecture.

## Recovery and Pass 5 handoff

Root or PT failure is mechanically non-executable. Manual status replacement,
token replacement, downstream ALLOW/PASS, Domain/Aurion success, presentation
changes, omission of failed evidence, replay, or direct Execution Gate entry
cannot clear it.

Recovery requires corrected material and the existing full path through EIE
validation, SKG/DTN validation, Hard Entry, State Construction, Collective
Attachment, Root, and PT. Pass 4 ends at the certified Classification handoff;
it does not implement Pass 5 Classification, Licensing, Governance, or GRC
hardening.
