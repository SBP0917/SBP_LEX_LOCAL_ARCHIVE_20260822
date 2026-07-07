# Blueprint Alignment Addendum Pack

Draft status: BLUEPRINT-SKGDTN-ALIGN-01 proposed text only. Do not insert into canonical documents until owner review approves.

## A. Universal EIE Insertion Addendum

Execution intent enters the SBP-LEX chain through a structured Execution Intent Envelope after adapter translation and before SKG/DTN readiness evaluation.

Controlled flow:

External System -> Native Format / Protocol -> Adapter Translation -> EIE: Execution Intent Envelope -> SKG verification of EIE truth foundations -> DTN contextual corroboration / environmental validation -> Pre-context signal package -> Hard Entry Gate -> internal control-plane chain.

EIE is a structured normalisation envelope. It binds request identity, source identity, native/protocol origin, adapter translation record, intent, objective, target, deployment context, declared authority where available, environmental context where available, AP-ACF/autonomy fields where available, timestamp/freshness data, and digest/signature readiness fields where available.

EIE does not govern, execute, classify final admissibility, license, override later layers, or bypass the Hard Entry Gate.

## B. SKG/DTN External Readiness Addendum

SKG and DTN are external readiness substrates. They prepare validated signals before internal control-plane entry. Raw substrate state does not enter the control plane.

SKG verifies the truth foundations of the EIE, including authority hierarchy, jurisdiction, legitimacy, rule lineage, procedural obligation, policy conflict, and declared authority validity.

DTN evaluates contextual corroboration and environmental validation under SKG constraints, including feasibility, operational state, dependency state, environmental condition, pathway viability, capability reality, and contextual contradiction.

Locked relation:

- SKG constrains DTN.
- DTN evaluates pathways under SKG constraints.

Only a validated, request-bound, freshness-bound, digest/signature-ready pre-context signal package may approach the Hard Entry Gate.

## C. Dual Adaptive Traversal Addendum

Dual Adaptive traversal uses the declared risk tier to scale traversal depth, redundancy, and governance intensity without relaxing convergence.

- LOW -> Single Pipeline Deterministic Traversal
- MEDIUM -> Split Governance Traversal / Validator Architecture
- TOP -> Full Dual Parallel Deterministic Traversal

Execution convergence remains mandatory at all tiers. Only traversal depth, redundancy, and governance intensity change.

No pipeline/order inference is allowed. User-declared order controls.

## D. Domain Boundary Addendum

SKG and DTN determine what is true.

Domain determines what is allowed to exist.

Domain is enforcement, not intelligence. Domain consumes verified SKG/DTN truth outputs and converts them into non-bypassable constraints. Domain must not re-simulate, re-detect, infer intent, compute risk models, override SKG/DTN, or absorb SKG/DTN intelligence work.

## E. PQC Stale-Placeholder Addendum

Older local deterministic placeholder/HMAC wording is superseded where the current repository implements the real PQC provider contract.

Current repository scope: `cryptography.mldsa` provider contract with ML-DSA as the primary signature algorithm, SLH-DSA reserved as backup signature policy, ML-KEM as KEM basis for future use, provider availability required, and fail-closed behavior when provider unavailable.

This addendum does not claim certified PQC compliance, production cryptographic certification, or full post-quantum security beyond the implemented provider contract.

## F. Phase19A Precondition Addendum

Controlled traversal activation should use EIE/SKG/DTN readiness fixtures and remain local/private/runtime-controlled unless explicitly advanced by later owner-approved phase instruction.

Minimum Phase19A preconditions:

- EIE fixture schema
- SKG readiness fixture
- DTN readiness fixture
- pre-context signal fixture
- SKG/DTN failure-mode fixtures
- digest/signature readiness fields consistent with current provider capacity
- no live substrate dependency
- no cloud dependency
- no external actuation

Phase19A must not silently convert external SKG/DTN readiness into production deployment, public publication, cloud execution, or runtime authority delegation.
