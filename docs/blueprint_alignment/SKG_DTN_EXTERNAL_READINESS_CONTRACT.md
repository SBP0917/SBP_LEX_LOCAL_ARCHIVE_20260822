# SKG/DTN External Readiness Contract

Draft status: BLUEPRINT-SKGDTN-ALIGN-01 proposed alignment material only. This document does not replace master doctrine unless the repository owner later approves canonisation.

## Purpose

The SKG/DTN external readiness layer defines how external truth, authority, environmental context, and feasibility signals are prepared before internal control-plane entry.

## Position

The readiness chain is:

External System -> Native Format / Protocol -> Adapter Translation -> EIE: Execution Intent Envelope -> SKG verification of EIE truth foundations -> DTN contextual corroboration / environmental validation -> Pre-context signal package -> Hard Entry Gate -> State Construction -> Collective Signal Attachment -> Root of Trust -> Procedural Truth / Threshold Conditioning -> Classification -> Licensing -> Governance -> GRC -> Domain Wrap -> Aurion -> Execution Gate -> Audit

## EIE Role

EIE is the structured envelope that normalises execution intent before SKG/DTN readiness evaluation.

EIE must contain, at minimum:

- request identity
- source system identity
- native format/protocol origin
- adapter translation record
- operator/system intent
- action objective
- target system/object
- declared deployment context
- declared AP-ACF class/autonomy data if available
- requested capability
- declared authority source if available
- environmental context if available
- timestamp/freshness data
- request fingerprint or pre-fingerprint
- digest/signature readiness fields if available

EIE must not:

- govern
- execute
- classify final admissibility
- license
- override later layers
- bypass Hard Entry Gate

## SKG Readiness Role

SKG verifies truth foundations of EIE.

SKG may evaluate:

- authority hierarchy
- jurisdiction
- legitimacy
- procedural obligation
- legal/sovereign precedence
- rule lineage
- authority conflict
- source legitimacy
- policy conflict
- declared authority validity

SKG output must be:

- external
- structured
- minimal
- signed/digest-ready
- request-bound
- freshness-bound
- non-executing

SKG must not:

- execute
- issue runtime ALLOW/DENY/ESCALATE
- bypass governance
- enter the internal control plane as raw substrate
- be overridden by DTN

## DTN Readiness Role

DTN evaluates contextual corroboration and environmental validation under SKG constraints.

DTN may evaluate:

- operational state
- feasibility
- environmental condition
- dependency state
- pathway viability
- risk/harm/infeasibility context
- system capability reality
- unsafe/impossible pathway indicators
- deployment condition mismatch
- contextual contradiction

DTN output must be:

- constrained by SKG
- external
- structured
- minimal
- signed/digest-ready
- request-bound
- freshness-bound
- non-executing

DTN must not:

- override SKG
- govern
- execute
- issue runtime ALLOW/DENY/ESCALATE
- enter the internal control plane as raw substrate

## SKG -> DTN Relation

Locked relation:

- SKG constrains DTN.
- DTN evaluates pathways under SKG constraints.

DTN can report operational contradiction or infeasibility, but it cannot erase, soften, or replace SKG authority/legitimacy constraints.

## Pre-Context Signal Package

The readiness package contains:

- intent_signal
- authority_link_signal
- jurisdiction_signal
- legitimacy_signal
- procedural_requirement_signal
- policy_conflict_signal
- operational_context_signal
- dependency_signal
- pathway_viability_signal
- risk_potential_signal
- environment_signal
- capability_reality_signal
- precedence_signal
- AP-ACF declaration signal where available
- autonomy ceiling signal where available
- digest
- signature
- timestamp
- nonce
- request binding

Only the validated pre-context signal package crosses inward. Raw SKG/DTN substrates remain external.

## Failure Modes

Failure modes use readiness/failure labels only. They do not use runtime decision statuses.

| Failure Mode | Source Layer | Expected Downstream Handling |
| --- | --- | --- |
| EIE_MALFORMED | EIE | fail closed, deny ingress, preserve evidence |
| EIE_UNBOUND | EIE | fail closed, deny ingress, preserve evidence |
| EIE_STALE | EIE | fail closed or escalate freshness review, preserve evidence |
| SKG_UNAVAILABLE | SKG | fail closed or mark Phase19A runtime proof pending, preserve evidence |
| SKG_AUTHORITY_CONFLICT | SKG | escalate, deny ingress until resolved, preserve evidence |
| SKG_LEGITIMACY_FAIL | SKG | fail closed, deny ingress, preserve evidence |
| SKG_PROCEDURAL_REQUIREMENT_UNRESOLVED | SKG | escalate, preserve evidence |
| DTN_UNAVAILABLE | DTN | fail closed or mark Phase19A runtime proof pending, preserve evidence |
| DTN_CONTEXT_CONFLICT | DTN | escalate or deny ingress, preserve evidence |
| DTN_FEASIBILITY_FAIL | DTN | fail closed, deny ingress, preserve evidence |
| DTN_ENVIRONMENT_MISMATCH | DTN | fail closed or escalate, preserve evidence |
| DTN_DEPENDENCY_FAIL | DTN | fail closed, preserve evidence |
| PRE_CONTEXT_SIGNAL_INVALID | Pre-context package | deny ingress, preserve evidence |
| PRE_CONTEXT_SIGNAL_STALE | Pre-context package | deny ingress or escalate freshness review, preserve evidence |
| PRE_CONTEXT_SIGNAL_SIGNATURE_FAIL | Pre-context package | fail closed, deny ingress, preserve evidence |
| PRE_CONTEXT_SIGNAL_DIGEST_FAIL | Pre-context package | fail closed, deny ingress, preserve evidence |

## Domain Boundary

SKG/DTN determine what is true.

Domain determines what is allowed to exist.

Domain consumes verified truth outputs and converts them into constraints. Domain must not re-simulate, re-detect, infer intent, or compute risk models.

## Phase19A Readiness Preconditions

Phase19A requires:

- EIE fixture schema
- SKG readiness fixture
- DTN readiness fixture
- pre-context signal fixture
- failure-mode fixtures
- signal digest/signature placeholders or real provider contract depending current repo capacity
- no live substrate dependency
- no cloud dependency
- no external actuation

Phase19A must remain local/private/runtime-controlled unless a later owner-approved phase explicitly advances beyond that boundary.
