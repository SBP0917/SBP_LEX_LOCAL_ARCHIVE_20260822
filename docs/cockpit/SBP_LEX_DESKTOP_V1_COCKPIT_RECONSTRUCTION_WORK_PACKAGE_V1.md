# SBP-LEX Dual V6 Desktop V1
## Cockpit Reconstruction Work Package V1

**Classification:** Non-canonical implementation work package  
**Repository:** `SBP0917/SBP_LEX_DUAL_V6`  
**Planning branch:** `ui-cockpit-reconstruction-planning`  
**Planning base:** `55ff03ec6991aa4a1da3c4e4793896292086fa93`  
**Runtime authority:** None  
**Governance authority:** None  
**Status:** Build preparation started; implementation blocked from merge until final IVVF / university-handover baseline is confirmed.

---

## 1. Purpose

Reconstruct the Desktop V1 operator cockpit as a practical hands-on and visual comprehension interface for assessors and operators without changing SBP-LEX architecture, pipeline order, decision authority, execution authority, or canonical terminology.

The reconstructed cockpit must help a user understand:

- what SBP-LEX is designed to govern between intention and execution;
- which pipeline mode is active and why;
- where a state is within traversal;
- which stage passed, constrained, denied, escalated, re-looped, converged, halted, executed, audited, or replayed;
- how realistic automation scenarios are assessed;
- how technical verification differs from conceptual demonstration;
- how audit, replay, PVPL, trust, and evidence artefacts can be inspected.

The cockpit remains a presentation, observability, bounded-input, and evidence-inspection layer only.

---

## 2. Mandatory separation of interface functions

The cockpit must present three clearly separated functions.

### 2.1 Visual Conceptual Recognition Scenarios

Purpose: slower explanatory demonstrations for hands-on understanding.

Requirements:

- selectable synthetic scenarios;
- stage names displayed above and below the horizontal pipeline axis;
- slower cadence than technical verification;
- concise explanation of what is happening, where it is happening, and why;
- clear display of selected Mode 1, Mode 2, or Mode 3;
- visible explanation of Domain constraint application, Aurion pathway resolution, convergence, execution-gate result, audit, replay, and PVPL evidence;
- conceptual outputs must never be represented as implementation verification evidence.

### 2.2 Technical Implementation Verification Suites

Purpose: display actual repository test execution and evidence.

Requirements:

- suite names must be discovered from the repository; do not invent authoritative suite names;
- actual commands, commit, runtime, baseline, test totals, duration, evidence path, and result must be shown;
- stage bubbles alternate above and below the horizontal axis;
- stage cadence:
  - new stage every approximately `0.20 s`;
  - each bubble visible approximately `0.25 s`;
  - approximately `0.05 s` overlap;
- technical suite output remains distinct from conceptual scenario output;
- no simulated pass result may be displayed as an executed test result.

### 2.3 Operator / Assessor Scenario Construction

Purpose: allow a user to define realistic external scenario facts and observe the resulting governed traversal.

The operator may construct a bounded external input package describing:

- system category and embodiment;
- intended action;
- operating environment;
- autonomy level and declared ceiling;
- human proximity and public exposure;
- reversibility;
- cascading impact;
- financial or operational impact;
- jurisdiction;
- licensing declarations;
- operator and manufacturer declarations;
- available evidence and corroboration;
- emergency stop and containment characteristics;
- recorded-event import or synthetic-case designation.

The operator must not directly edit:

- canonical internal state;
- state hash;
- request fingerprint;
- tokens or token validity;
- governance result;
- Domain result;
- Aurion result;
- execution result;
- audit hash;
- replay result;
- PVPL result;
- pipeline mode as a desired runtime outcome.

The normal path is:

`Operator / Assessor Inputs -> Adapter / Protocol -> EIE -> SKG/DTN-derived preparation -> Hard Entry Gate -> State Construction -> governed traversal -> Execution Gate -> Audit / Replay / PVPL`

A separately labelled conceptual comparison control may compare eligible synthetic presentations across modes, but it must not be represented as normal runtime mode selection.

---

## 3. Scenario spectrum

The scenario builder should support a broad but controlled system catalogue, including at minimum:

- bounded automated software;
- policy or regulatory compliance automation;
- defence or security automation;
- financial or insurance automation;
- warehouse robotics;
- hospitality or cafe robotics;
- underground mining robotics or autonomous machinery;
- autonomous taxi;
- automated public transport;
- aviation or drone systems;
- medical diagnostic automation;
- surgical robotics;
- industrial control;
- critical infrastructure control.

The system category supplies declared context only. Risk tier and assurance mode must be determined from actual consequence, autonomy, exposure, environment, evidence, and admissibility conditions according to existing implementation rules.

---

## 4. Initial conceptual-recognition catalogue

The initial catalogue should cover at least:

1. low-risk routine approval;
2. medium-risk split-validator approval;
3. Domain pathway reduction;
4. controlled fallback and materially changed candidate;
5. no admissible pathway;
6. highest-risk mirrored approval;
7. deterministic convergence mismatch;
8. Procedural Truth insufficiency;
9. Root-of-Trust or authority failure;
10. classification or licensing denial;
11. Governance denial and GRC response;
12. Governance escalation;
13. token-stack failure;
14. state, fingerprint, signal, or hash-chain integrity failure;
15. execution-gate HALT;
16. controlled material-change re-entry;
17. identical denied resubmission;
18. replay and PVPL verification;
19. audit-integrity reconstruction;
20. measured-startup or runtime-drift refusal.

Each conceptual scenario must declare:

- scenario name;
- purpose;
- synthetic or recorded-event status;
- risk / consequence inputs;
- expected mode-selection basis;
- expected traversal;
- expected constraint or failure point;
- expected outcome;
- expected audit / replay / PVPL evidence.

---

## 5. Pipeline presentation rules

### 5.1 Mode 1 — Full Mirrored

- Both pipelines traverse independently from their outer edges toward centre convergence.
- Both sides display applicable stage bubbles.
- Exact parity and convergence must be shown only when supported by runtime evidence.
- Mismatch must visibly prevent execution.

### 5.2 Mode 2 — Split Validator

- Pipeline A presents primary governance traversal toward the centre handoff.
- Pipeline B presents the validator / admissibility-reduction traversal from centre toward the right.
- The presentation must not imply that Domain creates authority, Aurion overrides Governance, or the Execution Gate is discretionary.
- Exact stage names and event order must come from repository implementation evidence.

### 5.3 Mode 3 — Single Constrained

- Only the applicable left pipeline traverses.
- The right pipeline remains visibly dormant.
- No false mirrored processing, convergence, or secondary validation may be shown.

---

## 6. Stage-bubble presentation

Stage bubbles must:

- use actual repository event or stage terminology;
- alternate above and below the horizontal centre axis;
- move in the correct direction for the active mode;
- remain inside their applicable pipeline visual area;
- use a dark or blank-backed label surface for legibility;
- avoid overlap with primary result, audit, or evidence information;
- omit stages not applicable to the active mode or recorded traversal.

Conceptual-recognition bubbles may contain:

- canonical stage name;
- one short explanation line;
- optional state determination or evidence count where supported.

Technical-verification bubbles should remain compact and use the faster approved cadence.

---

## 7. Central storm / cosmos environment

The storm / cosmos visual remains correctly contained in the central background area behind the pipelines' central direction of travel and convergence region.

The work must preserve that placement. The required improvement is dynamic behaviour, not whole-screen relocation.

The central environment may respond to existing runtime and presentation states by:

- quiet ambient movement when idle;
- controlled brewing or increasing atmospheric activity during traversal;
- increased central concentration as convergence approaches;
- stabilisation after confirmed deterministic convergence;
- existing fire-red HALT treatment for denial or fail-closed outcome;
- existing two-second strobe only for the already established re-loopable condition;
- calm or settled presentation after stable completion.

Do not create new authoritative colour meanings.

### 7.1 Ambient spacecraft

Permitted as restrained, non-semantic background activity:

- rare, slow spacecraft transit across the bounded central cosmos;
- occasional human-recognisable rocket, station, or speculative distant craft silhouette;
- gradual size change to create depth and distance;
- generally one visible craft, very occasionally two;
- movement entering from one edge and leaving through another;
- no combat, lasers, explosions, smoke damage, or narrative battle events;
- no spacecraft event may represent a governance, risk, pass, denial, escalation, or execution status;
- spacecraft must pause or reduce visibility where readability would be affected.

---

## 8. Existing implementation inventory to perform before code changes

Codex must inspect and record before implementation:

- `sbp_lex/desktop/cockpit.py`;
- `sbp_lex/desktop/dashboard.py`;
- `sbp_lex/api/server.py`;
- runtime event-bus event types and payloads;
- canonical runtime status fields;
- adaptive mode selection and freeze logic;
- pipeline convergence representation;
- audit trace and replay-ledger structures;
- PVPL evidence interfaces;
- local trust and runtime provenance outputs;
- university dossier and verification-suite evidence interfaces;
- current cockpit tests and snapshots;
- existing background image and visual assets;
- existing colour, glow, strobe, storm, ECG, and accessibility rules.

Produce an inventory report before modifying implementation files.

---

## 9. IVVF / university-baseline boundary

The current planning branch is based on public repository `main` at `55ff03ec6991aa4a1da3c4e4793896292086fa93`.

A separate local V1.2.13 finalisation rehearsal has since produced substantial assurance results but stopped before complete handover regeneration because `security.integrity_ledger` was missing. Therefore:

- do not merge this planning branch into `main` yet;
- do not claim the planning base is the final IVVF baseline;
- do not modify or regenerate university evidence from this branch;
- rebase or recreate the implementation branch only after the owner confirms the successful final IVVF / university-handover commit;
- treat the final university evidence package, manifests, integrity ledgers, baseline records, trust envelopes, and test evidence as protected inputs.

---

## 10. Implementation phases

### Phase UI-0 — Repository-first inventory

Deliverables:

- existing cockpit component map;
- event and data-source map;
- existing visual doctrine inventory;
- existing test inventory;
- mismatch and gap report;
- no code modification.

### Phase UI-1 — Presentation-state adapter

Create a viewer-only adapter that converts existing runtime events and evidence into presentation states without creating authority or changing runtime outcomes.

### Phase UI-2 — Stage-bubble engine

Implement mode-aware direction, alternating vertical placement, conceptual cadence, and technical cadence.

### Phase UI-3 — Three-area interface separation

Implement separate navigation and state boundaries for:

- Conceptual Recognition Scenarios;
- Technical Verification Suites;
- Operator / Assessor Scenario Construction.

### Phase UI-4 — Scenario-input schema and builder

Implement bounded external scenario input, validation, templates, preview, and submission through existing authorised runtime interfaces.

### Phase UI-5 — Dynamic central cosmos

Restrict effects to the central convergence zone and bind atmospheric activity only to existing presentation states.

### Phase UI-6 — Evidence inspection

Display audit, replay, PVPL, trust, baseline, suite, and export references without mutating them.

### Phase UI-7 — Verification and anti-drift closure

Add tests for:

- viewer-only authority boundary;
- no pipeline-order change;
- no runtime-outcome mutation;
- mode-direction correctness;
- dormant Mode 3 right pipeline;
- no false convergence;
- conceptual/technical evidence separation;
- exact bubble timing tolerances;
- accessibility and readability;
- central cosmos containment;
- ambient spacecraft non-semantic isolation;
- audit/replay/PVPL evidence integrity;
- baseline and university-package protection.

---

## 11. Acceptance criteria

The reconstruction is acceptable only when:

1. an assessor can construct a realistic external scenario without directly editing canonical internal state;
2. the runtime selects and reports the applicable mode under existing rules;
3. the conceptual view explains the traversal slowly and accurately;
4. the technical view displays actual suite evidence separately and at the faster approved cadence;
5. stage bubbles use repository-derived terminology and correct direction;
6. the right pipeline remains dormant in Mode 3;
7. Mode 1 convergence is never shown without exact evidence;
8. Mode 2 does not visually reassign architectural authority;
9. the central cosmos remains bounded to the convergence background;
10. spacecraft remain rare, non-semantic, and non-distracting;
11. existing electric-blue live traversal, fire-red HALT, and established re-loopable strobe meanings are preserved;
12. the cockpit cannot issue, alter, or override governance or execution decisions;
13. the final IVVF and university evidence package remain unchanged;
14. all new tests pass against the final confirmed implementation baseline.

---

## 12. Prohibited changes

Do not:

- redesign SBP-LEX architecture;
- reorder any pipeline;
- rename canonical stages;
- create new governance meanings;
- make the cockpit an execution authority;
- permit direct internal-state editing;
- let visual effects imply unrecorded runtime activity;
- substitute conceptual demonstrations for verification evidence;
- modify locked doctrine or canonical documents;
- alter final IVVF or university evidence;
- merge before the owner confirms the final safe baseline.
