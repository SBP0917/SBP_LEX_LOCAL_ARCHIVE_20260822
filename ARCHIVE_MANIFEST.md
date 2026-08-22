# SBP-LEX Local Preservation Archive

**Archive created:** 2026-08-22  
**Repository:** `SBP0917/SBP_LEX_LOCAL_ARCHIVE_20260822` (private)  
**Purpose:** preserve the local SBP-LEX history, checkpoints, worktrees, evidence and working notes that existed at archive time.

## Archive status and truth boundary

This is a **preservation archive**, not a release, production, certification,
handover, acceptance, or final-IVVF claim. It deliberately keeps both active
and historical material so that later work can be traced without rewriting the
record.

The current archived V1 source checkpoint is
`954c91bdf5e9f42d3258215ee568f87e9c5f37dc` on `main`. The original Pass 9
pre-pass checkpoint is retained at
`4ebe54124c652af53f16dfd46ec88cf6c4dc334f`; it is an ancestor of the current
checkpoint, not overwritten history.

Historical reports and older evidence remain evidence **only for the commits
and environments they record**. They do not become current evidence merely by
being present in this archive.

## What was preserved

- The current V1 canonical checkpoint on `main` and an explicitly named
  archive reference.
- Every local branch available in the selected V1 repository at archive time.
- Detached worktree commits that were otherwise vulnerable to loss.
- The local Git stash as a named archive branch.
- Two locally tracked remote workstreams, retained as copies rather than
  treated as current V1 authority.
- The complete reachable Git object history behind those references.

No forced update, reset, deletion, or history rewrite was used to create this
archive.

## Current V1 repair and verification record

The archive preserves the following repair sequence after the Pass 9 pre-pass
checkpoint:

| Commit | Change | Why it exists |
| --- | --- | --- |
| `cf25c6194e635fd4aad4a6e46136587b47b4a86b` | Repaired a runtime assertion-safety defect in the Pass 9 pre-pass. | A real failure was repaired without weakening the governing safety check. |
| `516e2abef2e12b90851d8b52dcbb34df89ba987c` | Fixed Windows generated-evidence lineage traversal. | Corrected Windows-specific provenance traversal behavior. |
| `1024dd04bf54b2b29ae5f9624b988faf6f165fe7` | Made the Pass 9 assurance timeout explicit on Windows. | Replaced an implicit timing assumption with a bounded, visible control. |
| `954c91bdf5e9f42d3258215ee568f87e9c5f37dc` | Bound the Double Triple suite timeout to measured canonical Windows evidence. | The measured full suite exceeded the old two-hour internal limit, so the finite bound was raised to eight hours; no safety control was bypassed. |

Fresh clean-clone evidence for `954c91b` recorded a full canonical suite result
of **2382 passed, 7 skipped** in **4009.60 seconds (1:06:49)**. A prior full
attempt had one non-reproducible H7 timing failure while waiting for an adapter
thread to start; the exact H7 module was then rerun and passed **187 tests**.
The accepted fresh full-suite rerun above passed. This archive is intentionally
careful not to reinterpret the earlier isolated timing failure as a source-code
defect or to weaken its cancellation/acknowledgement control.

At the time this manifest was first written, source-mode Double Triple was
still executing from the clean canonical clone. It must emit its explicit
source-assurance pass marker before it can be recorded here as a pass. No
source-mode pass is claimed by this paragraph.

## Hardening and engineering work preserved

The `main` history and named branch checkpoints retain the following work. The
listed reports and code are the detailed technical record; this manifest is an
index, not a replacement for them.

| Workstream | Hardened capability preserved | Key supporting areas |
| --- | --- | --- |
| Synthetic SKG/DTN work (Pass 2) | Replaced ambiguous or synthetic runtime assumptions with explicit SKG/DTN boundary and readiness work. | `external_substrates/`, `sbp_lex/shared/`, `sbp_lex/pipeline/`, runtime gap register. |
| EIE/control-plane work (Pass 3) | Added deterministic execution-integrity and control-plane evidence handling before downstream traversal. | EIE reports, audit engine, historical-integrity and replay code. |
| Root/PT lineage hardening (Pass 4) | Bound Root/PT lineage, persisted-bundle treatment, replay checks, and lineage gap closure. | `RUNTIME_PASS_4_ROOT_PT_HARDENING_REPORT.md`, Root/PT gap closure register. |
| Classification, licensing, governance and GRC (Pass 5) | Added governed-stage evidence, authority-boundary controls, scope/substitution resistance, stale-authority invalidation and lineage reporting. | `RUNTIME_PASS_5_CLASSIFICATION_LICENSING_GOVERNANCE_GRC_HARDENING_REPORT.md`, `governed_stage_evidence.py`, `authority_boundary.py`. |
| Domain/Aurion work (Pass 6) | Preserved the controlled domain integration/hardening work and its records without elevating it to a release claim. | Pass 6 history and linked runtime/security documentation. |
| Execution convergence (Pass 7) | Preserved regression, execution convergence, cancellation and deterministic runtime hardening. | `RUNTIME_ENGINEERING_PASS_07_EXECUTION_CONVERGENCE_REPORT.md`, H7 deterministic-execution tests. |
| Operational resilience and PQC readiness (Pass 8) | Preserved resilience controls, recovery/restart/backup/restore governance, readiness boundaries and explicit non-certification statements. | `RUNTIME_ENGINEERING_PASS_08_OPERATIONAL_RESILIENCE_REPORT.md`, `PASS_08_OPERATIONAL_RESILIENCE_SPECIFICATION.md`. |
| Controlled PQC migration (Pass 9) | Preserved controlled migration controls, revocation-registry Windows safety, evidence-lineage repair and bounded assurance timing. | `PASS_09_CONTROLLED_PQC_MIGRATION_SPECIFICATION.md`, `PASS_09_CONTROLLED_PQC_MIGRATION_DECISION.md`, Pass 9 branches and repairs. |
| Anti-drift and blueprint governance | Preserved source/supersession maps, relationship maps, mismatch tables, owner review queues and controls that prevent silent canonisation or history rewriting. | `docs/canonical_blueprint_series/`, `docs/blueprint_alignment/`, `docs/document_control/`. |
| Operator/cockpit and video integration material | Retained separately so interface and evidence work is not lost or mistaken for core-runtime authority. | `video-studio-ui-integration`, `local-main-49df56c`, UI cockpit detached checkpoint. |
| University/assurance records | Retained validation dossier, regeneration guide, release-integrity, capstone, adverse/negative harness and R2/R3/R4 evidence material. | `docs/UNIVERSITY_HANDOVER_REGENERATION.md`, `sbp_lex/local_trust/`, assurance reports. |

## Assurance and evidence structure

The preserved V1 tree implements a layered evidence model:

1. **Local Trust and constitutional gates** reject prohibited active authority
   terms and preserve deterministic local evidence boundaries.
2. **Release Integrity and capstone controls** bind source state, generated
   evidence and verification procedure.
3. **Adversarial negative harnesses** exercise fail-closed paths rather than
   only happy-path behavior.
4. **R2 supply-chain evidence** records dependency/SBOM/build/offline
   verification material.
5. **R3 external custody and recovery** preserves custody/recovery records
   while explicitly marking older evidence historical.
6. **R4 Independent Verification and Validation Package (IVVP)** is a detached
   package and must be verified against the exact repository state it covers.
7. **Double Triple** is a fail-closed, pre-handover composition of these gates;
   it is not satisfied by partial, renamed, historical or substituted evidence.

The reports themselves repeatedly distinguish a local deterministic evidence
label from production cryptography, certification, or external assurance. That
boundary remains in force in this archive.

## Windows IV&V / IVVF record

Windows work is preserved in detail but is not overstated:

- `archive/detached/windows-canonical-3ef5992` preserves commit
  `3ef5992cb7cd7f9d45daf2e00a0e1abb0750ebad`, whose recorded subject is
  `validation(ivvp): independent verification package and assessor evidence`.
- `archive/detached/ui-cockpit-1f6d634` preserves the locally detached commit
  `1f6d63422aeab848a8d4f26a6f8a46e3125c780a`, recorded as canonical Windows
  verification evidence.
- `archive/detached/r4-2c5f339` preserves the reconciled R4 baseline commit
  `2c5f339ccf685cd1b856457029fd3b55de478730` and its historical Windows
  pre-flight/verification context.
- `reports/R4_INDEPENDENT_VERIFICATION_PACKAGE_REPORT.md` records historical
  Windows evidence, the final R4/reconciliation lineage, targeted R4 results,
  and the rule that historical evidence does not replace fresh verification of
  the audited worktree.
- Pass 7’s Windows/R4 regression evidence is retained as regression evidence,
  not as a promoted package.
- Pass 8 and Pass 9 documentation explicitly excludes a final native-Windows
  IVVF completion claim. The controlled PQC migration documentation reserves
  final native-Windows IVVF for the later explicit Pass 10/handoff gate.

Therefore, the correct archive statement is: **historical Windows IV&V/IVVP
work and Windows hardening are preserved; a final current Windows IVVF result
is not claimed.** A future final claim requires fresh canonical Windows
evidence for its exact candidate plus the required complete assurance gates.

## Language inventory: Rust, SPARK and Ada

The selected V1 source snapshot was searched for Rust, SPARK and Ada source
trees and project manifests. At archive creation it contained **no Rust,
SPARK or Ada source paths/project files** (including `.rs`, `.adb`, `.ads`,
`Cargo.toml`, `.gpr` or `alire.toml`). They have not been added to the source
or fabricated into the archive. If they are introduced later, they should be
added in a normal, separately reviewed workstream with its own build and
verification evidence.

## Preserved reference map

| Archive reference | Commit | What it preserves |
| --- | --- | --- |
| `main` | `954c91b` | Current archived V1 canonical source checkpoint. |
| `archive/current-v1-canonical-954c91b` | `954c91b` | Explicit immutable-name copy of the current V1 checkpoint. |
| `archive/detached/d1-1024dd0` | `1024dd0` | Detached D1/Pass 9 Windows-timeout checkpoint. |
| `archive/branches/pass9-soak-fix` | `4ebe541` | Original Pass 9 soak/pre-pass checkpoint. |
| `archive/detached/r4-2c5f339` | `2c5f339` | Historical reconciled R4/Windows context. |
| `archive/detached/windows-canonical-3ef5992` | `3ef5992` | Historical IVVP/assessor-evidence checkpoint. |
| `archive/detached/ui-cockpit-1f6d634` | `1f6d634` | Detached canonical-Windows evidence/cockpit checkpoint. |
| `archive/branches/local-main-49df56c` | `49df56c` | Local main/video-studio evidence state. |
| `archive/branches/video-studio-ui-integration` | `49df56c` | Video Studio UI integration work. |
| `archive/branches/desktop-v1-36h-hardening` | `f79c4bf` | Extended local hardening and grant-tracker/owner-answer material. |
| `archive/branches/pass9-final-evidence` | `e8e0c27` | Pass 9 final-evidence/revocation-registry Windows-safe work. |
| `archive/branches/phase19e-cognitive-pipelines-experimental` | `de1c65b` | Experimental Phase 19E material; preserved separately and not a V1 release assertion. |
| `archive/branches/phase-18-8-university-validation-dossier` | `01803c8` | University validation dossier work. |
| `archive/stashes/main-b0f05b9` | `b0f05b9` | The local stash: duplicate video-generator worktree material surfaced during Pass 9 verification. |
| `archive/remote-tracking/external-windows-agent-v1` | `167ab02` | Locally tracked external Windows-agent workstream; preservation copy only. |
| `archive/remote-tracking/ui-cockpit-reconstruction-planning` | `bee0038` | Locally tracked UI-cockpit reconstruction planning workstream; preservation copy only. |

## How to use this archive safely

1. Start from a named reference, not from an unlabelled historical report.
2. Check the exact commit, working-tree cleanliness, Python/runtime lock and
   branch ancestry before accepting test output.
3. Treat all historical counts, package IDs and certificates as scoped to the
   commit/environment documented by their own evidence.
4. Run a fresh canonical Windows verification and complete assurance gates for
   any candidate to be proposed for release or handover.
5. Keep experimental, UI and Phase 19 material separated from the V1 runtime
   assurance claim unless a controlled governance decision says otherwise.

## Primary detailed records in the preserved source

- `docs/DOUBLE_TRIPLE_HANDOVER_ASSURANCE.md`
- `reports/DOUBLE_TRIPLE_PRE_HANDOVER_ASSURANCE_REPORT.md`
- `reports/R4_INDEPENDENT_VERIFICATION_PACKAGE_REPORT.md`
- `reports/R3_EXTERNAL_CUSTODY_OPERATIONAL_RECOVERY_REPORT.md`
- `reports/RUNTIME_PASS_4_ROOT_PT_HARDENING_REPORT.md`
- `reports/RUNTIME_PASS_5_CLASSIFICATION_LICENSING_GOVERNANCE_GRC_HARDENING_REPORT.md`
- `reports/RUNTIME_ENGINEERING_PASS_07_EXECUTION_CONVERGENCE_REPORT.md`
- `reports/RUNTIME_ENGINEERING_PASS_08_OPERATIONAL_RESILIENCE_REPORT.md`
- `docs/security/PASS_09_CONTROLLED_PQC_MIGRATION_SPECIFICATION.md`
- `docs/security/PASS_09_CONTROLLED_PQC_MIGRATION_DECISION.md`
- `docs/operations/RECOVERY_RESTART_BACKUP_RESTORE_INCIDENT_RUNBOOK.md`
- `docs/UNIVERSITY_HANDOVER_REGENERATION.md`

