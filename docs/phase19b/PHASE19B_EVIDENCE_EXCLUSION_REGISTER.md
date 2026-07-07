# PHASE19B Evidence Exclusion Register

Draft status: exclusion register for local/private Phase 19B evidence packaging.

Excluded material must not be used as active evidence, active authority, canon,
or deployment proof during Phase 19B.

| Path or category | Reason excluded | Risk if included | Owner review needed |
|---|---|---|---|
| `baselines/` | Archive/source-lineage tree is untracked and not active Phase 19B evidence. | Could mix historical or stale material into current evidence package. | YES |
| Missing originals | Not present in the repository under exact expected source titles. | Could lead to reconstruction from memory or unsupported canon claims. | YES |
| Source-lineage-only V6 documents | Historical lineage only unless separately classified and approved. | Could reintroduce old V6 assumptions or placement drift. | YES |
| `docs/canonical_blueprint_series/` | Canon candidate documents are not owner-promoted final canon. | Could imply canon promotion during Phase 19B. | YES |
| Future-node/distributed material | Phase 19B remains Desktop V1 local/private only. | Could imply nodes, quorum, distributed governance, or cloud runtime. | YES |
| Production/public deployment claims | Phase 19B is not deployment activation or production readiness. | Could overclaim handover status. | NO |
| Public/blockchain/ledger/cloud publication material | PVPL remains local/private and publication-inactive. | Could imply external publication activation. | YES |
| Runtime authority expansion artifacts | Runtime expansion is prohibited by scope lock. | Could imply execution, governance, token, audit, or hash-chain authority changes. | YES |
| `main.py` | Runtime entry point is not part of evidence-package implementation. | Any change could activate runtime behavior or alter traversal. | YES |
| `sbp_lex/pipeline/runner.py` | Runtime traversal runner is prohibited from modification. | Could reorder traversal or change Domain Wrap placement. | YES |
| Domain Wrap runtime files | Domain Wrap position is locked and not part of evidence packaging. | Could move or reinterpret Domain Wrap. | YES |
| Execution Gate runtime files | Execution authority is out of scope. | Could imply execution-gate behavior change. | YES |
| ODA runtime authority claims | ODA remains support-only. | Could turn support assistant into runtime authority. | YES |
| PVPL runtime/publication authority claims | PVPL remains local/private proof support only. | Could imply publication or decision authority. | YES |
| SIM runtime authority claims | SIM remains support/evidence only. | Could imply simulated outcomes are runtime decisions. | YES |
| Generated `runtime_artifacts/` outputs | Generated local outputs are not selected for this docs-only pass. | Could commit transient or environment-specific artifacts. | YES |
| Cache and bytecode files | Temporary/generated files are not evidence. | Could pollute package and repository baseline. | NO |

## Exclusion Principle

If an item would imply runtime expansion, authority expansion, canon promotion,
production deployment, public deployment, live publication, or missing-original
authority, it is excluded from Phase 19B evidence packaging unless a later owner
task explicitly changes the scope.
