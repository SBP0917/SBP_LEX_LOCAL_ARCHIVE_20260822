# SBP Operator Assistant V1

## Purpose

SBP Operator Assistant V1 is a separate local productivity assistant for organising SBP-LEX project materials. It helps the operator register workspaces, index documents, track project phase memory, locate canonical documents, and prepare structured Codex build packages.

It is not SBP-LEX runtime authority.

## Scope

V1 implements the first bounded practical layer:

- workspace manager
- file and document organiser
- calendar and task placeholder through pending task records
- SBP-LEX project memory
- canonical archive manager
- Codex build assistant for structured text packages
- video and diagram generation hooks as placeholders only
- separate operator dashboard renderer

## What It Does

- Records named workspaces and returns paths or commands for operator review.
- Registers documents with project, tag, phase, archive, and version metadata.
- Searches registered document metadata.
- Detects duplicate document entries in assistant storage.
- Tracks current phase, completed phases, pending tasks, and project status.
- Registers canonical documents by doctrine area.
- Links canonical documents to phases.
- Creates local text-only Codex build packages.
- Renders a separate local dashboard HTML view.
- Stores state as deterministic, human-readable JSON under `sbp_operator_assistant/data/`.

## What It Does Not Do

- It does not change SBP-LEX runtime governance.
- It does not modify Procedural Truth enforcement.
- It does not modify SKG or DTN substrates.
- It does not modify Execution Gate behavior.
- It does not introduce execution authority.
- It does not launch commands automatically.
- It does not delete files.
- It does not move files automatically.
- It does not commit or push to GitHub.
- It does not call external APIs or cloud services.
- It does not implement autonomous agent behavior.

## V1 Implementation Boundary

The assistant lives in the separate `sbp_operator_assistant` package. It does not merge into the Desktop V1 runtime cockpit and does not import or mutate the canonical SBP-LEX runtime control path.

The `prepare_workspace` API returns a review package only:

- `paths_to_open`
- `commands_to_review`
- `destructive_actions`
- `launched`

The assistant never executes those commands.

## Safe Local-Only Posture

All persistent state is local JSON:

- `sbp_operator_assistant/data/workspaces.json`
- `sbp_operator_assistant/data/documents.json`
- `sbp_operator_assistant/data/project_memory.json`
- `sbp_operator_assistant/data/canonical_archive.json`
- `sbp_operator_assistant/data/codex_packages.json`

The CLI is intentionally narrow and safe:

```powershell
python -m sbp_operator_assistant.app status
python -m sbp_operator_assistant.app add-doc <path>
python -m sbp_operator_assistant.app list-docs
python -m sbp_operator_assistant.app set-phase <phase>
python -m sbp_operator_assistant.app pending
python -m sbp_operator_assistant.app prepare-workspace <name>
```

## Tier Roadmap

These tiers are documented as the roadmap only. V1 does not attempt to implement every tier.

- Tier 1: Personal Digital Operator
- Tier 2: SBP-LEX Project Manager
- Tier 3: Canonical Knowledge Graph
- Tier 4: Build Assistant
- Tier 5: Creative Studio
- Tier 6: Research Assistant
- Tier 7: Desktop Workspace Manager
- Tier 8: Project Memory
- Tier 9: Operator Dashboard
- Tier 10: Future AI Agent Layer

## Future Placeholders

- Calendar integration remains a placeholder represented by pending task metadata.
- Video and diagram generation hooks remain placeholders and do not call generation services.
- Repository status is an operator-recorded field, not an automatic Git authority.
- Quick launch is displayed as a placeholder and does not execute commands.

## Runtime Preservation Confirmation

This assistant is a local productivity package only. It does not change SBP-LEX runtime authority, Governance, Procedural Truth, SKG, DTN, Domain, Aurion, Execution Gate, audit, replay, token, hash, or chronology behavior.

