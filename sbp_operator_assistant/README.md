# SBP Operator Assistant V1

SBP Operator Assistant V1 is a local productivity layer for SBP-LEX project materials.

It helps an operator register workspaces, index documents, track phase memory, record canonical archive pointers, prepare structured Codex build packages, and view a separate assistant dashboard.

It does not govern runtime execution, change SBP-LEX authority, alter Procedural Truth, modify SKG/DTN, launch commands, delete files, commit, push, call external APIs, or act as an autonomous agent.

## CLI

```powershell
python -m sbp_operator_assistant.app status
python -m sbp_operator_assistant.app add-doc docs/SBP_OPERATOR_ASSISTANT_V1.md
python -m sbp_operator_assistant.app list-docs
python -m sbp_operator_assistant.app set-phase "Operator Assistant V1"
python -m sbp_operator_assistant.app pending
python -m sbp_operator_assistant.app prepare-workspace "Phase 15.6B"
```

All storage is local, deterministic, human-readable JSON under `sbp_operator_assistant/data/`.

