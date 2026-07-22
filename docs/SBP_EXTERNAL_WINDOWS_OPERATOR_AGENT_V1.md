# SBP External Windows Operator Agent V1

## Position

The external agent is a separate owner-controlled Windows productivity and execution layer. It is distinct from:

1. `sbp_operator_assistant`, which manages internal SBP-LEX project materials; and
2. the SBP-LEX runtime, which remains the sole authority for its governed execution pathway.

## Controlled structure

```text
Owner instruction
    -> External Windows Agent action plan
    -> Fail-closed policy validation
    -> Owner approval record
    -> Windows action executor
    -> Hash-chained local audit record

External Windows Agent
    -> restricted read-only local bridge
    -> SBP Operator Assistant V1

No route grants SBP-LEX runtime authority.
```

## V1 executable capabilities

- Open a local file or directory after approval.
- Open an HTTP or HTTPS URL after approval.
- Run a bounded process using an executable and argument array after approval.
- Query the internal project assistant through a fixed read-only command allowlist.
- Persist pending requests and audit records locally outside the repository.

## Mandatory boundaries

- No autonomous approval.
- No arbitrary shell string execution.
- No destructive file command, privilege-changing command, Git publication command, or forced repository rewrite.
- No modification of SBP-LEX Governance, Procedural Truth, SKG, DTN, Domain, Aurion, Execution Gate, tokens, audit, replay, pipeline chronology, or runtime authority.
- The external agent may assist project work; it does not become part of the governed runtime.

## Next controlled increments

1. Windows application registry and workspace restoration profiles.
2. Screen capture and local computer-vision observation.
3. Mouse and keyboard driver with per-action approval and emergency stop.
4. AI planner/provider adapter that can propose but not self-approve actions.
5. Browser research connector and document-production adapters.
6. Email and calendar adapters with explicit owner approval for every write action.
