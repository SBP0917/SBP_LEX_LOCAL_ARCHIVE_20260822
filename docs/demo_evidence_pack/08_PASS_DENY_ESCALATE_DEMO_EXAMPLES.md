# Status Language and Demonstration Examples

## Status meanings

- **PASS**: the displayed check or comparison succeeded.
- **ESCALATE**: controlled human or governance review is required.
- **DENY**: the runtime produced a governed rejection.
- **FAIL**: a required check or operation failed.
- **ACTIVE**: traversal activity is currently represented.
- **IDLE**: no active traversal is represented.

The interface follows this presentation rule:

```text
Reason: <text>
[ OUTCOME ]
```

## Illustrative examples

These examples demonstrate wording and layout only. They are not predictions
of a particular runtime result.

```text
Reason: Pipeline A and Pipeline B convergence matched
[ PASS ]
```

```text
Reason: Additional controlled review is required
[ ESCALATE ]
```

```text
Reason: Existing admissibility controls rejected the request
[ DENY ]
```

```text
Reason: A required integrity check did not complete successfully
[ FAIL ]
```

```text
Reason: Approved demonstration traversal is in progress
[ ACTIVE ]
```

```text
Reason: No latest traversal is active
[ IDLE ]
```

Only actual runtime payload values determine the live dashboard outcome.
