# Local Trust Constitutional Enforcement Gates

## Purpose

Phase 18.7E.2 adds local-only constitutional enforcement gates for SBP-LEX DUAL V6. The gates convert local trust detection into deterministic checkpoint-readiness results.

Detection alone can be ignored. A manifest, execution envelope, evidence chain, or regression matrix can detect drift, but an operator or future tool could still proceed. These gates create a local pre-flight layer that reports whether the repository should treat the current trust checkpoint as ready.

The gates are not SBP-LEX runtime authority. They do not produce execution permission and do not replace Governance, Procedural Truth, the Execution Gate, the Hard Entry Gate, SKG, or DTN.

## Relationship To Prior Local Trust Phases

Phase 18.7A preserved quarantined integrity-store evidence after RED-20.

Phase 18.7B created the Local Trust Root Manifest and records repository, Python, command, critical-file, report, and output provenance.

Phase 18.7C created the Local Execution Environment Trust Envelope and records verification command provenance.

Phase 18.7D created the Local Evidence Chain and report integrity attestation.

Phase 18.7D.1 closed the evidence chain to zero missing evidence items.

Phase 18.7E.1 created the Local Trust Regression Matrix and proved that drift detection remains testable.

Phase 18.7E.2 binds those artifacts and gates checkpoint readiness.

## Gate Output

The default output path is:

```text
outputs/local_constitutional_gates.json
```

The gate result records:

```text
gate_result_type
gate_result_version
created_at
repository_root
git_commit
git_branch
bound_manifest_digest
bound_execution_envelope_digest
bound_evidence_chain_digest
bound_regression_matrix_digest
gate_policy_version
gate_results
gate_summary
gate_payload_digest
gate_digest
gate_signature
signature_mode
gate_status
validation_failures
```

JSON is canonicalised with stable key ordering before digesting. Status and validation fields are excluded from the payload digest so validation remains deterministic.

## Gate Result Fields

Each gate records:

```text
gate_id
gate_name
gate_category
required
input_artifact
expected_condition
observed_condition
status
reason
```

Gate result statuses:

```text
GATE_PASS
GATE_FAIL
GATE_SKIPPED
GATE_ERROR
```

Overall constitutional gate statuses:

```text
CONSTITUTIONAL_GATES_PASS
CONSTITUTIONAL_GATES_FAIL
CONSTITUTIONAL_GATES_INCOMPLETE
CONSTITUTIONAL_GATES_STALE
CONSTITUTIONAL_GATES_DIRTY
```

These statuses are local checkpoint-readiness statuses only.

## Gate Policy

The policy version is:

```text
LOCAL_TRUST_CONSTITUTIONAL_GATE_POLICY_V1
```

The policy defines required gates for artifact existence, artifact validation, zero-missing evidence, zero-changed evidence, regression case success, digest bindings, repository provenance, forbidden authority leakage, Phase 19 boundary preservation, active implementation absence for future runtime surfaces, generated-output pytest collection policy, and temp/cache evidence exclusions.

Policy changes require explicit future phase work.

## Artifact Binding

The gates bind to:

```text
outputs/local_trust_root_manifest.json
outputs/local_execution_environment_trust_envelope.json
outputs/local_evidence_chain.json
outputs/local_trust_regression_matrix.json
```

The output records the manifest digest, execution envelope digest, evidence chain digest, and regression matrix digest used for gate evaluation.

## Forbidden Authority Leakage

The gates reject or flag active authority fields such as:

```text
execution_permission
governance_result
external_governance_result
runtime_authority
allow_execution
external_allow
external_deny
external_escalate
```

Preserved runtime words may exist inside historical reports or captured evidence text. The gates reject active structured authority keys in local trust outputs.

## Phase 19 Boundary

The gates include a required Phase 19 not-started boundary gate. The phase boundary is derived from the regression matrix case that confirms Phase 19 has not begun.

## CLI

```bat
python -m sbp_lex.local_trust.constitutional_gates evaluate
python -m sbp_lex.local_trust.constitutional_gates validate
python -m sbp_lex.local_trust.constitutional_gates show
```

The CLI evaluates existing local trust artifacts only. It does not run runtime verification, replay, pytest, batch tests, the Hard Entry Gate, Governance, Execution Gate, SKG, or DTN.

## Strict Boundary

Constitutional gates do not introduce runtime activation, Phase 19, external execution permission, external Governance results, nodes, quorum, mesh, distributed runtime, cloud services, APK work, V2, or V3.

No SBP-LEX runtime authority is changed.
