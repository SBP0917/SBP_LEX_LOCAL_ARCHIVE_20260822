# Local Trust 25-Year Capstone

## Purpose

Phase 18.7E.4 closes the 25-year local-trust hardening set with a deterministic capstone artifact:

```text
outputs/local_trust_25_year_capstone.json
```

The capstone is a completion lock. It binds the validated local-trust artifacts, records the completed phase index, preserves the verification command index, confirms safety boundaries, and marks 18.7F as the next phase only.

It is not runtime authority.

## Why The Capstone Exists

The local-trust system now has separate artifacts for provenance, execution environment capture, evidence integrity, regression drift detection, constitutional gates, and toolchain drift protection. Those artifacts are useful individually, but long-horizon maintenance also needs a single final index that proves which artifacts close the local-trust phase together.

The capstone provides that closure layer without changing SBP-LEX runtime behavior.

## Relationship To Prior Phases

18.7D.1 cleaned the evidence chain to a zero-missing local evidence baseline.

18.7E.1 added the local trust regression matrix and mutation detection baseline.

18.7E.2 added constitutional enforcement gates for local trust pre-flight guardrails.

18.7E.3 added dependency and toolchain guard evidence.

18.7E.4 binds those layers together as a final completion index.

## Artifact Binding Model

The capstone binds these artifacts:

```text
outputs/local_trust_root_manifest.json
outputs/local_execution_environment_trust_envelope.json
outputs/local_evidence_chain.json
outputs/local_trust_regression_matrix.json
outputs/local_constitutional_gates.json
outputs/local_toolchain_guard.json
```

Each artifact entry records:

```text
artifact_id
path
presence_status
digest
digest_field
validation_status
expected_status
validation_failures
size_bytes
```

## Digest Binding Model

The capstone records top-level bound digests for:

```text
manifest
execution envelope
evidence chain
regression matrix
constitutional gates
toolchain guard
```

The capstone itself has:

```text
capstone_payload_digest
capstone_signature
capstone_digest
signature_mode
```

The digest is deterministic JSON using stable key ordering and the existing local-trust canonicalisation helper.

## Verification Command Index

The capstone records the required verification command set, including:

```text
python -m compileall -q .
python -m pytest -q
scripts\run_tests.bat
python -m sbp_lex.local_trust.manifest validate
python -m sbp_lex.local_trust.execution_envelope validate
python -m sbp_lex.local_trust.evidence_chain validate
python -m sbp_lex.local_trust.evidence_chain compare
python -m sbp_lex.local_trust.regression_matrix validate
python -m sbp_lex.local_trust.regression_matrix show
python -m sbp_lex.local_trust.constitutional_gates evaluate
python -m sbp_lex.local_trust.constitutional_gates validate
python -m sbp_lex.local_trust.constitutional_gates show
python -m sbp_lex.local_trust.toolchain_guard build
python -m sbp_lex.local_trust.toolchain_guard validate
python -m sbp_lex.local_trust.toolchain_guard show
python -m sbp_lex.local_trust.local_trust_capstone build
python -m sbp_lex.local_trust.local_trust_capstone validate
python -m sbp_lex.local_trust.local_trust_capstone show
python main.py
python main.py replay
git diff --check
git status --short
```

The capstone CLI records this command policy only. It does not execute runtime, replay, pytest, batch tests, Governance, Execution Gate, Hard Entry Gate, SKG, or DTN.

## Completion Conditions

The capstone passes only when:

```text
manifest validates
execution envelope validates
evidence chain validates
evidence chain compare has zero changed items
regression matrix validates
constitutional gates pass
toolchain guard passes
capstone digest validates
required completed phases are indexed
required verification commands are indexed
Phase 19 remains not started
18.7F is marked as next phase only
```

## Boundary Confirmations

The capstone confirms:

```text
no runtime activation introduced
no SBP-LEX runtime authority changed
Governance unchanged
Procedural Truth unchanged
Execution Gate unchanged
Hard Entry Gate unchanged
SKG/DTN remain external and non-authoritative
no nodes/quorum/mesh/distributed/cloud/APK/V2/V3 work introduced
Phase 19 remains not started
```

## CLI

```bat
python -m sbp_lex.local_trust.local_trust_capstone build
python -m sbp_lex.local_trust.local_trust_capstone validate
python -m sbp_lex.local_trust.local_trust_capstone show
```

`build` writes the capstone output. `validate` checks schema, required bindings, digest integrity, required phase coverage, command coverage, completion conditions, and boundary summaries. `show` prints a concise local trust completion summary.

## Transition To 18.7F

The next phase is:

```text
18.7F - Release Integrity Package / Reproducible Validation Bundle
```

18.7F is only marked as next-phase readiness here. This phase does not implement 18.7F, create release bundles, package artifacts, or start Phase 19.
