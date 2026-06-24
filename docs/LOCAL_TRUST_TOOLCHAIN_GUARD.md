# Local Trust Toolchain Guard

## Purpose

Phase 18.7E.3 adds a local Dependency / Toolchain Guard for SBP-LEX DUAL V6. It records the Python runtime, pytest and pip visibility, dependency file digests, installed package snapshot, verification command policy, pytest collection policy, temp/cache exclusion policy, and local trust artifact bindings.

The guard exists because a local trust system can decay over time if its toolchain changes silently. A different Python executable, changed pytest version, missing dependency file, changed verification command sequence, wrong working directory, generated-output collection problem, or temp-folder leak can undermine reproducibility without touching runtime authority.

## Relationship To Prior Phases

18.7A preserved quarantined persistence evidence after RED-20.

18.7B created the Local Trust Root Manifest.

18.7C created the Local Execution Environment Trust Envelope.

18.7D created the Local Evidence Chain and report integrity attestation.

18.7D.1 established zero missing evidence.

18.7E.1 created the Local Trust Regression Matrix.

18.7E.2 created Constitutional Enforcement Gates.

18.7E.3 binds those artifacts and records the toolchain assumptions used to verify them.

## Guard Structure

The default output is:

```text
outputs/local_toolchain_guard.json
```

The guard records:

```text
toolchain_guard_type
toolchain_guard_version
created_at
repository_root
git_commit
git_branch
python_executable
python_version
python_prefix
python_base_prefix
platform
pytest_version
pip_version_if_available
dependency_files
dependency_file_digests
installed_package_snapshot
verification_command_policy
pytest_collection_policy
ignored_output_paths
ignored_temp_paths
bound_manifest_digest
bound_execution_envelope_digest
bound_evidence_chain_digest
bound_regression_matrix_digest
bound_constitutional_gates_digest
toolchain_checks
toolchain_summary
toolchain_payload_digest
toolchain_digest
toolchain_signature
signature_mode
toolchain_status
validation_failures
```

The JSON payload is canonicalised with stable key ordering before digesting. Status and validation fields are excluded from the payload digest.

## Toolchain Policy

Policy version:

```text
LOCAL_TRUST_TOOLCHAIN_POLICY_V1
```

The policy requires Python evidence, pytest evidence, dependency file digest evidence, verification command policy, pytest ignore policy, temp/cache exclusion policy, artifact binding policy, forbidden-authority boundary policy, and Phase 19 boundary policy.

Policy changes require explicit future phase work.

## Verification Command Policy

The guard records the required verification commands, including compileall, pytest, batch tests, local trust artifact validation, constitutional gates, toolchain guard commands, runtime, replay, and git hygiene commands.

The toolchain guard does not execute those commands. It records the expected sequence for local verification provenance.

## Dependency Inventory

The guard checks these dependency files when present:

```text
requirements.txt
requirements-dev.txt
pyproject.toml
setup.py
setup.cfg
Pipfile
poetry.lock
```

Existing files are hashed. Missing candidates are recorded deterministically. If no dependency files are present, the guard records `NO_DEPENDENCY_FILE_PRESENT`.

This phase does not install packages and does not change package pins.

## Pytest And Temp Policies

The guard records pytest collection exclusions for generated outputs and stale local temp folders. It also records temp/cache exclusions such as `.pytest_cache`, `.pytest_tmp_*`, `outputs/local_trust_temp`, `__pycache__`, and `*.pyc`.

## Status Meanings

```text
TOOLCHAIN_GUARD_PASS
TOOLCHAIN_GUARD_FAIL
TOOLCHAIN_GUARD_INCOMPLETE
TOOLCHAIN_GUARD_STALE
TOOLCHAIN_GUARD_DIRTY
TOOLCHAIN_GUARD_UNSUPPORTED
```

Check statuses:

```text
TOOLCHAIN_CHECK_PASS
TOOLCHAIN_CHECK_FAIL
TOOLCHAIN_CHECK_SKIPPED
TOOLCHAIN_CHECK_ERROR
```

These statuses are local verification-environment statuses only.

## Artifact Binding

The toolchain guard binds to:

```text
outputs/local_trust_root_manifest.json
outputs/local_execution_environment_trust_envelope.json
outputs/local_evidence_chain.json
outputs/local_trust_regression_matrix.json
outputs/local_constitutional_gates.json
```

## Forbidden Authority Leakage

The guard rejects active structured authority keys in its own output, including:

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

Observed runtime words may exist only as preserved evidence or documentation. The guard is not an execution authority.

## Phase 19 Boundary

The guard includes a required Phase 19 not-started boundary check and future-surface absence checks. It does not start Phase 19.

## CLI

```bat
python -m sbp_lex.local_trust.toolchain_guard build
python -m sbp_lex.local_trust.toolchain_guard validate
python -m sbp_lex.local_trust.toolchain_guard show
```

The CLI records and validates toolchain evidence only. It does not run runtime, replay, pytest, batch tests, Governance, Execution Gate, Hard Entry Gate, SKG, or DTN.

## Strict Boundary

The toolchain guard does not introduce runtime activation, execution permission, distributed trust, nodes, quorum, mesh, cloud, APK, V2, V3, or Phase 19 work. It does not modify SBP-LEX runtime authority.
