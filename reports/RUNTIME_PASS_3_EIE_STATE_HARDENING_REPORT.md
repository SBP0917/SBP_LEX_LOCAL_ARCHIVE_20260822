# Runtime Pass 3 — EIE, Hard Entry, State and Attachment Hardening

Date: 2026-08-07

Tested implementation commit: `d127c5c868767654119ca4f5a31ba4e9036abf4a`

## Outcome

Runtime Pass 3 is implemented and verified for the locked Desktop V1 boundary:

`External Request -> Adapter -> EIE -> Synthetic SKG Validation -> Synthetic DTN Validation -> Bridge Validation -> Hard Entry Gate -> Canonical State Construction -> Collective Signal Attachment -> Root of Trust`

The boundary now rejects malformed, oversized, undeclared, stale, replayed, mismatched, replaced, unvalidated, and state-injecting inputs before governed state formation. Accepted ingress is represented by a sealed `HardEntryAdmission`; it is the only input accepted by the sole canonical state builder. Collective signals attach once, after state construction, through a minimal request-, EIE-, digest-, freshness-, and hash-chain-bound projection.

No critical or high-severity gap remains in the requested Pass 3 scope.

## Files changed

Boundary contracts and validation:

- `sbp_lex/api/schema_validation.py`
- `sbp_lex/pipeline/hard_ingress.py`
- `sbp_lex/runtime/boundary_types.py`
- `sbp_lex/runtime/synthetic_substrates.py`
- `sbp_lex/shared/control_chain_validation.py`

Canonical construction, attachment, parity, and replay:

- `sbp_lex/shared/state_builder.py`
- `sbp_lex/collective/context_interface.py`
- `sbp_lex/pipeline/runner.py`
- `sbp_lex/pipeline/dual_runner.py`
- `sbp_lex/pipeline/replay_runner.py`

Compatibility and downstream mutation removal:

- `sbp_lex/authority_first/root_of_trust_runner.py`
- `sbp_lex/authority_first/truth_expiry_engine.py`
- `sbp_lex/governance/procedural_truth_engine.py`
- `sbp_lex/phase19a/fixtures.py`
- `sbp_lex/phase19a/pre_context_translator.py`

Specification and evidence:

- `docs/runtime/EIE_HARD_ENTRY_STATE_RUNTIME_SPECIFICATION.md`
- `sbp_lex/runtime/eie_state_boundary_evidence.py`
- `outputs/runtime/eie_state_boundary_evidence.json`
- `reports/RUNTIME_PASS_3_EIE_STATE_HARDENING_REPORT.md`

Tests:

- Added `tests/test_runtime_pass3_eie_state_boundary.py` with 19 focused tests.
- Updated nine existing Phase 15, Phase 18, Phase 19, formal-architecture, procedural-truth, EIE/PT, and Runtime Pass 2 test modules for the hardened contract.

## Runtime findings

### Adapter and EIE

- The adapter applies Unicode NFC normalization, deterministic key ordering, a closed request schema, byte limits, recursive internal-state-key rejection, and lossless canonical serialization.
- `AdapterResult` is frozen and sealed. A caller mutation after adaptation cannot alter its normalized request or fingerprint.
- `build_execution_intent_envelope` is the one canonical EIE constructor. Schema `desktop-v1.eie.v1` binds the normalized request, objective/action, actor/principal inputs, unvalidated authority claims, jurisdiction, AP-ACF/deployment declarations, consequence profile, environment modifiers, deterministic synthetic package references, freshness, and replay values.
- The EIE contains no runtime authority result. Its canonical serialization and `eie_hash` are deterministic.

### Hard Entry

- `run_hard_ingress` verifies the adapter seal, EIE schema/digest/request binding, mandatory and forbidden fields, logical freshness, signal signature and binding, SKG/DTN validation statuses and package digests, bridge status/digest, and replay state.
- Replay state is recorded only after all other substrate validation succeeds, so an invalid substrate attempt cannot consume a valid EIE nonce.
- Invalid ingress returns deterministic `HardEntryDenialEvidence` with `governed_state_formed=false`, `authority_token_issued=false`, `governance_result_issued=false`, and `downstream_stage_reached=false`. It has no state, state hash, version, decision, governance result, or execution result.
- Direct state construction and direct downstream execution with raw mappings raise typed boundary errors.

### State construction and mutation protection

- `build_state` is the sole state builder and accepts only `HardEntryAdmission`.
- Schema `desktop-v1.canonical-state.v1` starts with controlled empty collective/PT defaults.
- Raw SKG, DTN, bridge, or signal packages do not enter canonical state. Only verified reference digests, validation statuses, bridge digest, and the later minimal signal projection enter.
- Request fingerprint, normalized-request digest, EIE digest, EIE, verified substrate references, state schema, and construction hash are protected by `boundary_protected_fields_digest` and revalidated before Root of Trust.
- Static AST enforcement found one `build_state` definition and one direct production call site: `sbp_lex/pipeline/runner.py`.

### Collective attachment and parity

- `attach_collective_signals` operates only on an `UNATTACHED` canonical state and rejects double, stale, cross-request, cross-EIE, unverified, unbound, or field-overwriting attachment attempts.
- Attachment excludes raw `skg_context`, `dtn_context`, and `synthetic_substrate_evidence`. It records a minimal validated projection, PT evidence envelope, prior-state binding, and `collective_attach` hash-chain record.
- Pipeline A and Pipeline B are materialized from the same sealed `PreparedPipelineBoundary` after a single Hard Entry, state construction, and attachment.
- Exact initial parity is required for EIE, substrate references, construction hash, signal digest, attachment hash, state-hash basis, and A/B initial hashes. Near-match reconciliation is disabled.

## Deterministic evidence

The committed artifact `outputs/runtime/eie_state_boundary_evidence.json` records:

| Evidence field | Value |
|---|---|
| Normalized request digest / fingerprint | `cd84a2f696258fe3f24aa6014be5d6b4a7f1805fe593733ecac7b53e428598a8` |
| EIE digest | `6d4c48f5a9c296fb06e81681a148f0f2af57d17a082ae0951e23e2c997aae1f5` |
| SKG package digest | `71ebf24dce45aad893671ff994e23f72dd80e9d5a5fdf0309d80088f06726b58` |
| DTN package digest | `86b7da60a4632c5b5f025c8e9bf33b37b89c214bf36084e003968bbe94e3d0f4` |
| Bridge result digest | `c08f7db83ab08d22f69ff89a82c4bdc274a96347ab3c596759655634d0eb8fe5` |
| Initial state / construction hash | `c84b23408080dc6b3bd9fff3d3be5b740c16622b16b914ddf8e6a365a089ecd9` |
| State hash basis | `1aa360b97d01e7975e14045e435a7e690398cf48c3b0ba464bd4fbb88ea43f35` |
| Collective signal package digest | `f3d4917dd0050a58b7d52d09a749ed7c0ad8dc926b2a44cf1bf491b9b1d421e1` |
| Collective attachment hash | `463b9403f8ee8fb4118f62ca03d866f96d07398d1f678497234afd7606a8e10f` |
| Pipeline A initial hash | `c668a053b00c6bcb9b8662469f2c96f1e94548874069f831ea30526ab274e2b3` |
| Pipeline B initial hash | `c668a053b00c6bcb9b8662469f2c96f1e94548874069f831ea30526ab274e2b3` |
| Exact parity / near-match used | `true` / `false` |

The artifact also records `ATTACHED`, `ALLOW`, `EXECUTE`, replay matched with no mismatches, no state/token on invalid ingress, and rejection of builder/downstream bypasses.

## Verification results

| Verification | Result |
|---|---|
| `python -m compileall -q .` | PASS, exit 0. Python sources compiled; the command reported pre-existing inaccessible pytest cache/temp directories as non-fatal `Can't list` notices. |
| Focused Pass 3 boundary tests | PASS — 19 passed in 9.42s. |
| Directly affected regression set | PASS — 388 passed in 31.64s. |
| Full approved test suite | PASS — 1,874 passed, 7 skipped in 789.11s. |
| Approved Windows runner | PASS — `scripts\run_tests.bat -p no:cacheprovider -q` using Python 3.14 core; wrapper reported `[PASS] Requested test run passed.` |
| Normal runtime entry point | PASS — `ALLOW`, `EXECUTE`, `MODE_2_SPLIT_VALIDATOR`, convergence matched, no token failures, measured startup approved. |
| Replay entry point | PASS — two runs matched, no mismatches, exact initial A/B parity. The evidence generator also verifies three-run replay parity. |
| Parity verification | PASS — identical EIE, references, signal package, state-hash basis, and pipeline A/B initial hash; no near-match reconciliation. |
| `git diff --check` | PASS. |
| Final `git status --short` | Clean after the report-only evidence commit. |

The runtime and replay entry points used the repository's controlled local test signing identity and an ephemeral approved measured-startup baseline. They did not contact or activate an external provider.

An earlier non-acceptance full-suite attempt used the `Python\bin\python.exe` launcher shim, which invalidated inherited Windows standard-input handles and caused subprocess tests to fail with `WinError 6`. A subprocess-heavy probe passed with the core interpreter before the authoritative clean full-suite run above. No result from the invalid launcher attempt is counted as verification evidence.

## Minimal lineage

| Requirement | Runtime finding | File | Function or schema | Test | Evidence | Commit |
|---|---|---|---|---|---|---|
| Deterministic adapter boundary | Closed, bounded, normalized, sealed request; injection rejected | `sbp_lex/pipeline/hard_ingress.py`, `sbp_lex/runtime/boundary_types.py` | `adapt_external_request`, `AdapterResult` | `test_adapter_rejects_malformed_oversized_unknown_and_state_injection`, `test_request_mutation_after_adapter_does_not_change_boundary` | normalized request digest; invalid-ingress flags | `d127c5c` |
| One immutable EIE | One canonical schema and digest; request/intent/context bound; no authority outcome | `sbp_lex/shared/state_builder.py`, `sbp_lex/shared/control_chain_validation.py` | `build_execution_intent_envelope`, `desktop-v1.eie.v1` | `test_eie_is_constructed_once_and_contains_no_runtime_authority_outcome`, `test_eie_tamper_is_rejected` | `eie_digest` | `d127c5c` |
| Hard Entry fail-closed validation | Adapter, EIE, substrate, bridge, freshness, replay, and injection checks precede state | `sbp_lex/pipeline/hard_ingress.py` | `run_hard_ingress`, `HardEntryDenialEvidence` | stale/replay, mismatch/status, bridge/replacement, invalid-ingress tests | denial flags; SKG/DTN/bridge digests | `d127c5c` |
| Sole canonical state construction | One builder accepts only sealed admission; deterministic protected state | `sbp_lex/shared/state_builder.py`, `sbp_lex/pipeline/runner.py` | `build_state`, `desktop-v1.canonical-state.v1`, `PreparedPipelineBoundary` | `test_state_construction_is_deterministic_and_raw_packages_are_isolated`, `test_sole_state_builder_enforcement` | construction hash; state-hash basis | `d127c5c` |
| Protected-state mutation resistance | Boundary fields are sealed and revalidated before downstream authority | `sbp_lex/shared/state_builder.py`, `sbp_lex/authority_first/root_of_trust_runner.py` | `validate_boundary_protection` | `test_protected_field_overwrite_and_double_attachment_are_rejected` | bypass flags; focused test result | `d127c5c` |
| One minimal collective attachment | Post-state, one-time, validated, bound, hash-chain-recorded projection | `sbp_lex/collective/context_interface.py` | `attach_collective_signals` | minimal attachment, stale/cross-request, overwrite/double-attach tests | attachment hash; `ATTACHED` | `d127c5c` |
| Exact dual-pipeline initial parity | Both pipelines use the same sealed prepared boundary; near-match disabled | `sbp_lex/pipeline/dual_runner.py`, `sbp_lex/pipeline/replay_runner.py` | `run_dual_pipeline`, replay comparison schema | `test_repeated_run_and_replay_parity_are_exact` | A/B initial hashes; exact parity `true` | `d127c5c` |
| Durable Pass 3 evidence | Deterministic boundary and negative-control evidence generated locally | `sbp_lex/runtime/eie_state_boundary_evidence.py`, `outputs/runtime/eie_state_boundary_evidence.json` | `desktop-v1.runtime-pass3-evidence.v1` | focused and full suite | evidence digest `db401d1d04fbad8bf11d5ba955aeeb5650124ca7e1121b8a1800b29be8562f78` | `d127c5c` |

## Scope confirmations

- Architecture: unchanged. The locked pipeline order remains intact; no second state path, hidden parallel state, cloud, node, mesh, or quorum architecture was introduced.
- Runtime authority: unchanged. Governance, Classification, Licensing, Domain, Aurion, and Execution Gate decision authority and sequencing were not altered. Limited downstream edits remove post-digest EIE mutation and enforce the new protected-boundary invariant.
- External linkage: none. Only deterministic local synthetic SKG/DTN fixtures are used; no live provider or external runtime linkage was activated.
- Stop boundary: work stops at Collective Signal Attachment and its Root of Trust handoff. No further Root of Trust, Procedural Truth, or broader pipeline hardening was undertaken.

## Unresolved gaps

None in the requested Runtime Pass 3 boundary. Live-provider integration remains intentionally out of scope and disabled.
