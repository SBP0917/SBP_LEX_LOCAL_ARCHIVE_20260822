# H6 External Trust Boundary Hardening Report

## Mission identity

- Mission: H6A-H6F external SKG and DTN boundary hardening, adapter translation containment, package integrity, evidence provenance, freshness, replay, and poisoning resistance.
- Starting commit: `73d23877cdba1ed69196c1d3f08ec7d53ac479c4`.
- Ending commit: the single local commit containing this report (`git rev-parse HEAD` after commit is authoritative because a commit cannot embed its own hash).
- Scope: Desktop V1 only. No runtime architecture, node, distributed topology, public deployment, or cognitive capability was added.

## Boundary architecture

The existing separation between `external_substrates` and `sbp_lex` is preserved. External input is accepted only as canonical UTF-8 JSON text, translated into one `ExternalIngressEnvelope`, and marked `canonical_traversal_state: false` plus `EVIDENCE_ONLY_HARD_ENTRY_REQUIRED`. It cannot construct canonical runtime state or issue authority. The established runtime Hard Entry, Root of Trust, Procedural Truth, Classification, Licensing, Governance, GRC, Domain, Aurion, and Execution Gate remain the only path to an executable result.

The boundary sequence is:

`strict adapter -> external ingress envelope -> SKG verification -> DTN verification -> pre-context chain verification -> Hard Entry required`

Every adapter call returns exactly one fully verified non-authoritative envelope or raises one stable `ExternalBoundaryError`; partial output is never returned.

## SKG hardening

SKG packages now bind package type/version, schema version, deterministic package identifier, request fingerprint, issuance time, source digests, transport identity, content digest, and signature. Validation requires qualified source records, measured freshness, unique provenance, independent origins when multiple sources are claimed, a non-empty acyclic authority lineage, the exact SKG signal set, request binding, signal integrity, package integrity, and absence of forbidden runtime authority.

SKG remains an external evidence substrate. Its output is evidence-only and cannot issue Procedural Truth, Classification, Licensing, Governance, GRC, Domain, Aurion, or execution capability.

## DTN hardening

DTN packages receive the same identity, provenance, freshness, transport, schema, digest, and signature bindings. The DTN request and constraint digest must bind to the verified SKG package. Dependency identifiers must be unambiguous, every signal must bind the SKG constraint, and the complete package must pass contextual package verification before translation can complete.

DTN remains an external evidence substrate and never runtime authority.

## Adapter containment

The adapter rejects binary input, invalid Unicode, malformed JSON, duplicate keys, non-finite numbers, non-object packages, non-canonical JSON, protocol confusion, unsupported versions, unexpected top-level fields, excessive bytes, excessive nesting, and excessive aggregate container items. Parsing is deterministic and canonical rendering is byte-for-byte checked after surrounding whitespace removal.

The default limits are 262,144 UTF-8 bytes, depth 24, and 20,000 aggregate container items. A caller can supply a stricter immutable policy. The caller also owns replay state, keeping external replay tracking separate from canonical runtime state.

## Package integrity and provenance

The deterministic package identifier binds package type, package version, request fingerprint, issued time, sorted source-record digests, and transport identity. The package digest and signature then bind that identifier and the complete package body. SKG, DTN, and pre-context packages use aligned strict schemas and regenerated deterministic demo artefacts.

Provenance validation requires each source record to have a valid digest and all qualification flags set, a fresh retrieval timestamp, a unique source identity, and a non-duplicated origin when independence is claimed. The pre-context provenance set must equal the union of the verified SKG and DTN provenance sets. This removes the prior overlap where Boolean freshness/consistency flags and summary counts could be accepted without independently measuring source time and chain membership.

## Freshness, replay, and poisoning resistance

Freshness is measured from `issued_at` and every `retrieved_at` against the supplied verification time; package Boolean flags are not trusted as the measurement. Future or stale values fail closed. The replay registry rejects reused package identifiers or digests and rejects duplicate identifiers within one chain. Changed content is never auto-accepted as an approved package.

The boundary rejects malformed SKG/DTN objects, absent or invalid signatures, schema/version mismatch, wrong provenance, duplicate provenance, shared-origin masquerading, mixed-chain fingerprints, SKG/DTN/pre-context substitution, authority forgery, dependency ambiguity, stale evidence, replay, malformed encodings, and adapter resource attacks before an ingress envelope is produced. No failure path mutates or constructs canonical runtime state.

## Tests

Nineteen targeted H6 tests cover valid deterministic translation; malformed SKG and DTN packages; stale packages; replay; missing and invalid signatures; wrong schema and version; protocol confusion; forged authority; substitution; wrong and duplicate provenance; shared-origin independence failure; dependency ambiguity; duplicate JSON keys; malformed and non-canonical JSON; nesting, item, and byte limits; binary and invalid-Unicode input; mixed chains; poisoning; deterministic replay; and caller-owned replay state.

The focused external-substrate regression set passed 68/68. The complete repository suite passed 1,088/1,088 through both direct pytest and `scripts\run_tests.bat`.

## Verification commands and results

| Command or group | Result |
|---|---|
| `python -m compileall -q .` | PASS |
| `python -m pytest -q --basetemp=runtime_artifacts\pytest_tmp_h6_final` | PASS, 1,088 tests in 349.29 seconds |
| `scripts\run_tests.bat --basetemp=runtime_artifacts\pytest_tmp_h6_batch` | PASS, 1,088 tests in 320.93 seconds |
| H6 plus external-substrate focused suite | PASS, 68/68 |
| Manifest build/validate/show | `LOCAL_TRUST_VALID` |
| Execution envelope build/validate/show | `EXECUTION_ENV_VALID` |
| Evidence chain build/validate/compare/show | `EVIDENCE_CHAIN_VALID`; zero changed evidence items; 15 items; zero missing |
| Regression matrix build/run/validate/show | `REGRESSION_MATRIX_VALID`, 19/19 |
| Constitutional gates evaluate/validate/show | `CONSTITUTIONAL_GATES_PASS`, 24/24 |
| Toolchain guard build/validate/show | `TOOLCHAIN_GUARD_PASS`, 39/39 |
| Adversarial negative harness run/validate/show | `ADVERSARIAL_NEGATIVE_HARNESS_PASS`, 39/39 |
| Capstone build/validate/show | `LOCAL_TRUST_CAPSTONE_PASS` |
| Release integrity build/validate/show | `RELEASE_INTEGRITY_PASS`, 38/38 required artefacts |
| Validation dossier build/validate/show | `VALIDATION_DOSSIER_READY`, 32 claims and 50 evidence artefacts |
| Measured baseline propose/approve/validate/show | `DESKTOP_V1_H6_APPROVED_2026_07_11_03`; `MEASURED_STARTUP_APPROVED` |
| `python main.py` | PASS, `ALLOW` / `EXECUTE`, convergence matched |
| `python main.py replay` | PASS, two runs matched, zero mismatches |
| `git diff --check` | PASS before commit |

The final measured runtime identity is `7f7db2b7c0a67e53af98448c7a4ca9b316d9bd872a1d2ebd4fc8ccfb42c53d1e`. Baseline `DESKTOP_V1_H8_APPROVED_2026_07_11_02` was explicitly retired only after the H6 schemas and refreshed local-trust outputs were measured; no changed state was automatically approved.

## Security properties

- External input is bounded, canonical, strictly typed, integrity-bound, provenance-bound, fresh, and replay checked.
- Package identity prevents silent source, transport, version, schema, time, request, and package substitution.
- SKG and DTN chain binding prevents cross-request and mixed-package contamination.
- External authority values and authority-bearing keys fail closed before Hard Entry.
- Source independence is based on both source identity and origin, preventing duplicate-origin corroboration inflation.
- Deterministic translation and deterministic replay are preserved.
- Canonical state construction and every authority gate remain unchanged.

## Remaining limitations

- External-substrate signing still uses the repository's explicitly labelled deterministic HMAC placeholder. Production exchange requires a managed asymmetric trust store, key rotation, revocation, and hardware- or OS-backed key protection.
- The replay registry is caller-owned in-memory state. Durable cross-process replay protection requires a protected local persistence adapter without changing its fail-closed semantics.
- Freshness depends on the supplied trusted verification time. Host clock assurance is outside this application boundary.
- Origin independence compares declared source identities and URIs; strong organizational independence requires externally verifiable identity credentials and ownership metadata.
- JSON is the only supported wire protocol in this package. Unsupported binary and alternate encodings are rejected rather than translated.

## Desktop V1, no-node, and cognitive confirmation

The canonical Desktop V1 pipeline and runtime modules were not changed. No node, quorum, mesh, distributed convergence, listener, public deployment, or new execution path was introduced. The detached cognitive worktree remains on `phase19e-cognitive-pipelines-experimental` at `de1c65bc18c3cf1e7e05f879f369b44496f4ce5d`; its pre-existing untracked `baselines/`, `experiments/`, cognitive contract, and cognitive report were not read into, copied into, or modified by this mission.

The existing stash was not altered. GitHub was not contacted and no push was performed.
