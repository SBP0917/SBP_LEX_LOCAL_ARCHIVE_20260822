# H6GHI External Source Identity, Trust and Replay Report

## Mission identity

- Mission: H6G managed asymmetric SKG/DTN source identities, H6H protected external-source trust store, and H6I durable external-package replay persistence.
- Starting commit: `10c80d8aa9d2d486cef757d1e9f858d94ed43fd8`.
- Ending commit: the single local commit containing this report (`git rev-parse HEAD` after commit is authoritative because a commit cannot embed its own hash).
- Scope: local/private Desktop V1, single host, no node, no distributed convergence, no cognitive work, no public deployment, and no architectural redesign.

## Files changed

The package changes the existing SKG/DTN builders and strict package schemas, the external boundary coordinator, H8 measurement policy and approved baseline, H6 regression tests, protected local-trust outputs, release/dossier evidence, and this report. It adds dedicated external-source cryptography, trust-store, replay-store, trust-record schema, replay-record schema, and H6GHI adversarial tests.

## Asymmetric verification design

Accepted SKG and DTN source packages now require an `H6G_EXTERNAL_SOURCE_SIGNATURE_V1` ML-DSA signature. External/source-side construction receives an external private key in memory and produces a signature envelope. Desktop verification receives only the public verification material selected from the protected trust store. Neither trust records nor replay records contain external private keys.

The signature claims explicitly bind:

- source identity and key identity;
- substrate type;
- algorithm and evidence-verification purpose;
- allowed package class and schema version;
- deterministic package identifier; and
- the complete canonical package digest.

Signature success alone is insufficient. The declared source must also occur in the verified package provenance, match the selected trust record, match the substrate, package class, schema version, purpose and algorithm, and be active at the supplied verification time. Legacy placeholder-signed demo packages remain usable only by offline compatibility builders; the secure adapter rejects them with `managed_asymmetric_signature_required`.

## SKG and DTN domain separation

SKG signs `SBP_LEX_DESKTOP_V1_EXTERNAL_SKG_SOURCE_PACKAGE_V1` messages and DTN signs `SBP_LEX_DESKTOP_V1_EXTERNAL_DTN_SOURCE_PACKAGE_V1` messages. The substrate type is also included in the canonical signature claims and trust-record scope. A valid SKG key or signature therefore cannot verify a DTN package, and vice versa. HMAC downgrade, unknown algorithms, wrong purposes, malformed public keys, malformed signatures, wrong keys, and altered packages fail closed.

Signature verification remains evidence authentication only. It creates no Procedural Truth, Classification, Licensing, Governance, GRC, Domain, Aurion, or execution authority.

## Trust-store schema and lifecycle

`ExternalSourceTrustStore` persists an immutable hash-linked sequence of exact-schema records containing all required H6H fields. Store payload, records, checkpoint and anchor use a separate `SBP_LEX_DESKTOP_V1_EXTERNAL_SOURCE_TRUST_ADMIN` integrity domain. Writes use same-directory temporary files, flush, `fsync`, atomic replacement, a process writer lock and a thread lock.

Supported states are `PENDING`, `ACTIVE`, `ROTATING`, `SUSPENDED`, `REVOKED`, `EXPIRED`, and `RETIRED`. Only `ACTIVE` keys verify new packages. Unknown, pending, rotating, suspended, revoked, expired and retired keys are rejected. Revocation records require an effective time and reason. Every mutation requires an integrity-bound explicit local administration authorization matching the action, source and key; source package material cannot self-register, self-approve, self-rotate or self-revoke.

Missing components, invalid schemas, malformed keys, hash/link/signature failures, stale checkpoints, current-anchor mismatches, replacement and generation rollback, and ambiguous persistence state fail closed before package acceptance.

## Key rotation and revocation

Rotation uses two explicitly administered active records during a maximum ten-minute overlap. The outgoing record names its replacement and has a bounded expiry. The replacement must preserve source identity and substrate and may only retain or narrow package/schema scope. An overlap exceeding the bound or any replacement scope broadening is rejected. After the outgoing expiry, only the replacement remains eligible. Immediate suspension or revocation is represented by a higher-version record for the affected key; because current state is reconstructed from the latest record, it cannot verify another new package.

## Durable replay-persistence model

`ExternalReplayStore` records package ID, canonical package digest, source ID, key ID, substrate, issued time, accepted time, freshness window and protection deadline before an ingress envelope is returned. Records are hash-linked and locally integrity-bound in the separate `SBP_LEX_DESKTOP_V1_EXTERNAL_REPLAY_STATE` domain.

The ledger survives object/process reconstruction. A package ID reused with changed content, a digest reused under another ID, cross-source reuse, and ordinary replay are distinct fail-closed conditions. A Windows file lock plus an in-process lock prevents concurrent duplicate acceptance; exactly one contender can persist the package.

Retention is the greater of the active freshness window and the 600-second minimum. Bounded compaction can remove only records whose protection deadline has passed and rebuilds the protected chain and metadata. Active replay protection is never removed early.

## Crash and rollback handling

Replay acceptance first atomically writes a bound intent, then atomically replaces the ledger, checkpoint and anchor, and removes the intent only after completion. An incomplete intent, partial ledger, stale checkpoint or anchor mismatch fails closed. The trust store likewise atomically replaces each protected component; interruption that leaves inconsistent components is detected and rejected rather than silently repaired.

Deletion, truncation, invalid JSON, hash-chain corruption, checkpoint rollback, and restoring an older ledger/store plus checkpoint while leaving the current anchor all fail closed. This is crash-safe acceptance, not a claim of hardware-backed monotonic storage.

## Tests added

Thirty-three H6GHI test cases cover valid SKG/DTN ML-DSA signatures; wrong keys and cross-substrate use; wrong purpose, downgrade and unknown algorithms; package/schema scope; every non-active state; expired validity; bounded rotation and overlap expiry; replacement broadening; malformed keys/signatures; altered packages; source mismatch; missing, corrupt, stale and rolled-back trust state; unauthorized administration; replay after reconstruction; ID/content, alternate-ID/digest and cross-source replay; concurrent duplicate acceptance; ledger truncation, corruption, deletion and rollback; retention; private-key non-persistence; mandatory protected state; and no ingress-envelope construction after failure.

The combined H6 and H6GHI target passed 52/52. The broader external-boundary focus passed 102/102 before the two final explicit rollback/deletion additions; those additions passed in the final targeted and complete runs. The final repository total is 1,121/1,121.

## Commands and results

| Command or group | Result |
|---|---|
| H6 + H6GHI targeted tests | PASS, 52/52 |
| External-boundary focused regression | PASS, 102/102, followed by final rollback/deletion additions |
| `python -m compileall -q .` | PASS |
| `python -m pytest -q --basetemp=runtime_artifacts\pytest_tmp_h6ghi_final` | PASS, 1,121 tests in 348.31 seconds |
| `scripts\run_tests.bat --basetemp=runtime_artifacts\pytest_tmp_h6ghi_batch_final` | PASS, 1,121 tests in 393.77 seconds |
| Manifest build/validate | `LOCAL_TRUST_VALID` |
| Execution envelope build/validate | `EXECUTION_ENV_VALID` |
| Evidence chain build/validate/compare | `EVIDENCE_CHAIN_VALID`, zero changed evidence items |
| Regression matrix build/run/validate | `REGRESSION_MATRIX_VALID`, 19/19 |
| Constitutional gates evaluate/validate | `CONSTITUTIONAL_GATES_PASS`, 24/24 |
| Toolchain guard build/validate | `TOOLCHAIN_GUARD_PASS`, 39/39 |
| Adversarial negative harness run/validate | `ADVERSARIAL_NEGATIVE_HARNESS_PASS`, 39/39 |
| Capstone build/validate | `LOCAL_TRUST_CAPSTONE_PASS` |
| Release integrity build/validate | `RELEASE_INTEGRITY_PASS`, 38/38 required artefacts |
| Validation dossier build/validate | `VALIDATION_DOSSIER_READY` |
| Measured baseline propose/approve/validate/show | `MEASURED_STARTUP_APPROVED` |
| `python main.py` | PASS, `ALLOW` / `EXECUTE`, convergence matched |
| `python main.py replay` | PASS, two runs matched, zero mismatches |
| `git diff --check` | PASS before commit |

The first pre-approval full run intentionally demonstrated H8 fail-closed behavior: changed measured schemas/software caused runtime measurement drift and 28 runtime-dependent failures. No baseline was bypassed. After evidence reconciliation and explicit approval, the complete suite passed.

## Measured-baseline transition

The external shared, SKG and DTN executable modules are now included in the H8 software measurement policy, and the new strict schemas are included in schema measurement. Baseline `DESKTOP_V1_H6_APPROVED_2026_07_11_03` was explicitly retired through the existing pending-to-approved workflow. The approved replacement is `DESKTOP_V1_H6GHI_APPROVED_2026_07_11_04`, with runtime identity:

`ae934a9840037491437b4d9b3c847fa83cba29d1fa6a1b2c901c8030b326edcb`

No changed measurement was automatically accepted.

## Remaining limitations

- ML-DSA is provided by the installed `cryptography` provider. No external HSM, certificate authority, CRL, OCSP service, transparency log, or hardware protection is claimed.
- External private-key custody, generation ceremony and secure signing infrastructure remain the source operator's responsibility. Desktop V1 stores only public verification material.
- Trust and replay anchors are protected local files, not TPM monotonic counters. An attacker able to replace the ledger/store, checkpoint, anchor, code and measured baseline together exceeds this application-level boundary.
- A crash between protected component replacements intentionally leaves a fail-closed state requiring explicit local administrative recovery; automatic acceptance-oriented repair is not attempted.
- Expired replay records may be compacted locally; no external archival transparency service retains removed historical records.
- Local administration authorization uses the repository's existing application-level integrity control, not an external multi-party approval or hardware-backed administrator credential.

## Architecture and no-node confirmation

The canonical runtime and authority pipeline are unchanged. The established Adapter -> external ingress envelope -> SKG verification -> DTN verification -> Hard Entry sequence is preserved, followed by Root of Trust, Procedural Truth, Classification, Licensing, Governance, GRC, Domain, Aurion and Execution Gate. External SKG remains evidence only; DTN remains context only. Durable external replay and trust state are security state, not canonical runtime state.

No node, quorum, mesh, distributed convergence, new listener, public deployment, cognitive path or GitHub workflow was added.

## Stash, cognitive branch and push status

The existing stash was preserved. The detached cognitive worktree and its pre-existing untracked `baselines/`, `experiments/`, cognitive contract and cognitive report were not incorporated or modified. No push was performed and GitHub was not contacted.
