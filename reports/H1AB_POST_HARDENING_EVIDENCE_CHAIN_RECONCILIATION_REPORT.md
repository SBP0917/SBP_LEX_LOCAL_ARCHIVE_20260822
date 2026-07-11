# H1A/H1B Post-Hardening Evidence-Chain Reconciliation

## Scope and decision

Starting commit: `826b973351761b2d3e8e336f44eaae4c49ddda04`.

This work reconciles local-trust evidence only. It makes no runtime, API,
identity, request-binding, architecture, cognitive, future-version, or
hardening change.

The initial evidence comparison reported six changed protected artefacts.
Each path was clean in Git. For every path, the recorded digest exactly matched
the SHA-256 digest of the canonical `HEAD` blob. The apparent new digest was
the byte-sensitive SHA-256 of Git's Windows CRLF checkout representation.
Accordingly:

- no substantive protected content change was found;
- no unrelated change was accepted;
- the CRLF-only representation difference was explained and deliberately
  incorporated into the refreshed local evidence record;
- the canonical old digests remain traceable below.

## Protected artefact reconciliation

| Protected artefact | Old canonical SHA-256 | Refreshed checked-out SHA-256 | Justified source |
|---|---|---|---|
| `reports/SBP_OPERATOR_ASSISTANT_V1_IMPLEMENTATION_REPORT.md` | `62abc4862d81b17f97e87a1db4fbe6ab3659967373f866417dfe310c30f25bd5` | `db821f8e95d7e0d1d0882782baf4a6c145f2f915d98b62d52df68e895be37c87` | LF canonical blob represented as CRLF by Windows checkout; Git content unchanged |
| `reports/PHASE_18_7B_LOCAL_TRUST_ROOT_MANIFEST_REPORT.md` | `a9d25192e6444013b0b6371c9d75753fff333f82dc8e05914f2f73587153bb6e` | `883e9008a03132f99ba98a1284ae69d4397460474c376265600606fa6b3841c6` | LF canonical blob represented as CRLF by Windows checkout; Git content unchanged |
| `reports/PHASE_18_7C_LOCAL_EXECUTION_ENVIRONMENT_TRUST_ENVELOPE_REPORT.md` | `c54d146402bbc1b54462c9f56aeaaecef1e4ca1897f6715c517ff2b303c88f53` | `3946f01490f7083014722f629a0771f647d4db2300e3f4cf444cfd24e27999f7` | LF canonical blob represented as CRLF by Windows checkout; Git content unchanged |
| `outputs/SBP_OPERATOR_ASSISTANT_V1_COMMIT_AND_TEST_REPORT.md` | `c5368f644d6f887570bd76b38a5ab681857649fd2ba13ef22fb2b087e318d095` | `8669b8390f202872bab0e171eda84345624e9ccb9df69452f1ed28db6dbd7c85` | LF canonical blob represented as CRLF by Windows checkout; Git content unchanged |
| `docs/LOCAL_TRUST_ROOT_MANIFEST.md` | `536fb0eb18e419b9196cc802ea72e13a8e5195b3e360af8d6b8659407dae4bdb` | `7cbb6719eac0e4e7fbe260b8f3330e5a97a56df38036d963f423b6a34b9f3833` | LF canonical blob represented as CRLF by Windows checkout; Git content unchanged |
| `docs/LOCAL_EXECUTION_ENVIRONMENT_TRUST_ENVELOPE.md` | `7732bd31b73bffa0e50dbc08d35b4480cc4a4c3d49a4e494fb264f6921e3387e` | `890f2c62cdfe3b909dcf1f622cdf4bdc5e7484e41d4cff83a1b3a5d03a25e01e` | LF canonical blob represented as CRLF by Windows checkout; Git content unchanged |

## Refreshed trust bindings

- Root manifest: `551839dafd12d59f1c4945568f2be2fd896758eade95d8acdc3a6e4c629405e5`
- Execution envelope: `6b669bffba26942aa96b8310b3e2abf05590db0bcdeb46ef31adef1c0b1923ea`
- Evidence chain: `76366eca3cab51d1d81f6bf51c5dee16e30d21dfd76f75e82b8973b051c06c55`
- Regression matrix: `3ae965acd061631ecabb9719451996fe0429f43f0f1f989b2332f0c8ff4e878f`
- Constitutional gates: `9fc7aa05cc11184c3543a923a69652ee728e2cdbf33648fb72b93e1d4181d637`
- Toolchain guard: `8c49b3a928f763d12ecf59506e6cfc135f1111a0f50312b0d83bffbc13675aac`
- Capstone: `dc71e7ce2b2f692fea89862bdc97dcb5674a8b7864dfdfc65a5b7cc9e25291c4`

## Exclusions and invariants

The separate cognitive branch, its untracked `baselines/`, experiments,
cognitive documents, and the preserved stash were not incorporated, inspected
deeply, modified, applied, or deleted. No future-version material was added.
The canonical traversal, deterministic replay, single-host architecture, and
no-node rule remain unchanged.

## Validation results

- Local trust manifest: VALID
- Execution environment envelope: VALID
- Evidence chain: VALID; compare changed items: 0
- Regression matrix: VALID; 19/19 cases passed
- Constitutional enforcement: PASS; 24/24 gates passed
- Toolchain guard: PASS; 39/39 checks passed; pytest 9.1.1 recorded
- Local-trust capstone: PASS

- Compile check: PASS
- Direct pytest: 727/727 passed
- `scripts\run_tests.bat`: 727/727 passed
- Runtime: ALLOW / EXECUTE / MODE_2_SPLIT_VALIDATOR; convergence matched
- Replay: 2/2 matched; zero mismatches
- Git diff check: PASS before commit
