# R4 Independent Verification and Validation Package Report

## Mission scope

R4 creates a detached Independent Verification and Validation Package for
technical assessors. It packages existing evidence; it does not introduce a new
runtime capability, alter authority, change governance, redesign traversal,
modify constitutional behavior, or claim certification.

Starting commit: `a9d9f57a2a92d1320add5aa3b60935fbd1e1f390`.

Desktop V1 remains local-first, private, deterministic, authority-first,
fail-closed, single-host, and no-node. H7, PHQ, R1, R2, and R3 are reused without
behavioral modification.

## Package architecture

`validation_package/` is a curated evidence set rather than a repository copy.
It contains no Python source implementation. Its deterministic records are:

- `REPOSITORY_IDENTITY.json`;
- `ENGINEERING_CLAIMS_REGISTER.json`;
- `EVIDENCE_TRACEABILITY_INDEX.json`;
- `EVIDENCE_INVENTORY.json`;
- `RUNTIME_REPLAY_EVIDENCE.json`;
- `VERIFICATION_COMMANDS.json`;
- `INDEPENDENT_VERIFICATION_GUIDE.md`;
- `QUICK_START.md`;
- `VALIDATION_SUMMARY.md`;
- `PACKAGE_MANIFEST.json`;
- curated copies beneath `evidence/`.

The package manifest hashes every included file except itself, binds all
identity and register digests, and is signed through the existing
domain-separated PQC provider. The manifest payload is deterministic; provider
signature bytes are external proof material and are not treated as deterministic
build inputs.

## Repository identity package

The identity sheet binds the canonical SBP-LEX Dual V6 Desktop V1 designation,
normalized repository identity, source commit, Git tree, repository digest,
approved measured baseline, measurement digest, runtime identity, and Desktop V1
scope. The package verifier rejects foreign identities, invalid digests,
rewritten ancestry, and Git-tree mismatch.

The recorded commit is the evidence-source commit from which the package is
generated. The final commit contains the package, so embedding the final commit's
own hash inside itself is intentionally avoided as a cryptographic self-reference.

## Engineering claims register

The deterministic register contains bounded engineering claims for H7, PHQ, R1,
R2, R3, the Double Triple pre-handover gate, Local Trust, Constitutional Gates,
Toolchain Guard, Release Integrity, Capstone, runtime, and replay. Every claim
has:

- a stable claim identifier;
- restrained engineering language;
- implementation reference;
- verification source;
- supporting report and test references;
- explicit evidence status.

Supported claims without report and test evidence fail validation. Unsupported
claims may be represented only when explicitly marked `UNSUPPORTED`; the package
does not infer evidence or overstate conclusions.

## Evidence traceability and inventory

The traceability index maps every major assurance layer to an originating report
or evidence artefact, verification method, and current status. The evidence
inventory records deterministic identifiers, original repository-relative path,
package-relative path, SHA-256, byte size, and presence status.

Curated evidence includes H7 and PHQ reports, R1 recovery inventory/drill, R2
SBOM/build/offline verification, R3 custody profile, the Double Triple report,
the measured-baseline store, Local Trust root and evidence chain, Constitutional
Gates, Toolchain Guard, Release Integrity, Capstone, formal assurance,
adversarial evidence, and protected baseline documentation.

Missing, stale, substituted, unexpected, foreign, or internally inconsistent
evidence fails closed.

## Independent verification guide and quick start

The assessor guide assumes no repository familiarity. It explains identity,
contents, sequence, expected output, result interpretation, assumptions, and
limitations. The quick start is bounded to 10-20 minutes:

1. inspect the repository identity sheet;
2. run the detached package verifier;
3. confirm `R4_IVVP_VALID`;
4. review claims and evidence traceability;
5. optionally run the non-mutating repository command pack when read access is
   available.

An assessor can verify package integrity without repository write access and
without reviewing proprietary source implementation. Repository access is only
needed for optional reproduction of the established validation commands.

## Verification command pack

The command pack contains only supported validation commands. It covers IVVP,
measured startup, Local Trust, evidence comparison, Constitutional Gates,
Toolchain Guard, Release Integrity, Capstone, R2 offline verification, and R3
custody validation. It also contains exactly one approved Windows launcher for
the terminal Double Triple handover gate. Any renamed or substituted batch
launcher is rejected. Every command is marked as non-mutating to tracked
repository state and includes an expected output.

Runtime and replay are represented by freshly collected deterministic evidence
inside the signed package. This permits read-only independent verification; live
runtime reproduction remains optional because it writes operational data only to
the established ignored runtime-artifact area.

## Evidence integrity

The verifier checks:

- package signature and package identity;
- explicit agreement with an out-of-band trusted signer fingerprint;
- exact package file set and every file hash/size;
- common repository, baseline, and runtime identities;
- claims and traceability digests and links;
- evidence inventory hashes;
- copied measured-baseline integrity signature;
- R2 and R3 signatures and baseline/runtime linkage;
- recorded runtime PASS and replay PASS with zero mismatches;
- command-pack digest and non-mutation flags;
- checkout-byte and canonical Git-blob identities for tracked evidence;
- optional source-commit ancestry and Git-tree identity;
- when repository access is supplied, either the exact evidence-source commit
  or one direct child whose changes are confined to `validation_package/`.

The package rejects stale measured identity, stale R2/R3 evidence, broken report
links, broken traceability, corrupt signatures, duplicate records, unexpected
files, failed runtime/replay evidence, legacy/placeholder assurance material,
false Git-blob claims, arbitrary descendant handoff commits, and unapproved
verification launchers.

## Validation summaries

The package includes concise non-marketing summaries for executive reviewers,
engineers, researchers, and university assessors. It describes implemented
assurance and limitations without commercial claims, certification claims, or
claims of mathematical proof beyond the implemented formal verification.

## Tests

The current targeted R4 suite passes `42/42`. In addition to the original
coverage, it now tests out-of-band signer fingerprints, exact package
replacement recognition, nested evidence tampering after outer re-signing,
legacy evidence after outer re-signing, portable paths, working-copy/Git-blob
identity attacks, direct package-only handoff commits, arbitrary descendant
rejection, and exact authorization of the measured Double Triple launcher.

The earlier `26/26` and focused `578/578` results remain historical evidence
for their recorded commits; they are not the current repository totals.

## Measured baseline linkage

R4 changes protected assurance code, tests, schemas, and this report. The
intended successor is `DESKTOP_V1_R4_APPROVED_2026_07_13_17`, retiring
`DESKTOP_V1_R3_APPROVED_2026_07_12_16` under approval reference
`R4_INDEPENDENT_VERIFICATION_PACKAGE_2026_07_13`.

After evidence and baseline finalization, R2 and R3 are refreshed, real runtime
and replay evidence is collected, and the final IVVP is generated. This ordering
ensures every copied artefact references the same final baseline and runtime
identity.

## Limitations

- IVVP provides independent evidence verification, not institutional
  certification, accreditation, or legal assurance.
- Curated evidence avoids unnecessary source disclosure; an assessor cannot use
  this package alone to perform a complete line-by-line source audit.
- Recorded runtime/replay evidence is signed and hash-bound; live reproduction
  requires a compatible approved local toolchain and writable runtime-artifact
  location.
- Independent external witnesses, hardware attestations, and university review
  conclusions remain outside this repository mission.

## Architectural impact

None. R4 is detached and non-authoritative. It introduces no node, cloud
validation, remote execution, distributed topology, new runtime behavior, or
constitutional change.

## Historical verification evidence

The earlier R4 Linux archive run is retained as an intermediate historical
snapshot. It recorded `1,630 collected`, `1,340 passed`, `283 failed`, and
`7 errors`. Those values are not the current repository state and are not used
as the canonical Windows result.

The parent evidence-source commit
`a9d9f57a2a92d1320add5aa3b60935fbd1e1f390` independently collects 1,618
tests. R4's final commit adds the single 26-test file
`tests/test_r4_independent_verification_package.py`. The historical 1,630 count
therefore represents the parent suite plus an intermediate 12-test R4 working
file. The final 14 tests added to reach 1,644 are:

- `test_unexpected_package_file_rejected`;
- `test_corrupt_manifest_rejected`;
- `test_foreign_identity_rejected`;
- `test_stale_runtime_identity_rejected`;
- `test_stale_r3_evidence_rejected`;
- `test_broken_report_link_rejected`;
- `test_broken_traceability_rejected`;
- `test_runtime_failure_evidence_rejected`;
- `test_command_mutation_flag_rejected`;
- `test_package_contains_no_source_code`;
- `test_quick_start_is_bounded`;
- `test_summary_disclaims_certification`;
- `test_inventory_identifiers_are_deterministic`;
- `test_all_documents_share_identity`.

No historical test disappeared. The 14-test increase is bounded to R4 negative
integrity, assessor-document, deterministic-identity, and cross-document
consistency coverage.

## Corrective Windows work

Canonical Windows pre-flight initially failed closed because the approved R4
measurement captured mixed working-tree line endings that a fresh checkout
could not reproduce. Reconciliation proved that the 17 apparent content
mismatches and 68 CRLF-only mismatches were checkout representation defects,
not semantic runtime regressions.

The correction:

- adds a repository-owned `.gitattributes` policy;
- keeps ordinary source and documentation at LF;
- preserves CRLF only for Windows launchers and Windows-generated hash-bound
  evidence whose embedded manifests cover those bytes;
- retains the exact approved CPython 3.12.13 AMD64 executable;
- refreshes Local Trust, R2, R3, release, dossier, and IVVP evidence through
  their existing fail-closed builders;
- retains the prior R4 baseline as retired historical evidence;
- changes no runtime behavior, provenance rule, branch rule, architecture, or
  test.

The canonical Windows run used the controlled approved baseline
`DESKTOP_V1_R4_RECONCILED_FINAL_2026_07_16_19`, measurement digest
`56d08812faded67aa0a73f391ed0b8c7df0f059d320ff201835df60e23e625b3`,
and runtime identity
`23c34e088901d64b86decb98114fd71932c02d60816cf3890e84dc4daf53ec58`.
The post-report evidence refresh necessarily creates a successor; its exact
identifier and digest are recorded in the final Windows verification package.

## Canonical Windows verification

Corrective verification commit:
`2c5f339ccf685cd1b856457029fd3b55de478730`.

The independent `main` clone used CPython 3.12.13 AMD64, pytest 9.1.1,
pluggy 1.6.0, and cryptography 49.0.0. `PYTEST_ADDOPTS` and `PYTHONPATH`
were removed, pytest caching was disabled, and every run used a new external
temporary root.

- Direct measured startup: `MEASURED_STARTUP_APPROVED`.
- Test collection: 1,644; zero errors; zero deselections.
- Targeted pre-flight: 921 passed, 3 skipped, zero failures/errors in 277.05s.
- Complete unselected suite: 1,641 passed, 3 skipped, zero failures/errors in
  378.94s.
- R1 skip at line 189: expected Windows `symlink creation unavailable`.
- R1 skip at line 358: expected Windows `symlink creation unavailable`.
- R2 skip at line 192: expected Windows `symlink creation unavailable`.
- Local Trust, Constitutional Gates, Toolchain Guard, Capstone, adversarial
  harness, Release Integrity, University Dossier, R2, R3, and IVVP all validate.

The detailed logs and hashes are retained in the controlled Windows canonical
checkout verification package generated after the final evidence commit.

## Current post-hardening status

The historical Windows verification above remains evidence for corrective
commit `2c5f339ccf685cd1b856457029fd3b55de478730` only. It does not validate
later protected hardening changes or later generated evidence.

The current source audit passed:

- complete suite: `1785/1785`;
- targeted R4 suite: `42/42`;
- startup-to-terminal linkage: `141/141` in each of three fresh processes;
- strict tracked JSON schemas: 50;
- statically parsed production Python files: 377;
- dependency, bytecode, Git diff, and Git object checks: pass.

The current uploaded package is not a university-ready IVVP. The pre-handover
gate found 28 bounded historical artefacts containing legacy V1 or placeholder
proof material across the source evidence, copied package evidence, package
manifest, and approved-baseline store. Those files must be regenerated on the
canonical Windows host with the controlled production trust identity after
explicit successor baseline approval.

Status: **IMPLEMENTATION HARDENED — CURRENT HANDOVER BLOCKED PENDING FRESH
CANONICAL WINDOWS EVIDENCE AND A FULL DOUBLE TRIPLE HANDOVER PASS**.
