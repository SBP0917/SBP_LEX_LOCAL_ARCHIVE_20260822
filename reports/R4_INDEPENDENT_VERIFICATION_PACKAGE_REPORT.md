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
R2, R3, Local Trust, Constitutional Gates, Toolchain Guard, Release Integrity,
Capstone, runtime, and replay. Every claim has:

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
SBOM/build/offline verification, R3 custody profile, measured-baseline store,
Local Trust root and evidence chain, Constitutional Gates, Toolchain Guard,
Release Integrity, Capstone, formal assurance, adversarial evidence, and protected
baseline documentation.

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
custody validation. Every command is marked as non-mutating to tracked repository
state and includes an expected output.

Runtime and replay are represented by freshly collected deterministic evidence
inside the signed package. This permits read-only independent verification; live
runtime reproduction remains optional because it writes operational data only to
the established ignored runtime-artifact area.

## Evidence integrity

The verifier checks:

- package signature and package identity;
- exact package file set and every file hash/size;
- common repository, baseline, and runtime identities;
- claims and traceability digests and links;
- evidence inventory hashes;
- copied measured-baseline integrity signature;
- R2 and R3 signatures and baseline/runtime linkage;
- recorded runtime PASS and replay PASS with zero mismatches;
- command-pack digest and non-mutation flags;
- optional source-commit ancestry and Git-tree identity.

The package rejects stale measured identity, stale R2/R3 evidence, broken report
links, broken traceability, corrupt signatures, duplicate records, unexpected
files, and failed runtime/replay evidence.

## Validation summaries

The package includes concise non-marketing summaries for executive reviewers,
engineers, researchers, and university assessors. It describes implemented
assurance and limitations without commercial claims, certification claims, or
claims of mathematical proof beyond the implemented formal verification.

## Tests

The targeted R4 suite passes `26/26`. Tests cover repository identity,
deterministic claims and traceability, package determinism, required documents,
missing/substituted/unexpected evidence, corrupt manifests, foreign identity,
stale runtime identity, stale R3 evidence, broken report links, broken
traceability, failed runtime evidence, command mutation flags, source exclusion,
quick-start bounds, certification disclaimer, deterministic identifiers, and
cross-document identity consistency.

The pre-approval focused R4, R3, R2, R1, H4A, H6GHI, H7, and PHQ integration
suite passes `578/578`, with three expected Windows symlink skips.

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
