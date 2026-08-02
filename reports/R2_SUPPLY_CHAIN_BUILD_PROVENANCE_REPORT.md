# R2 Supply Chain, Build Provenance and Artefact Authenticity Assurance

## Mission scope

R2 is a detached engineering-assurance package for SBP-LEX Dual V6 Desktop V1.
It strengthens provenance from canonical source through repository, dependency,
build, artefact, measured-runtime, and validation evidence. It does not alter
canonical traversal, execution authority, governance, runtime topology,
measured-startup architecture, Local Trust architecture, H7, H8, PHQ, or R1.

Starting commit: `42b17ba9c87a8d17a6d48c46b608ed68ce19efab`

Desktop scope remains local-first, private, deterministic, authority-first,
fail-closed, single-host, and no-node.

## Assurance architecture

The package creates three offline artefacts:

1. `outputs/r2_software_bill_of_materials.json` contains the deterministic
   dependency closure and dependency digest.
2. `outputs/r2_deterministic_build_manifest.json` contains a deterministic
   payload wrapped by the existing approved PQC provider.
3. `outputs/r2_offline_verification.json` records the verified provenance-link
   result and is independently sealed.

The canonical payloads contain no build timestamp. PQC signatures are external
proof envelopes around deterministic payload digests; their provider-generated
signature bytes are not treated as deterministic build inputs.

R2 outputs are self-authenticating evidence rather than inputs to the Local
Trust manifest. R2 source, schemas, tests, verifier, and this report are Local
Trust protected. This separation prevents a circular dependency in which a
signed R2 output hashes Local Trust while Local Trust simultaneously hashes the
same newly signed output.

## Repository provenance

Repository provenance records and verifies:

- normalized canonical origin identity;
- canonical `main` branch;
- source commit and Git tree identity;
- bounded first-parent lineage;
- repository provenance digest;
- ancestry of the recorded source commit to the current canonical HEAD.

Unknown origins, noncanonical branches, detached or duplicate lineage,
repository-tree mismatch, and non-ancestor history fail closed. The build
manifest records the source commit from which the R2 candidate was produced;
new R2 source and evidence are bound separately through artefact hashes.

## Dependency provenance and SBOM

The deterministic SBOM begins with `requirements.txt` and resolves the active
installed dependency closure using local distribution metadata. It records:

- direct and transitive relationship;
- exact installed version;
- declaring parent packages;
- installer and project metadata source;
- licence metadata;
- aggregate SHA-256 of every declared installed distribution file;
- distribution file count and total size;
- approval and integrity status.

Direct versions must satisfy the repository declaration. Every dependency must
exist locally. Offline validation recomputes each distribution hash, size, and
file count and rejects missing, substituted, modified, duplicated, unknown, or
unapproved dependencies. Absolute installation paths are not emitted.

## Build provenance

Build provenance binds:

- repository commit;
- approved measured-baseline identifier and sequence;
- measurement digest and runtime identity;
- Python implementation, version, architecture, executable name, and executable
  SHA-256;
- operating-system identity;
- Local Trust Toolchain Guard digest;
- PQC policy, algorithm, provider availability, and fail-closed status;
- cryptographic-provider version.

Interpreter, toolchain, PQC provider, repository, measured baseline, and runtime
identity substitution fail closed.

## Artefact inventory and authenticity

The build manifest deterministically inventories the protected canonical source,
schemas, tests, reports, documentation, and generated validation evidence already
registered by Local Trust. Each record contains a logical identity, portable
repository-relative path, checkout-byte SHA-256 and size, canonical Git-blob
identity, Git-blob-byte SHA-256 and size, repository origin, artefact type, and
creation relationship. Keeping checkout and Git-blob identities separate avoids
false equivalence across LF/CRLF checkout representations.

Duplicate logical identities, duplicate paths, absolute or escaping paths,
symlinks, missing files, foreign origin, hash mismatch, and size mismatch are
rejected. The inventory has its own deterministic digest.

## Supply-chain linkage

The signed build manifest verifies the complete local chain:

```text
Canonical repository
  -> approved dependency closure
  -> approved interpreter and toolchain
  -> protected artefact inventory
  -> measured baseline and runtime identity
  -> Local Trust and formal validation evidence
```

The chain is accepted only when every link validates. There is no warning-mode
continuation for missing or unknown provenance.

## Deterministic manifest

The manifest payload binds the repository provenance digest, SBOM dependency
digest, build identity, artefact inventory digest, validation-evidence bindings,
validation identity, measured baseline, and runtime identity. Canonical JSON and
SHA-256 provide deterministic identities. The existing ML-DSA provider signs the
domain-separated payload; no signing secret is serialized.

## Offline verification

`python -m sbp_lex.supply_chain.offline_verify` performs detached verification
using only:

- local Git objects and origin configuration;
- local installed-distribution metadata and files;
- local protected repository artefacts;
- the local measured-baseline store;
- existing Local Trust evidence;
- the trusted ML-DSA public verification key and expected SHA-256 fingerprint
  provisioned through a separate authenticated channel.

The verifier does not establish trust from public-key material copied only from
the evidence under review.

No network request, cloud service, package download, distributed builder, node,
or public deployment is required or introduced.

## Tamper and adversarial tests

Targeted tests cover repository identity normalization, repository digest and
lineage, dependency closure and ordering, dependency hash and version integrity,
missing and duplicated dependencies, build identity, measured-baseline and
runtime linkage, interpreter and toolchain binding, artefact hashing, path escape,
symlink rejection, substitution, duplicate identities, manifest corruption,
SBOM mismatch, stale artefacts, unknown provenance, validation-identity mismatch,
offline-result staleness, and deterministic generation.

The current targeted R2 suite passes `48/48`. It covers closed record schemas,
all untracked-file rejection, explicit direct and transitive dependencies,
installed-distribution hashes, working-copy and Git-blob identity separation,
false Git-blob claims, internal and escaping symlinks, artifact overrides,
repository lineage, deterministic ordering, and signed offline linkage.

The earlier `37/37` and `517/517` results remain historical evidence for their
recorded commits; they are not presented as the current repository total.

## Measured baseline and runtime linkage

R2 intentionally changes protected software and therefore H8 must fail closed
until explicit approval. The final successor is
`DESKTOP_V1_R2_APPROVED_2026_07_12_15`, retiring the R2 evidence checkpoint
`DESKTOP_V1_R2_APPROVED_2026_07_12_14`, under approval reference
`R2_SUPPLY_CHAIN_BUILD_PROVENANCE_FINAL_2026_07_12`.

Baseline 14 was explicitly approved after the initial R2 evidence freeze. The
complete suite then exposed a pre-existing H2 test-fixture defect: a credential
used with the live clock had a fixed absolute expiry. The fixture was corrected
to install a credential relative to the live test clock, without changing H2
runtime behavior. Because that test and this factual report are protected,
baseline 14 is retired through the normal explicit transition to baseline 15.

The final R2 bundle is built after Local Trust evidence and the measured baseline
are finalized, ensuring its recorded baseline and runtime identity are current.

## Verification commands

```text
python -m compileall -q .
python -m pytest -q
scripts\run_tests.bat
python -m sbp_lex.runtime.measured_startup validate
python -m sbp_lex.local_trust.manifest validate
python -m sbp_lex.local_trust.evidence_chain compare
python -m sbp_lex.local_trust.constitutional_gates validate
python -m sbp_lex.local_trust.toolchain_guard validate
python -m sbp_lex.local_trust.release_integrity validate
python -m sbp_lex.local_trust.local_trust_capstone validate
python -m sbp_lex.supply_chain.assurance validate
python -m sbp_lex.supply_chain.offline_verify
scripts\run_double_triple_assurance.bat
python main.py
python main.py replay
git diff --check
git status --short
```

## Limitations

- R2 verifies the installed dependency closure and files; it does not download
  or contact package-index transparency services.
- Licence values are distribution-supplied metadata, not a legal opinion.
- The signed manifest binds the recorded source commit and the candidate R2
  artefacts; generating an artefact that embeds the hash of the commit containing
  itself is intentionally avoided as a cryptographic self-reference.
- External reproducible-build witnesses, independent notarisation, hardware key
  custody, and third-party transparency logs remain outside this local mission.

## Architectural and push status

Canonical runtime architecture is unchanged. R2 is detached, non-authoritative
engineering assurance. Desktop V1 remains local, private, single-host, and
no-node. Push is permitted only after the full verification chain passes, the
final measured baseline is explicitly approved, the one local commit is clean,
and post-commit checks succeed.

## Current hardening reconciliation

The current source audit passed the complete suite `1785/1785` and the
startup-to-terminal linkage suite `141/141` in each of three fresh processes.
The R2 targeted suite passed `48/48`.

Those source results do not validate the uploaded generated evidence. The
pre-handover evidence gate found 28 bounded historical artefacts containing
legacy V1 or placeholder proof material. R2 production evidence must therefore
be regenerated from a clean canonical Windows commit after explicit successor
baseline approval and with the controlled production trust identity. Until the
default Double Triple handover command passes, the current handover package is
blocked.
