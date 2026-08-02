# Double Triple Handover Assurance

## Standard

The Double Triple Standard is the fail-closed pre-handover rule for this
repository:

1. one complete test-suite run;
2. three separate fresh-process startup-to-terminal linkage runs;
3. three strength layers: source/runtime controls, cryptographic evidence
   integrity, and repository-bound handover verification.

No partial mode authorizes handover. Only the default handover mode may emit
`DOUBLE_TRIPLE_HANDOVER_ASSURANCE_PASS`.

## Canonical Windows command

From a clean canonical `main` checkout:

```powershell
.\scripts\run_double_triple_assurance.bat
```

The command clears Python and pytest injection variables before Python starts,
disables user-site and pytest plugin autoload, uses external bytecode storage,
checks Git integrity and cleanliness, parses every tracked JSON schema with
duplicate-key rejection, statically rejects runtime `assert`, dynamic execution,
unsafe deserialization, and `shell=True`, runs `pip check`, runs the complete
suite once, and runs the linkage suite three times in independent processes.

It then rejects legacy or placeholder evidence, confirms the separately
provided ML-DSA public key and fingerprint match, and validates measured
startup, Local Trust, evidence comparison, Constitutional Gates, Toolchain
Guard, Release Integrity, Capstone, R2, R3, and the R4 package against the
canonical repository.

## Required trust configuration

Before the handover run, provision these through the controlled production
process:

- `SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY`;
- `SBP_LEX_EXPECTED_SIGNER_FINGERPRINT`;
- `SBP_LEX_SIGNING_SECRET` only where evidence regeneration is explicitly
  authorized.

The verification public key and its SHA-256 fingerprint must come from a
separate authenticated channel. Values copied only from the package do not
establish trust.

## Diagnostic partial modes

These modes diagnose a bounded layer and do not authorize handover:

```powershell
.\scripts\run_double_triple_assurance.bat --mode source
.\scripts\run_double_triple_assurance.bat --mode evidence
```

`--mode source` cannot certify generated evidence. `--mode evidence` cannot
replace the complete test run or the three linkage runs.

## Evidence refresh boundary

The gate validates; it does not silently approve a measured-baseline change or
manufacture production signatures. After applying hardening changes to the
canonical repository, the owner must explicitly approve the successor measured
baseline and regenerate the Local Trust, release, dossier, R2, R3, runtime,
replay, and R4 evidence in dependency order. The repository must then be clean
before the default command is run.

Any source change, evidence change, trust-key mismatch, missing file, symlink,
unexpected package member, stale baseline, noncanonical Git lineage, or failed
command causes a non-zero exit. A failed run is not handover evidence.
