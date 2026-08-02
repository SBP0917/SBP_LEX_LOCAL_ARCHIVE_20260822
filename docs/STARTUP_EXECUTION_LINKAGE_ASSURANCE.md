# Startup-to-Terminal Linkage Assurance

The linkage assurance suite checks one continuous, fail-closed identity chain:

1. measured startup attestation and approved baseline;
2. canonical traversal authority;
3. single-use execution capability;
4. adapter completion evidence;
5. terminal execution attestation and durable lifecycle record.
6. detached formal state and causal-lineage verification.

Every link explicitly carries and verifies the runtime identity, approved baseline
identifier, measurement digest, startup attestation digest, startup sequence,
request fingerprint, traversal authority digest, capability digest, and audit
lineage fields applicable to that link.

The suite also verifies that:

- missing startup binding fields deny authority creation;
- any binding drift before issuance or during execution fails closed;
- stale approved identity state is erased after drift rejection;
- signed V1 downgrade artifacts are rejected at every link;
- re-signed malformed or substituted evidence is rejected;
- a `COMPLETED` terminal attestation requires valid positive completion evidence;
- the terminal attestation binds the exact completion-evidence digest.

The repository-owned test runners remove inherited Python and pytest injection
surfaces, disable user-site packages, and disable third-party pytest plugin
autoload before Python starts. The runner scripts and this procedure are
themselves included in Local Trust, measured-startup, and R2 provenance scope.
The linkage wrapper also requires Git to report a clean tracked and untracked
working tree before it launches Python.

## Run on Windows

From the repository root:

```bat
scripts\run_linkage_assurance.bat
```

Success requires a zero exit code and no failures or unexpected skips. This focused
suite does not replace the full canonical Windows verification; run the complete
release validation after the linkage suite passes and before regenerating the
university handover package.
