# Double Triple Pre-Handover Assurance Report

## Purpose

This report defines and records the high-assurance hardening layer added before
the Desktop V1 university handover. It does not claim certification and does
not convert historical evidence into current evidence.

## Implemented control

The Double Triple Standard requires:

- one complete suite in an isolated pytest process;
- three complete linkage-assurance runs in three additional fresh processes;
- source, cryptographic-evidence, and repository/package verification layers;
- a clean tracked and untracked Git state before, between, and after the gates;
- explicit out-of-band ML-DSA public-key fingerprint agreement;
- zero legacy V1 signature or deterministic-placeholder markers in bounded
  handover evidence;
- a repository-bound R4 verification as the terminal gate.

The cross-platform entry points are
`scripts/run_double_triple_assurance.bat` and
`scripts/run_double_triple_assurance.sh`. The implementation is
`sbp_lex/assurance/double_triple.py`; its adversarial contract is in
`tests/test_double_triple_assurance.py`.

## Hardened conditions

The gate clears interpreter and pytest injection variables before Python starts,
disables user-site and third-party pytest plugin autoload, isolates production
trust material from test subprocesses, rejects optimized-away runtime
assertions, performs strict JSON parsing, checks dependency integrity and Git
object integrity, and refuses symlinked evidence.

R2 now distinguishes checkout bytes from canonical Git-blob bytes, declares
its direct `packaging` dependency, rejects all untracked files, and preserves
explicit symlink rejection. R4 verifies the production signing fingerprint,
deeply verifies nested evidence, constrains the permissible handoff commit, and
rejects legacy evidence even if the outer package is re-signed.

## Current bounded result

The clean source audit in the current controlled Linux environment passed:

- complete repository suite: `1785/1785`;
- startup-to-terminal linkage run 1: `141/141`;
- startup-to-terminal linkage run 2: `141/141`;
- startup-to-terminal linkage run 3: `141/141`;
- strict tracked JSON schemas: 50;
- statically parsed production Python files: 377;
- dependency integrity, bytecode compilation, Git diff integrity, and Git
  object integrity: pass.

The three linkage results came from three separately initialized pytest
processes after the complete-suite process, with a clean-repository gate before
every run. These results validate the hardening source in the audit environment;
they do not substitute for canonical Windows evidence generation.

The uploaded historical evidence is not relabelled. Any file containing the
legacy V1 provider-signature marker or the deterministic-placeholder marker
remains a blocking failure until regenerated on the canonical Windows host
with the controlled production trust identity and an explicitly approved
successor baseline.

The bounded evidence scan found 28 affected artefacts. Therefore the evidence
half of the Double Triple gate correctly returned non-zero and did not run the
downstream validators against evidence already known to be disqualified.

## Handover rule

University handover is authorized only when the canonical Windows command
below completes with a zero exit code and its terminal line is
`DOUBLE_TRIPLE_HANDOVER_ASSURANCE_PASS`:

```powershell
.\scripts\run_double_triple_assurance.bat
```

Passing a partial diagnostic mode is not equivalent to passing the handover
gate.
