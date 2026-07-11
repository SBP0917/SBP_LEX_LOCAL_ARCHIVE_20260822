# H2A/H2B Scoped Identity and Request Binding Report

## Baseline and scope

- Starting commit: \`26221d9629667b6d139b6221c361c5e5143c768b\`
- Ending commit: the single commit containing this report; its exact
  content-addressed hash is recorded in the final task handoff.
- Scope: SBP-LEX DUAL V6 Desktop V1, local/private, single-host.
- Architecture changes: none.
- No-node rule: preserved.

## Files changed

- \`sbp_lex/api/request_auth.py\`
- \`sbp_lex/api/access_control.py\`
- \`sbp_lex/api/server.py\`
- \`tests/test_h2ab_scoped_request_auth.py\`
- \`DEPLOYMENT_SECURITY.md\`
- this report

## Principal model and authorization matrix

Authorization is default-deny. Endpoint paths map to one scope:
\`observe\`, \`runtime:traverse\`, \`runtime:replay\`,
\`connector:submit\`, or \`connector:build\`.

| Principal | GET/observe | Traverse | Replay | Submit connector envelope | Build connector envelope |
|---|---:|---:|---:|---:|---:|
| viewer | Allow | Deny | Deny | Deny | Deny |
| operator | Allow | Allow | Allow | Deny | Deny |
| validator | Allow | Deny | Allow | Deny | Deny |
| connector | Allow | Deny | Deny | Allow | Allow |
| replay_examiner | Allow | Deny | Allow | Deny | Deny |
| administrator | Allow | Allow | Allow | Allow | Allow |
| maintenance | Allow only while canonical execution is inactive | Deny | Deny | Deny | Deny |

Administrator scope permits API submission only; it does not create, replace,
or bypass canonical execution authority. APK/UI legacy access is mapped to an
observation-only viewer.

## Request-authentication envelope

The strict schema contains:
\`protocol_version\`, \`request_id\`, \`credential_id\`, \`principal_id\`,
\`principal_type\`, \`device_id\`, \`method\`, \`canonical_path\`,
\`canonical_query_digest\`, \`canonical_body_digest\`, \`content_type\`,
\`issued_at\`, \`expires_at\`, \`nonce\`, \`security_mode\`,
\`credential_scope\`, and \`signature\`.

Signatures are HMAC-SHA256 over canonical JSON excluding only the signature
field. Bodies are parsed with strict duplicate-key and non-finite-number
rejection, re-encoded as sorted compact JSON, and SHA-256 bound. Method, path,
sorted query, content type, credential, principal, device, mode, and scope are
independently bound. Envelopes have a maximum 120-second window and five-second
future skew. Nonces and request IDs are single-use per credential.

Transport authentication remains outside EIE. It does not replace or bypass
Hard Entry, Root of Trust, Procedural Truth, Classification, Licensing,
Governance, GRC, Domain, Aurion, Execution Gate, or Audit.

## Compatibility decisions

- Local localhost mode retains existing unauthenticated local behavior.
- Private GET bearer compatibility is explicit, temporary, fail-closed, and
  restricted to a synthetic viewer identity with \`observe\` scope.
- A legacy bearer cannot authorize a private POST.
- Private state-changing requests require a valid scoped signed envelope.
- Scoped signed GET requests are supported without broadening bearer authority.

## Tests and results

Added 148 H2 tests covering every principal against every GET and POST
endpoint, viewer mutation denial, connector replay denial, replay-examiner
traversal denial, maintenance inactivity, administrator non-authority,
credential expiry/revocation/scope/identity failures, all binding mutations,
nonce/request-ID reuse, expiry/future issuance, signature failure, duplicate
keys, cross-endpoint/payload replay, compatibility, and secret non-disclosure.

Commands and results:

- \`python -m compileall -q .\`: PASS
- targeted H2 plus H1 suite: 156 passed
- \`python -m pytest -q --basetemp=runtime_artifacts\\pytest_tmp_h2ab_full\`:
  875 passed
- \`scripts\\run_tests.bat --basetemp=runtime_artifacts\\pytest_tmp_h2ab_bat\`:
  875 passed
- local-trust manifest/envelope/evidence/regression/gates/toolchain validation:
  PASS; evidence compare changed items 0
- capstone validation: PASS
- runtime: ALLOW / EXECUTE / MODE_2_SPLIT_VALIDATOR; convergence matched
- replay: 2/2 matched; zero mismatches
- \`git diff --check\`: PASS before commit

## Security properties and limitations

Established: scoped principals, endpoint allowlists, default deny, signed
canonical request binding, strict JSON, replay prevention, bounded freshness,
private POST legacy-bearer rejection, and secret-free results/events.

Remaining limitations: credentials are supplied through local environment
configuration; replay memory is process-local and intentionally single-host;
legacy private GET viewer compatibility remains temporary and should be
removed in a separately authorized migration. No credential lifecycle service,
network topology, distributed state, or architectural redesign was added.

The cognitive branch, its untracked artefacts, and the preserved stash were
not modified, applied, merged, or incorporated. No push was performed.
