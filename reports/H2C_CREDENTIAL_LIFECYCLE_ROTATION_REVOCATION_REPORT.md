# H2C Credential Lifecycle, Rotation, Expiry and Revocation Report

## Baseline and scope

- Starting commit: \`8b0e266053160f78bcf43f080394afeb2e6d4b34\`
- Ending commit: the single commit containing this report; the exact
  content-addressed hash is recorded in the final task handoff.
- Scope: SBP-LEX DUAL V6 Desktop V1, local/private, single-host.
- Architecture changes: none.
- No-node rule: preserved.

This package governs API transport credentials only. It does not duplicate or
alter Root-of-Trust, PQC provider, audit-signing, or canonical-runtime key
lifecycle.

## Files changed

- \`sbp_lex/api/credential_lifecycle.py\`
- \`sbp_lex/api/request_auth.py\`
- \`tests/test_h2c_credential_lifecycle.py\`
- \`tests/test_h2ab_scoped_request_auth.py\`
- \`DEPLOYMENT_SECURITY.md\`
- this report

## Credential lifecycle schema

Strict records contain \`credential_id\`, \`principal_id\`,
\`principal_type\`, \`credential_version\`, \`credential_purpose\`,
\`allowed_scopes\`, \`issued_at\`, \`not_before\`, \`expires_at\`, \`status\`,
\`rotation_group\`, \`replacement_credential_id\`, \`revoked_at\`,
\`revocation_reason\`, \`last_used_at\`, \`device_id\`, and \`secret\`.
Unknown, incomplete, duplicate-ID, invalid-time, invalid-state, unsupported
version, or secret-bearing identifier records invalidate the configured
registry.

Secrets are excluded from public snapshots, events, access results, reports,
health responses, and exports. Safe successful use updates \`last_used_at\`
inside the locked local registry.

## State-transition table

| From | To | Rule |
|---|---|---|
| PENDING | ACTIVE | Administrator-authorized; only at/after \`not_before\` |
| ACTIVE | ROTATING | Administrator-authorized, unique request, valid replacement |
| ROTATING | RETIRED | Deterministic at bounded-overlap expiry |
| ACTIVE/ROTATING/PENDING/SUSPENDED/EXPIRED | REVOKED | Immediate authorized revocation |
| REVOKED | any authenticating state | Denied |
| RETIRED | any authenticating state | Denied; historical record only |
| EXPIRED | ACTIVE | Denied; requires a new credential identity |

All lifecycle operations are guarded by one registry lock. Events are frozen,
append-only dataclasses with monotonic sequence and deterministic event digest.
Transition request IDs are single-use.

## Rotation policy

Rotation requires a distinct replacement credential in the same rotation
group, with the same principal ID and type, a strictly higher version, and
equal-or-narrower scopes. The replacement must already satisfy ACTIVE time
bounds. Overlap is limited to 1-300 seconds.

ACTIVE is the ordinary authenticating state. ROTATING is the sole constrained
exception: the old credential authenticates only before its overlap deadline
and only while its valid ACTIVE replacement remains same-principal,
same-type, higher-version, and equal-or-narrower. It then becomes RETIRED.
This reconciles bounded operational overlap with default ACTIVE-only policy.

## Revocation and scope preservation

Revocation changes status atomically to REVOKED, records time and reason,
removes rotation overlap, and immediately causes outstanding signed envelopes
to fail before signature acceptance. Revocation and rotation require an
ACTIVE administrator credential; self-transition and non-administrator
escalation are denied.

Replacement scope broadening, principal-type mutation, principal mutation,
rotation-group substitution, version downgrade, duplicate replacement IDs,
unbounded overlap, request replay, and silent reactivation fail closed.
Administrator credentials gain no execution authority; viewer and maintenance
boundaries remain unchanged.

## Tests and verification

Added 25 H2C tests. Together with H1/H2 regression coverage, targeted
verification was 181 tests. Coverage includes all states, activation,
bounded overlap/expiry, replacement validity, scope/type/version attacks,
rotation and revocation replay, emergency revocation, outstanding-envelope
invalidation, self-transition, self-escalation, immutable events, secret
non-disclosure, version/schema failure, administrator non-authority, viewer
observation-only behavior, and maintenance boundaries.

Commands and results:

- \`python -m compileall -q .\`: PASS
- targeted H2C/H2AB/H1 tests: 181 passed
- full pytest: 900 passed
- \`scripts\\run_tests.bat\`: 900 passed
- local-trust manifest, execution envelope, evidence chain, regression matrix,
  constitutional gates and toolchain guard: PASS
- evidence compare: zero changed items
- capstone: PASS
- runtime: ALLOW / EXECUTE / MODE_2_SPLIT_VALIDATOR; convergence matched
- replay: 2/2 matched; zero mismatches
- \`git diff --check\`: PASS before commit

## Security properties and remaining limitations

Established: deterministic strict registry loading, atomic authorized
transitions, immutable lifecycle events, immediate revocation, bounded
rotation, replay-safe transition requests, version monotonicity, scope
preservation, no self-escalation, and lifecycle enforcement before request
acceptance.

Limitations: the registry, transition journal, last-use timestamp, and
outstanding-envelope invalidation state are process-local and memory-resident.
Environment configuration remains the startup source. Durable single-host
crash-safe persistence is intentionally deferred to a separate bounded
package; no distributed or architectural facility was introduced.

The cognitive branch, its pre-existing untracked artefacts, and the preserved
stash were not modified, applied, merged, or incorporated. No push was
performed.
