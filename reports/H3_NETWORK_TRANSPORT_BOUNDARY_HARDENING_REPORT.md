# H3 Network and Transport Boundary Hardening Report

## Baseline and scope

- Starting commit: `1754146a89e9239aa3a2d254b49e3ab9c4905c2b`
- Ending commit: the single local commit containing this report; its exact
  content-addressed hash is recorded in the final task handoff.
- Scope: SBP-LEX DUAL V6 Desktop V1, local/private, single-host.
- Architecture changes: none.
- No-node rule: preserved.

H3 hardens the existing HTTP listener and transport boundary. It does not
activate public deployment, add remote infrastructure, redesign the API,
create node or cloud authority, or alter canonical traversal, replay,
Governance, EIE, Hard Entry, or execution outcomes.

## Files changed

- `sbp_lex/api/transport_security.py`
- `sbp_lex/api/server.py`
- `sbp_lex/api/access_control.py`
- `sbp_lex/runtime/event_bus.py`
- `tests/test_h3_network_transport_boundary.py`
- `DEPLOYMENT_SECURITY.md`
- this report

## Socket-peer model

The address obtained from `BaseHTTPRequestHandler.client_address` is the sole
authority for local/remote transport origin. Address parsing uses the standard
IP parser, canonicalizes IPv4-mapped IPv6, and rejects malformed literals,
hostnames, whitespace ambiguity, zone identifiers, unspecified addresses, and
multicast peers. The previous `127.*` string-prefix check was removed.

Each transport decision tracks separately:

- canonical `socket_peer`;
- configured `trusted_proxy_identity`;
- non-authoritative `asserted_client_identity`;
- canonical bounded `forwarding_chain`;
- selected `transport_profile`;
- optional, digest-derived `transport_device_identity`.

The socket peer—not a Host or forwarding header—is passed to H1/H2 access
control and H2D admission. A proxy assertion of `127.0.0.1` therefore cannot
grant local-mode access.

## Trusted-proxy and forwarded-header model

Proxy mode is disabled by default. Enabling it requires at least one exact
trusted address or bounded network plus one exact proxy identity. Exact
addresses, networks, identities, and hop counts are cardinality-bounded.
Wildcard addresses, `0.0.0.0/0`, `::/0`, broad networks, invalid CIDR,
duplicates, blank values, disabled-mode proxy settings, and implicit trust-all
fail before listener binding.

`Forwarded`, `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`,
`CF-Connecting-IP`, and `True-Client-IP` are recognized case-insensitively.
When the immediate socket peer is not trusted, these headers are ignored and
evidenced. When it is trusted, the required proxy identity must match and the
chain must contain canonical IP literals within the hop ceiling. Duplicate
header instances, multiple forwarding-header families, malformed values, and
an untrusted intermediate proxy are denied.

Request header cardinality is capped before chain processing. Forwarded
values, bearer material, request signatures, and reusable credentials are not
written to evidence.

## Listener bind policy

Bind validation occurs before H4A initialization, H2D initialization, TLS
wrapping, or socket creation:

- `local`: validated IPv4/IPv6 loopback literal and `LOCAL_PRIVATE` only;
- `private`: configured API credential/token, exact
  `SBP_LEX_BIND_ADDRESS`, and valid allowed transport profile;
- isolated test-only mode: retains the H1 harness restriction and loopback
  bind requirement.

Wildcard, hostname, non-loopback local, mismatched private, missing-auth,
plaintext remote, and unknown-mode binds fail closed. IPv6 listeners use an
IPv6-only server socket to prevent unexpected dual-stack exposure.

## Transport profiles and TLS/mTLS status

| Profile | Status | Enforcement |
|---|---|---|
| `LOCAL_PRIVATE` | Default, active | Loopback-only, no external certificate dependency |
| `PILOT_PRIVATE_TLS` | Inactive until explicitly configured | Private mode, exact bind, remote activation, TLS enabled, certificate/key files, TLS 1.2 minimum |
| `PILOT_PRIVATE_MTLS` | Inactive until explicitly configured | TLS controls plus CA, required client certificate, clientAuth purpose, expiry, exact service SAN identity, local SHA-256 denylist |
| `REMOTE_PRODUCTION_DISABLED` | Permanently denied | Cannot be activated |

The server builds and loads its `SSLContext` before socket binding, then wraps
the validated listener. mTLS uses `CERT_REQUIRED`. Peer DER certificates are
parsed for expiry, client-auth extended key usage, exact single service
identity, and a configured bounded fingerprint denylist. Expired,
explicitly-denied, wrong-purpose, and wrong-service fixtures fail closed.

TLS/mTLS tests use configuration and certificate test doubles. No real TLS
handshake was run, and this package does not claim CRL, OCSP, public PKI,
automated certificate issuance/renewal, hardware key custody, or production
certificate-revocation infrastructure. The local fingerprint denylist is the
only implemented explicit revocation mechanism.

## Connector/device identity boundary

Transport certificate/device identity, API principal identity, API credential
identity, connector envelope identity, and canonical runtime authority remain
separate. A dedicated boundary function always returns false for attempts to
derive API scope from transport identity. Consequently connector, viewer,
device, maintenance, or administrator certificates cannot independently
traverse, replay, submit/build connectors, mutate, administer, or execute.

Existing H2 scoped-principal and signed-envelope checks remain the only API
identity authorization path. Existing connector schema, digest/signature,
recovery, admission, and canonical traversal rules are reused unchanged.

## Security events

Transport failures are recorded in a separate non-canonical in-memory buffer
bounded to 256 entries. Evidence values are domain-digested and capped. Event
identifiers cover untrusted forwarding headers, malformed chains, proxy trust,
bind policy, transport profile, certificate identity, plaintext remote, and
unexpected peer failures. Runtime observability also recognizes the bounded
transport observed/rejected event types; neither event path contains secrets.

## Tests and verification results

`tests/test_h3_network_transport_boundary.py` adds 68 tests covering direct
IPv4/IPv6 loopback, IPv4-mapped IPv6, remote IPv4/IPv6, every forwarding
header rule, localhost forgery, trusted/unknown proxies, multi-hop and mixed
chains, hop overflow, malformed/duplicate/case-varied headers, wildcard and
CIDR configuration attacks, bind modes, all four profiles, TLS/mTLS activation,
certificate expiry/purpose/service/revocation, transport/API identity
separation, header cardinality, ambiguity, evidence bounds, secret leakage,
no partial canonical state, and no unintended ALLOW.

Commands and results:

- targeted H3 tests: 68 passed
- H3 plus H1/H2/H2D focused regression tests: 269 passed
- `python -m compileall -q .`: PASS
- `python -m pytest -q --basetemp=runtime_artifacts\pytest_tmp_main`: 1039 passed
- `scripts\run_tests.bat --ignore=runtime_artifacts`: 1039 passed; the ignore
  excludes only generated pytest basetemp trees with inherited sandbox ACLs,
  not repository tests or integrity gates
- manifest and execution-envelope validators: PASS
- evidence-chain validation/compare: PASS, zero changed evidence items
- regression matrix: PASS
- constitutional gates: PASS
- toolchain guard: PASS
- local-trust capstone: PASS
- `python main.py`: ALLOW / EXECUTE / MODE_2_SPLIT_VALIDATOR; convergence matched
- `python main.py replay`: 2/2 matched; zero mismatches
- `git diff --check`: PASS before commit

## Security properties and overlap removed

Established properties are authoritative socket-peer origin, validated IP
handling, default-untrusted forwarding headers, explicit proxy identity and
bounded chains, strict pre-bind policy, remote-plaintext denial, inactive
fail-closed TLS/mTLS pilots, certificate/device/API identity separation,
bounded non-secret events, and denial before request parsing or governed work.

Overlap was removed by reusing H1 mode/token enforcement, H2 scoped identities
and exact request binding, H2C credential lifecycle, H2D admission/leases, H4A
startup persistence, connector validation, and the existing canonical runtime.
No duplicate principal authorization, nonce/replay protection, admission
counter, connector authority, or API endpoint was introduced.

## Boundary preservation and remaining limitations

The implementation remains single-host Desktop V1. It adds no distributed
proxy registry, shared network rate, node, convergence protocol, cloud
authority, public ingress, external CA, certificate service, or cognitive
work. Pilot profile operation still requires operator-supplied local PEM files
and trust material and was not activated during this mission.

The canonical architecture, deterministic replay, and no-node rule are
unchanged. The preserved stash and detached cognitive branch—including its
pre-existing untracked `baselines/`, documentation, experiments, and report—
were not modified, applied, merged, or incorporated. GitHub was not contacted
for writes and no push was performed.
