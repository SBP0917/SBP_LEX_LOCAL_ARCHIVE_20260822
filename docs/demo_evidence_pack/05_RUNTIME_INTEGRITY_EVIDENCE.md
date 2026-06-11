# Runtime Integrity Evidence

## Local/private posture

Desktop V1 defaults to localhost operation and the documented launch binds the
server to `127.0.0.1`. The dashboard is a private operator-facing surface, not
a public service.

## Authority boundary

The canonical runtime remains authoritative. The dashboard renders available
runtime status and evidence but does not move governance, admissibility,
execution, chronology, replay, audit, token, or convergence authority into the
browser.

## Controlled serving

The supplied background image is served through one explicit access-controlled
route. An adjacent arbitrary static image path is not permitted. Existing
runtime, health, integrity, dashboard, export, and controlled demo endpoints
remain governed by the current route and access policy.

## Verification purpose

- The health endpoint confirms service availability and access posture.
- The integrity endpoint reports runtime contract and environment checks.
- The smoke check combines health, traversal, convergence, mode, status,
  integrity, environment security, and dashboard checks.
- Static route tests confirm the intended image is available without enabling
  arbitrary file serving.

This is evidence for a local V1 prototype. It is not a production security
certification, penetration-test report, accreditation, or compliance opinion.
