# Phase 15.5D Desktop V1 Operator Cockpit Report

## Files inspected

- Desktop dashboard renderer, snapshot projection, background route, API server,
  runtime status contract, replay/event exports, and dashboard tests
- Phase 15.5D owner specification plus heartbeat and storm doctrine

## Files changed

- `sbp_lex/desktop/cockpit.py` - new UI-only cockpit renderer
- `sbp_lex/desktop/dashboard.py` - delegates rendering to the cockpit and exposes
  read-only identity, Procedural Truth, and governed-reentry display fields
- `tests/test_desktop_dashboard.py` - eight additional doctrine-focused tests
- `reports/DESKTOP_V1_OPERATOR_COCKPIT_REPORT.md`

## UI layout

The primary viewport now contains pinned controls, visually separate Pipeline A
and Pipeline B wings, central scales, current state, last-current state,
recoverable/alive state, Procedural Truth status, execution outcome, and compact
licensing/scope identity. Operators do not need to leave the live cockpit to
start a traversal or observe it.

## Semantic state implementation

- PASS/ALLOW/EXECUTE: translucent emerald green
- ESCALATE/REFINE: amber
- DENY/FAIL/HALT/STOP: fire-truck red
- ACTIVE/PROCESSING/LIVE: electric blue
- IDLE/WAITING: neutral grey

No additional semantic colour language was introduced.

## Live ECG and heartbeat doctrine

Live traversal alone inserts the electric-blue travelling ECG SVG, path
illumination, controlled strobing, active scale motion, wind, and developing
storm. The ECG node is removed for every non-live mode.

Recoverable/alive states retain their semantic colour and use a two-second
thump-thump/pause heartbeat glow across the state and nearby pipeline section.
They have no ECG and no full-path illumination. Last-current state uses a steady
glow without ECG or strobe. Historical and terminal states are static.

## HALT and DENY

HALT remains an explicit execution-control label. A HALT is heartbeat-active
only when the retained governed-reentry data marks it recoverable. DENY remains
a terminal governed refusal. Both use fire-truck red but receive distinct labels,
meaning, state mode, and environmental behavior.

## Storm and scales

The deterministic awareness environment supports calm, live, residual/alive,
procedural-tension, denial-withdrawal, historical, terminal, and maximum-stable
execution modes. Weather reflects the current retained state only and never
calculates an outcome. Scales gently move while live, pulse subtly while alive,
tilt for escalation, react sharply for denial, and settle for successful or
historical states. Environmental layers remain behind the cockpit.

## Details, displays, and celestial workspace

Runtime, audit, Procedural Truth, bridge, and response details open on demand in
a side panel. Desktop layout reserves panel space so live content is not covered;
compact layouts place the panel in normal document flow. A user-initiated pop-out
supports secondary-display diagnostics with the same cosmic visual system and
360-degree, degree, minute, and second markings. Monitor absence has no runtime
effect. No automatic display permission is requested.

## Identity envelope

The cockpit projects existing read-only metadata when present: manufacturer,
system name, model/version, unique identifier, AP-ACF class/subclass, autonomy
level/ceiling, operational scope/environment, licence state/authority, short
request fingerprint, and current semantic state. It creates no authority.

## Verification

- Focused dashboard suite: 14 passed
- Full pytest suite: 108 passed
- Batch suite: 108 passed
- Compileall: passed; inaccessible pre-existing `.pytest_cache` skipped
- `python main.py`: unchanged ALLOW/EXECUTE result, convergence matched
- `python main.py replay`: two deterministic runs matched with no mismatches
- HTTP dashboard: status 200 after local-server launch
- Generated dashboard JavaScript: syntax check passed
- Primary cockpit DOM contract: passed
- In-app rendered screenshot review: unavailable because the Windows host sandbox
  refused the browser process before a tab could open

## Locked confirmations

- No runtime authority, governance, Procedural Truth, threshold, execution,
  Domain, Aurion, audit, replay, token, hash-chain, SKG/DTN, or bridge logic was
  changed.
- SKG and DTN remain external substrates.
- Desktop V1 remains local/private.
- Dual Adaptive Deterministic Pipelines remain preserved.
- No active-node, quorum, mesh, or distributed-runtime topology was introduced.
- Phase 16 was not started.
