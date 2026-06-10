from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Dict

from sbp_lex.audit.pipeline_replay_ledger import PIPELINE_REPLAY_LEDGER
from sbp_lex.runtime.canonical_runtime import CANONICAL_RUNTIME
from sbp_lex.runtime.event_bus import RUNTIME_EVENTS


DESKTOP_BACKGROUND_PATH = (
    Path(__file__).resolve().parent / "static" / "images" / "sbp_lex_background.png"
)
DESKTOP_BACKGROUND_URL = "/desktop/static/images/sbp_lex_background.png"


def desktop_background_bytes() -> bytes:
    return DESKTOP_BACKGROUND_PATH.read_bytes()


def sample_request_payload() -> Dict[str, Any]:
    return {
        "request_id": "desktop-sample",
        "request": {
            "action": "test_action",
            "payload": {
                "classification": {
                    "ap_acf_class": "CLASS_4B",
                    "autonomy_level": 50,
                    "autonomy_ceiling": 75,
                    "operational_scope": "controlled_test",
                    "public_exposure": "controlled",
                },
                "licence_state": "VALID",
            },
            "resolved_authority": "test_authority",
            "jurisdiction": "AU-PACIFIC",
            "context": {
                "evidence": [
                    {"source": "test_source_a", "content": "evidence_a"},
                    {"source": "test_source_b", "content": "evidence_b"},
                    {"source": "test_source_c", "content": "evidence_c"},
                ],
                "financial_amount": 5000,
                "operational_scope": "controlled_test",
                "public_exposure": "controlled",
                "environment": "controlled_test",
                "human_proximity": "low",
                "operational_containment": "bounded",
                "emergency_stop_available": True,
                "licence_state": "VALID",
            },
            "safety_profile": {
                "human_safety": 2,
                "irreversibility": 1,
                "cascading_impact": 1,
                "financial_operational": 1,
            },
        },
    }


def _latest_event(events: list[Dict[str, Any]], event_type: str) -> Dict[str, Any] | None:
    return next(
        (deepcopy(event) for event in reversed(events) if event.get("event_type") == event_type),
        None,
    )


def _timeline_from_audit_trace(last_state: Dict[str, Any]) -> list[Dict[str, Any]]:
    timeline: list[Dict[str, Any]] = []
    for item in last_state.get("audit_trace", []):
        if not isinstance(item, dict):
            continue
        timeline.append(
            {
                "stage": item.get("stage") or "runtime_stage",
                "status": item.get("result")
                or item.get("event")
                or ("PASS" if item.get("audit_complete") is True else None),
                "reason": item.get("reason"),
            }
        )
    return timeline


def latest_runtime_snapshot() -> Dict[str, Any]:
    status = CANONICAL_RUNTIME.status()
    security_mode = status.get("api_security_mode")
    last_state = deepcopy(CANONICAL_RUNTIME.last_result or {})
    convergence = last_state.get("pipeline_convergence", {}) if isinstance(last_state, dict) else {}
    tokens = last_state.get("tokens", {}) if isinstance(last_state, dict) else {}
    events = RUNTIME_EVENTS.latest(500)
    replay_entries = PIPELINE_REPLAY_LEDGER.export()
    latest_traversal = _latest_event(events, "traversal_completed")
    latest_replay = _latest_event(events, "replay_completed")
    traversal_payload = latest_traversal.get("payload", {}) if latest_traversal else {}
    replay_payload = latest_replay.get("payload", {}) if latest_replay else {}
    governance_feedback = last_state.get("governance_feedback", {}) if isinstance(last_state, dict) else {}
    admissibility = governance_feedback.get("admissibility", {}) if isinstance(governance_feedback, dict) else {}
    audit_finalisation = last_state.get("audit_finalisation", {}) if isinstance(last_state, dict) else {}
    integrity_ok = all(
        status.get(field) is True
        for field in (
            "chronology_valid",
            "event_bus_valid",
            "replay_ledger_valid",
            "connector_recovery_valid",
            "persistence_valid",
        )
    )
    return {
        "status": status,
        "operator_summary": {
            "console_name": "SBP-LEX Desktop V1",
            "console_role": "Local Governance Observability Console",
            "runtime_health": "PASS" if integrity_ok else "FAIL",
            "runtime_mode": security_mode,
            "binding_posture": (
                "localhost-only policy"
                if security_mode == "local"
                else "private token policy"
                if security_mode == "private"
                else "security disabled"
                if security_mode == "disabled"
                else None
            ),
            "latest_traversal_id": traversal_payload.get("request_id"),
            "latest_audit_reference": status.get("last_audit_hash"),
        },
        "integrity_summary": {
            "healthy": integrity_ok,
            "status_contract_endpoint": "/runtime/integrity",
            "security_posture": f"{status.get('api_security_mode', 'unknown')} / localhost-first",
            "latest_execution_status": status.get("last_execution_result"),
            "latest_replay_status": replay_payload.get("matched"),
        },
        "last_state_summary": {
            "request_fingerprint": last_state.get("request_fingerprint"),
            "decision": last_state.get("decision"),
            "execution_result": last_state.get("execution_result"),
            "execution_verified": last_state.get("execution_verified"),
            "execution_reason": last_state.get("execution_reason"),
            "pipeline_mode": last_state.get("pipeline_mode"),
            "audit_hash": last_state.get("audit_hash"),
            "state_hash": last_state.get("state_hash"),
            "convergence_matched": convergence.get("matched"),
            "convergence_hash": convergence.get("convergence_hash"),
            "convergence_mismatches": convergence.get("mismatches", []),
            "pipeline_a_summary": convergence.get("pipeline_a"),
            "pipeline_b_summary": convergence.get("pipeline_b"),
            "pipeline_a_timeline": _timeline_from_audit_trace(last_state),
            "admissibility_status": admissibility.get("result"),
            "admissibility_reason": admissibility.get("reason"),
            "admissibility_failures": admissibility.get("failures", []),
            "audit_complete": audit_finalisation.get("audit_complete"),
            "audit_verified": audit_finalisation.get("audit_verified"),
            "token_count": len(tokens),
            "token_failures": last_state.get("token_verification_failures", []),
        },
        "latest_events": events[-25:],
        "latest_event_count": len(events),
        "replay_ledger_size": PIPELINE_REPLAY_LEDGER.size(),
        "latest_replay_summary": {
            "available": latest_replay is not None,
            "matched": replay_payload.get("matched"),
            "replay_hash": replay_payload.get("replay_hash"),
            "mismatch_count": None,
            "ledger_reference": replay_entries[-1].get("ledger_hash") if replay_entries else None,
        },
        "export_availability": {
            "latest_result": True,
            "replay_ledger": True,
            "events": True,
        },
    }


def export_latest_runtime_json() -> Dict[str, Any]:
    return {
        "export_type": "latest_runtime_snapshot",
        **latest_runtime_snapshot(),
    }


def export_replay_ledger_json() -> Dict[str, Any]:
    ok, failures = PIPELINE_REPLAY_LEDGER.verify()
    return {
        "export_type": "replay_ledger",
        "valid": ok,
        "failures": failures,
        "entries": PIPELINE_REPLAY_LEDGER.export(),
    }


def export_traversal_events_json() -> Dict[str, Any]:
    ok, failures = RUNTIME_EVENTS.verify()
    return {
        "export_type": "traversal_events",
        "valid": ok,
        "failures": failures,
        "events": RUNTIME_EVENTS.latest(500),
    }


def desktop_dashboard_html() -> str:
    sample = sample_request_payload()
    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>SBP-LEX V1 Desktop Runtime Dashboard</title>
  <style>
    :root {{
      color-scheme: dark;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      --sbp-white: #ffffff;
      --sbp-muted: #c8d5e6;
      --sbp-panel: rgba(4, 10, 24, .78);
      --sbp-panel-strong: rgba(2, 7, 18, .9);
      --sbp-line: rgba(137, 180, 255, .26);
      --status-pass: #19d98b;
      --status-pass-fill: rgba(16, 185, 129, .2);
      --status-escalate: #ff9f1c;
      --status-escalate-fill: rgba(249, 115, 22, .22);
      --status-deny: #ff3b30;
      --status-deny-fill: rgba(220, 38, 38, .24);
      --status-fail: #ff3b30;
      --status-fail-fill: rgba(220, 38, 38, .24);
      --status-active: #22d3ee;
      --status-active-fill: rgba(6, 182, 212, .2);
      --status-idle: #718096;
      --status-idle-fill: rgba(71, 85, 105, .28);
    }}
    * {{ box-sizing: border-box; }}
    html {{
      min-height: 100%;
      background: #020611 url('{DESKTOP_BACKGROUND_URL}') center center / cover fixed no-repeat;
    }}
    body {{
      min-height: 100vh;
      margin: 0;
      color: var(--sbp-white);
      font-weight: 700;
      background:
        linear-gradient(180deg, rgba(1, 5, 14, .78), rgba(2, 8, 22, .9)),
        radial-gradient(circle at 50% 20%, rgba(17, 67, 145, .18), transparent 52%);
    }}
    .desktop-shell {{ min-height: 100vh; padding: 24px; overflow-x: hidden; }}
    .content {{ width: min(1480px, 100%); margin: 0 auto; }}
    .hero {{
      margin-bottom: 18px;
      padding: 20px 22px;
      border: 1px solid rgba(81, 146, 255, .4);
      border-radius: 16px;
      background: linear-gradient(135deg, rgba(3, 11, 30, .9), rgba(7, 25, 58, .68));
      box-shadow: 0 20px 60px rgba(0, 0, 0, .42), inset 0 1px rgba(255,255,255,.05);
      backdrop-filter: blur(14px);
    }}
    h1 {{ margin: 0 0 7px; font-size: clamp(24px, 3vw, 38px); letter-spacing: .03em; }}
    h2 {{ margin: 0 0 12px; font-size: 17px; letter-spacing: .04em; text-transform: uppercase; }}
    p {{ margin: 0; color: var(--sbp-muted); line-height: 1.55; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 14px; }}
    .grid + .grid, .card + .card {{ margin-top: 14px; }}
    .card {{
      min-width: 0;
      padding: 16px;
      border: 1px solid var(--sbp-line);
      border-radius: 14px;
      background: linear-gradient(145deg, rgba(4, 13, 32, .86), rgba(2, 8, 20, .72));
      box-shadow: 0 18px 44px rgba(0, 0, 0, .38), inset 0 1px rgba(255,255,255,.04);
      backdrop-filter: blur(14px);
    }}
    .metric {{
      display: grid;
      grid-template-columns: minmax(120px, .8fr) minmax(0, 1.2fr);
      align-items: start;
      gap: 12px;
      padding: 8px 0;
      border-bottom: 1px solid rgba(142, 174, 220, .14);
    }}
    .metric:last-child {{ border-bottom: 0; }}
    .label {{ color: var(--sbp-muted); }}
    .value {{
      color: var(--sbp-white);
      font-family: "Cascadia Mono", "SFMono-Regular", Consolas, monospace;
      text-align: right;
      overflow-wrap: anywhere;
    }}
    .reason-outcome {{
      margin: 10px 0;
      padding: 12px;
      border-radius: 12px;
      background: rgba(0, 0, 0, .34);
      border: 1px solid rgba(255,255,255,.1);
    }}
    .reason {{ margin-bottom: 9px; color: var(--sbp-white); font-weight: 800; line-height: 1.45; }}
    .status-badge {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 92px;
      padding: 7px 12px;
      border: 1px solid;
      border-radius: 999px;
      color: var(--sbp-white);
      font-weight: 900;
      letter-spacing: .08em;
      text-transform: uppercase;
    }}
    .status-pass {{ background: var(--status-pass-fill); border-color: var(--status-pass); box-shadow: 0 0 18px rgba(25,217,139,.22); }}
    .status-escalate {{ background: var(--status-escalate-fill); border-color: var(--status-escalate); box-shadow: 0 0 18px rgba(255,159,28,.24); }}
    .status-deny, .status-fail {{ background: var(--status-deny-fill); border-color: var(--status-deny); box-shadow: 0 0 18px rgba(255,59,48,.24); }}
    .status-active {{ background: var(--status-active-fill); border-color: var(--status-active); box-shadow: 0 0 18px rgba(34,211,238,.22); }}
    .status-idle {{ background: var(--status-idle-fill); border-color: var(--status-idle); box-shadow: none; }}
    .event-row {{
      margin-bottom: 10px;
      padding: 12px;
      border: 1px solid rgba(112, 167, 255, .2);
      border-radius: 10px;
      background: rgba(2, 8, 20, .66);
    }}
    .event-meta {{ margin-bottom: 8px; color: var(--sbp-muted); font-family: "Cascadia Mono", Consolas, monospace; font-size: 12px; }}
    button {{
      padding: 9px 12px;
      margin: 8px 5px 0 0;
      border: 1px solid #39c8ff;
      border-radius: 8px;
      color: var(--sbp-white);
      background: rgba(0, 122, 204, .34);
      box-shadow: 0 0 16px rgba(34, 211, 238, .14);
      font-weight: 800;
      cursor: pointer;
    }}
    button:hover {{ background: rgba(0, 152, 220, .5); }}
    button.secondary {{ border-color: rgba(255,255,255,.34); background: rgba(15, 23, 42, .62); }}
    textarea, pre {{
      width: 100%;
      color: #f8fbff;
      border: 1px solid rgba(116, 166, 238, .3);
      border-radius: 10px;
      background: var(--sbp-panel-strong);
      font-family: "Cascadia Mono", "SFMono-Regular", Consolas, monospace;
      font-weight: 650;
      line-height: 1.5;
    }}
    textarea {{ min-height: 280px; padding: 12px; resize: vertical; }}
    pre {{ max-height: 420px; margin: 0; padding: 12px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; }}
    .notice {{ margin-bottom: 10px; }}
    .eyebrow {{
      margin-bottom: 8px;
      color: #7dd3fc;
      font-size: 12px;
      font-weight: 900;
      letter-spacing: .16em;
      text-transform: uppercase;
    }}
    .hero-layout {{
      display: grid;
      grid-template-columns: minmax(0, 1.25fr) minmax(320px, .75fr);
      gap: 20px;
      align-items: start;
    }}
    .hero-subtitle {{ margin-top: 7px; color: var(--sbp-white); font-size: 18px; }}
    .hero-description {{ max-width: 780px; margin-top: 10px; }}
    .landing-status {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px;
    }}
    .landing-item {{
      min-width: 0;
      padding: 10px;
      border: 1px solid rgba(137,180,255,.2);
      border-radius: 10px;
      background: rgba(0,0,0,.24);
    }}
    .landing-item .label {{
      display: block;
      margin-bottom: 5px;
      font-size: 11px;
      letter-spacing: .08em;
      text-transform: uppercase;
    }}
    .landing-item .value {{ display: block; text-align: left; }}
    .section-heading {{
      display: flex;
      align-items: end;
      justify-content: space-between;
      gap: 14px;
      margin: 22px 0 10px;
      padding: 0 3px;
    }}
    .section-heading h2 {{ margin: 0; font-size: 14px; color: #dcecff; }}
    .section-heading p {{ font-size: 12px; text-align: right; }}
    .grid-wide {{ grid-template-columns: repeat(12, minmax(0, 1fr)); }}
    .span-4 {{ grid-column: span 4; }}
    .span-5 {{ grid-column: span 5; }}
    .span-6 {{ grid-column: span 6; }}
    .span-7 {{ grid-column: span 7; }}
    .span-8 {{ grid-column: span 8; }}
    .panel-kicker {{
      margin-bottom: 8px;
      color: #7dd3fc;
      font-size: 11px;
      letter-spacing: .12em;
      text-transform: uppercase;
    }}
    .panel-note {{ margin: -5px 0 10px; font-size: 12px; }}
    .timeline {{
      position: relative;
      display: grid;
      gap: 8px;
      margin-top: 12px;
    }}
    .timeline-row {{
      position: relative;
      display: grid;
      grid-template-columns: minmax(120px, .75fr) minmax(0, 1.25fr) auto;
      gap: 10px;
      align-items: center;
      padding: 10px;
      border: 1px solid rgba(112,167,255,.18);
      border-radius: 10px;
      background: rgba(2,8,20,.58);
    }}
    .timeline-stage {{ color: var(--sbp-white); font-size: 12px; letter-spacing: .04em; text-transform: uppercase; }}
    .timeline-reason {{ color: var(--sbp-muted); font-size: 12px; overflow-wrap: anywhere; }}
    .timeline-empty {{
      padding: 12px;
      border: 1px dashed rgba(137,180,255,.28);
      border-radius: 10px;
      color: var(--sbp-muted);
    }}
    .action-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 8px; }}
    .action-grid button {{ width: 100%; min-height: 48px; margin: 0; text-align: left; }}
    .action-description {{ display: block; margin-top: 4px; color: var(--sbp-muted); font-size: 11px; font-weight: 700; }}
    details {{ margin-top: 12px; }}
    summary {{ cursor: pointer; color: var(--sbp-muted); }}
    .compact-json {{ max-height: 300px; margin-top: 10px; font-size: 12px; }}
    @media (max-width: 720px) {{
      .desktop-shell {{ padding: 12px; }}
      .metric {{ grid-template-columns: 1fr; gap: 5px; }}
      .value {{ text-align: left; }}
      .hero-layout {{ grid-template-columns: 1fr; }}
      .landing-status {{ grid-template-columns: 1fr; }}
      .grid-wide {{ grid-template-columns: 1fr; }}
      .span-4, .span-5, .span-6, .span-7, .span-8 {{ grid-column: auto; }}
      .section-heading {{ align-items: start; flex-direction: column; }}
      .section-heading p {{ text-align: left; }}
      .timeline-row {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <div class=\"desktop-shell\">
    <main class=\"content\">
      <header class=\"hero\">
        <div class=\"hero-layout\">
          <div>
            <div class=\"eyebrow\">Institutional Operator Surface · Desktop V1</div>
            <h1>SBP-LEX Desktop V1</h1>
            <p class=\"hero-subtitle\">Local Governance Observability Console</p>
            <p class=\"hero-description\">Private, runtime-connected oversight of canonical traversal, Dual Adaptive Deterministic Pipelines, convergence, execution admissibility, audit continuity, and deterministic replay.</p>
          </div>
          <div id=\"landingStatus\" class=\"landing-status\"></div>
        </div>
      </header>

      <div id=\"notice\" class=\"notice\"></div>

      <div class=\"section-heading\">
        <h2>Runtime Assurance</h2>
        <p>Read-only integrity and execution posture from the canonical runtime</p>
      </div>
      <div class=\"grid grid-wide\">
        <section class=\"card span-7\">
          <div class=\"panel-kicker\">Runtime Integrity Summary</div>
          <h2>Canonical Runtime Assurance</h2>
          <div id=\"integrity\"></div>
        </section>
        <section class=\"card span-5\">
          <div class=\"panel-kicker\">Execution Boundary</div>
          <h2>Execution Admissibility</h2>
          <div id=\"admissibility\"></div>
        </section>
      </div>

      <div class=\"section-heading\">
        <h2>Pipeline / Convergence</h2>
        <p>Dual Adaptive Deterministic Pipelines · Pipeline A / Pipeline B</p>
      </div>
      <div class=\"grid grid-wide\">
        <section class=\"card span-8\">
          <div class=\"panel-kicker\">Traversal Timeline</div>
          <h2>Pipeline A / Pipeline B Progression</h2>
          <p class=\"panel-note\">Only runtime-retained stages and reasons are displayed.</p>
          <div id=\"pipelineTimeline\"></div>
        </section>
        <section class=\"card span-4\">
          <div class=\"panel-kicker\">Deterministic Parity</div>
          <h2>Convergence Proof</h2>
          <div id=\"convergenceProof\"></div>
        </section>
      </div>

      <div class=\"section-heading\">
        <h2>Continuity & Replay</h2>
        <p>Controlled runtime record, trace continuity, and replay-verifiable evidence</p>
      </div>
      <div class=\"grid grid-wide\">
        <section class=\"card span-6\">
          <div class=\"panel-kicker\">Controlled Runtime Record</div>
          <h2>Audit Continuity</h2>
          <div id=\"auditContinuity\"></div>
        </section>
        <section class=\"card span-6\">
          <div class=\"panel-kicker\">Deterministic Comparison</div>
          <h2>Replay Comparison</h2>
          <div id=\"replayComparison\"></div>
        </section>
      </div>

      <div class=\"section-heading\">
        <h2>Controlled Operator Actions</h2>
        <p>Existing safe dashboard operations only · no execution authority</p>
      </div>
      <section class=\"card\">
        <div class=\"action-grid\">
          <button onclick=\"runApprovedDemo()\">Run Approved Demo Traversal<span class=\"action-description\">Uses the fixed existing Desktop V1 sample request</span></button>
          <button onclick=\"runReplay()\">Run Demo Replay<span class=\"action-description\">Executes the existing two-run deterministic comparison</span></button>
          <button class=\"secondary\" onclick=\"refreshAll()\">Refresh Console<span class=\"action-description\">Reload current runtime observability</span></button>
          <button class=\"secondary\" onclick=\"downloadJson('/desktop/export/latest','latest_runtime_snapshot.json')\">Export Latest Result<span class=\"action-description\">Controlled runtime snapshot JSON</span></button>
          <button class=\"secondary\" onclick=\"downloadJson('/desktop/export/replay-ledger','replay_ledger.json')\">Export Replay Ledger<span class=\"action-description\">Replay-verifiable ledger JSON</span></button>
          <button class=\"secondary\" onclick=\"downloadJson('/desktop/export/events','traversal_events.json')\">Export Events<span class=\"action-description\">Trace continuity event JSON</span></button>
          <button class=\"secondary\" onclick=\"openEndpoint('/health')\">Open Runtime Health<span class=\"action-description\">Existing local health endpoint</span></button>
          <button class=\"secondary\" onclick=\"openEndpoint('/runtime/integrity')\">Open Runtime Integrity<span class=\"action-description\">Existing local integrity endpoint</span></button>
        </div>
        <details>
          <summary>Approved demo request definition</summary>
          <pre class=\"compact-json\">{__import__('json').dumps(sample, indent=2)}</pre>
        </details>
      </section>

      <div class=\"section-heading\">
        <h2>Trace Observability</h2>
        <p>Latest runtime events and operator action response</p>
      </div>
      <div class=\"grid grid-wide\">
        <section class=\"card span-6\">
          <h2>Traversal Events</h2>
          <div id=\"events\"></div>
        </section>
        <section class=\"card span-6\">
          <h2>Latest Operator Action Response</h2>
          <div id=\"responseStatus\"></div>
          <pre id=\"response\">{{}}</pre>
        </section>
      </div>
    </main>
  </div>

<script>
const STATUS_CLASS = Object.freeze({{
  PASS: 'status-pass',
  ALLOW: 'status-pass',
  EXECUTE: 'status-pass',
  MATCHED: 'status-pass',
  VALID: 'status-pass',
  TRUE: 'status-pass',
  ESCALATE: 'status-escalate',
  DENY: 'status-deny',
  REJECTED: 'status-deny',
  FAIL: 'status-fail',
  HALT: 'status-fail',
  FALSE: 'status-fail',
  ACTIVE: 'status-active',
  IN_PROGRESS: 'status-active',
  IDLE: 'status-idle',
  INACTIVE: 'status-idle',
  UNKNOWN: 'status-idle'
}});
const APPROVED_DEMO = {__import__('json').dumps(sample)};

function escapeHtml(value) {{
  return String(value ?? '')
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('\"', '&quot;').replaceAll(\"'\", '&#039;');
}}

function normalizeOutcome(value) {{
  if (value === true) return 'PASS';
  if (value === false) return 'FAIL';
  const normalized = String(value ?? 'IDLE').trim().toUpperCase().replaceAll(' ', '_');
  return normalized || 'IDLE';
}}

function statusBadge(outcome) {{
  const normalized = normalizeOutcome(outcome);
  const cls = STATUS_CLASS[normalized] || 'status-idle';
  return `<span class=\"status-badge ${{cls}}\">${{escapeHtml(normalized.replaceAll('_', ' '))}}</span>`;
}}

function reasonOutcome(reason, outcome) {{
  return `<div class=\"reason-outcome\"><div class=\"reason\">Reason: ${{escapeHtml(reason || 'No runtime result available')}}</div>${{statusBadge(outcome)}}</div>`;
}}

function metric(label, value) {{
  const display = value === null || value === undefined || value === '' ? 'Not available' : value;
  return `<div class=\"metric\"><span class=\"label\">${{escapeHtml(label)}}</span><span class=\"value\">${{escapeHtml(display)}}</span></div>`;
}}

function landingItem(label, value) {{
  const display = value === null || value === undefined || value === '' ? 'Not available' : value;
  return `<div class=\"landing-item\"><span class=\"label\">${{escapeHtml(label)}}</span><span class=\"value\">${{escapeHtml(display)}}</span></div>`;
}}

function stageOutcome(value) {{
  const normalized = normalizeOutcome(value);
  if (STATUS_CLASS[normalized]) return normalized;
  if (normalized.includes('REJECT') || normalized.includes('DENY')) return 'DENY';
  if (normalized.includes('FAIL') || normalized.includes('INVALID')) return 'FAIL';
  if (normalized.includes('ALLOW') || normalized.includes('PASS') || normalized.includes('COMPLETE')) return 'PASS';
  return 'IDLE';
}}

function renderTimelineRows(items) {{
  if (!items || !items.length) return '<div class=\"timeline-empty\">No retained stage timeline is available.</div>';
  return `<div class=\"timeline\">${{items.map(item => {{
    const status = stageOutcome(item.status);
    return `<div class=\"timeline-row\">
      <div class=\"timeline-stage\">${{escapeHtml(item.stage || 'runtime_stage')}}</div>
      <div class=\"timeline-reason\">${{escapeHtml(item.reason || 'No stage reason retained')}}</div>
      ${{statusBadge(status)}}
    </div>`;
  }}).join('')}}</div>`;
}}

function renderPipelineB(summary) {{
  if (!summary) return '<div class=\"timeline-empty\">Pipeline B stage detail: Not available. V1 retains the final deterministic validator summary only when Pipeline B executes.</div>';
  return renderTimelineRows([
    {{stage: 'governance', status: summary.governance_result, reason: 'Retained Pipeline B governance result'}},
    {{stage: 'domain', status: summary.domain_result, reason: 'Retained Pipeline B domain result'}},
    {{stage: 'aurion runtime', status: summary.aurion15_result, reason: 'Retained Pipeline B runtime result'}},
    {{stage: 'execution gate', status: summary.execution_result, reason: 'Retained Pipeline B execution result'}},
    {{stage: 'final decision', status: summary.decision, reason: 'Retained Pipeline B final decision'}}
  ]);
}}

function outcomeReason(outcome, fallback) {{
  const value = normalizeOutcome(outcome);
  const reasons = {{
    PASS: 'Runtime verification completed successfully',
    ALLOW: 'Execution admissibility verified',
    EXECUTE: 'Canonical execution gate permitted execution',
    MATCHED: 'Pipeline A and Pipeline B parity matched',
    ESCALATE: 'Additional governance review required',
    DENY: 'Runtime policy denied the requested outcome',
    FAIL: 'Runtime verification did not pass',
    HALT: 'Fail-closed execution halt applied',
    ACTIVE: 'Runtime activity is in progress',
    IDLE: 'No completed runtime outcome is available'
  }};
  return reasons[value] || fallback || `Runtime reported ${{value.replaceAll('_', ' ')}}`;
}}

function inferEventOutcome(event) {{
  const payload = event.payload || {{}};
  return payload.outcome || payload.decision || payload.result || payload.status ||
    (String(event.event_type || '').includes('rejected') ? 'DENY' : 'ACTIVE');
}}

function renderEvents(events) {{
  if (!events.length) return reasonOutcome('No traversal events have been recorded', 'IDLE');
  return events.slice().reverse().map(event => {{
    const outcome = inferEventOutcome(event);
    const payload = event.payload || {{}};
    const reason = payload.reason || payload.error || outcomeReason(outcome, event.event_type);
    return `<div class=\"event-row\">
      <div class=\"event-meta\">${{escapeHtml(event.timestamp || '')}} · ${{escapeHtml(event.event_type || 'runtime_event')}}</div>
      ${{reasonOutcome(reason, outcome)}}
      <div class=\"value\">${{escapeHtml(JSON.stringify(payload))}}</div>
    </div>`;
  }}).join('');
}}

async function getJson(path) {{
  const res = await fetch(path, {{cache:'no-store'}});
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `${{res.status}} ${{res.statusText}}`);
  return data;
}}

async function postJson(path, payload) {{
  const res = await fetch(path, {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify(payload)}});
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `${{res.status}} ${{res.statusText}}`);
  return data;
}}

function renderSnapshot(data, integrityData) {{
  const status = data.status || {{}};
  const operator = data.operator_summary || {{}};
  const integrity = data.integrity_summary || {{}};
  const last = data.last_state_summary || {{}};
  const replay = data.latest_replay_summary || {{}};
  const exports = data.export_availability || {{}};
  const endpointIntegrity = integrityData || {{}};
  const environment = endpointIntegrity.environment_security || {{}};

  document.getElementById('landingStatus').innerHTML =
    landingItem('Runtime Mode', operator.runtime_mode) +
    landingItem('Local / Private Posture', operator.binding_posture) +
    landingItem('Runtime Health', operator.runtime_health) +
    landingItem('Decision State', last.decision) +
    landingItem('Pipeline Mode', last.pipeline_mode) +
    landingItem('Latest Traversal ID', operator.latest_traversal_id) +
    landingItem('Latest Audit Reference', operator.latest_audit_reference);

  document.getElementById('integrity').innerHTML =
    reasonOutcome(integrity.healthy ?
      'Chronology, event bus, replay ledger, connector recovery, and persistence integrity verified' :
      'One or more canonical runtime integrity checks require attention',
      integrity.healthy ? 'PASS' : 'FAIL') +
    metric('Runtime', status.runtime_id) +
    metric('Security Mode', status.api_security_mode) +
    metric('Binding Policy', operator.binding_posture) +
    metric('Integrity Endpoint Contract', endpointIntegrity.status_contract_valid) +
    metric('Environment Security Valid', environment.valid) +
    metric('Security Posture', integrity.security_posture) +
    metric('Latest Execution Status', integrity.latest_execution_status) +
    metric('Latest Replay Status', integrity.latest_replay_status) +
    metric('Traversals', status.traversal_count) +
    metric('Chronology', status.chronology_valid) +
    metric('Event Bus', status.event_bus_valid) +
    metric('Replay Ledger', status.replay_ledger_valid) +
    metric('Connector Recovery', status.connector_recovery_valid) +
    metric('Persistence', status.persistence_valid);

  document.getElementById('pipelineTimeline').innerHTML =
    `<div class=\"panel-kicker\">Pipeline A · Canonical retained stage trace</div>` +
    renderTimelineRows(last.pipeline_a_timeline) +
    `<div class=\"panel-kicker\" style=\"margin-top:16px\">Pipeline B · Deterministic validator summary</div>` +
    renderPipelineB(last.pipeline_b_summary);

  document.getElementById('convergenceProof').innerHTML =
    reasonOutcome(last.convergence_matched === true ? 'Pipeline A and Pipeline B convergence matched' :
      last.convergence_matched === false ? 'Parity mismatch detected' : 'No latest traversal loaded',
      last.convergence_matched === true ? 'PASS' : last.convergence_matched === false ? 'DENY' : 'IDLE') +
    metric('Pipeline Mode', last.pipeline_mode) +
    metric('Convergence Matched', last.convergence_matched) +
    metric('Convergence Hash', last.convergence_hash) +
    metric('Parity Mismatches', JSON.stringify(last.convergence_mismatches || [])) +
    metric('Replay Comparison Status', replay.matched);

  const admissibilityReason = last.admissibility_reason || last.execution_reason || outcomeReason(last.decision);
  document.getElementById('admissibility').innerHTML =
    reasonOutcome(admissibilityReason, last.decision || 'IDLE') +
    metric('Final Decision', last.decision) +
    metric('Execution Result', last.execution_result) +
    metric('Execution Gate Verified', last.execution_verified) +
    metric('Admissibility Status', last.admissibility_status) +
    metric('Admissibility Failures', JSON.stringify(last.admissibility_failures || [])) +
    metric('Token Count', last.token_count) +
    metric('Token Failures', JSON.stringify(last.token_failures || []));

  document.getElementById('auditContinuity').innerHTML =
    reasonOutcome(last.audit_complete ?
      'Audit continuity established with a replay-verifiable controlled runtime record' :
      'No finalised controlled runtime record is available',
      last.audit_complete ? 'PASS' : 'IDLE') +
    metric('Audit Written', last.audit_complete) +
    metric('Audit Verified', last.audit_verified) +
    metric('Audit Reference', last.audit_hash) +
    metric('Audit Hash', last.audit_hash) +
    metric('Request Fingerprint', last.request_fingerprint) +
    metric('Replay Ledger Availability', exports.replay_ledger) +
    metric('Event Export Availability', exports.events) +
    metric('Latest Event Count', data.latest_event_count);

  document.getElementById('replayComparison').innerHTML =
    reasonOutcome(replay.available ?
      replay.matched === true ? 'Latest deterministic replay comparison matched' :
      replay.matched === false ? 'Latest deterministic replay comparison mismatched' :
      'Latest replay status is not available' :
      'No replay comparison has been recorded',
      replay.matched === true ? 'PASS' : replay.matched === false ? 'DENY' : 'IDLE') +
    metric('Replay Status', replay.available ? 'Recorded' : 'Not available') +
    metric('Replay Matched', replay.matched) +
    metric('Mismatch Count', replay.mismatch_count) +
    metric('Replay Hash', replay.replay_hash) +
    metric('Latest Replay Ledger Reference', replay.ledger_reference) +
    metric('Replay Ledger Size', data.replay_ledger_size);
}}

async function refreshAll() {{
  try {{
    const [data, integrityData, events] = await Promise.all([
      getJson('/desktop/latest'),
      getJson('/runtime/integrity'),
      getJson('/runtime/events?after=0')
    ]);
    renderSnapshot(data, integrityData);
    document.getElementById('events').innerHTML = renderEvents(events.events || []);
    document.getElementById('notice').innerHTML = '';
  }} catch (error) {{
    document.getElementById('notice').innerHTML = reasonOutcome(error.message, 'FAIL');
  }}
}}

async function runApprovedDemo() {{
  try {{
    document.getElementById('responseStatus').innerHTML =
      reasonOutcome('Approved Desktop V1 demo traversal is in progress', 'ACTIVE');
    const result = await postJson('/runtime/traverse', APPROVED_DEMO);
    const state = result.state || {{}};
    document.getElementById('responseStatus').innerHTML =
      reasonOutcome(outcomeReason(state.decision), state.decision || 'ACTIVE');
    document.getElementById('response').textContent = JSON.stringify(result, null, 2);
    await refreshAll();
  }} catch (error) {{
    document.getElementById('responseStatus').innerHTML = reasonOutcome(error.message, 'FAIL');
  }}
}}

async function runReplay() {{
  try {{
    const payload = JSON.parse(JSON.stringify(APPROVED_DEMO));
    payload.replay_count = 2;
    document.getElementById('responseStatus').innerHTML =
      reasonOutcome('Deterministic demo replay comparison is in progress', 'ACTIVE');
    const result = await postJson('/runtime/replay', payload);
    document.getElementById('responseStatus').innerHTML =
      reasonOutcome(result.matched ? 'Replay checkpoints matched deterministically' : 'Replay checkpoint mismatch',
        result.matched ? 'PASS' : 'DENY');
    document.getElementById('response').textContent = JSON.stringify(result, null, 2);
    await refreshAll();
  }} catch (error) {{
    document.getElementById('responseStatus').innerHTML = reasonOutcome(error.message, 'FAIL');
  }}
}}

function openEndpoint(path) {{
  window.open(path, '_blank', 'noopener,noreferrer');
}}

async function downloadJson(path, filename) {{
  try {{
    const data = await getJson(path);
    const blob = new Blob([JSON.stringify(data, null, 2)], {{type:'application/json'}});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click(); URL.revokeObjectURL(url);
    document.getElementById('notice').innerHTML = reasonOutcome(`${{filename}} prepared for export`, 'PASS');
  }} catch (error) {{
    document.getElementById('notice').innerHTML = reasonOutcome(error.message, 'FAIL');
  }}
}}

refreshAll();
setInterval(refreshAll, 3000);
</script>
</body>
</html>"""
