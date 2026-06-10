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


def latest_runtime_snapshot() -> Dict[str, Any]:
    status = CANONICAL_RUNTIME.status()
    last_state = deepcopy(CANONICAL_RUNTIME.last_result or {})
    convergence = last_state.get("pipeline_convergence", {}) if isinstance(last_state, dict) else {}
    tokens = last_state.get("tokens", {}) if isinstance(last_state, dict) else {}
    return {
        "status": status,
        "last_state_summary": {
            "request_fingerprint": last_state.get("request_fingerprint"),
            "decision": last_state.get("decision"),
            "execution_result": last_state.get("execution_result"),
            "pipeline_mode": last_state.get("pipeline_mode"),
            "pipeline_count": 2 if convergence.get("pipeline_b") is not None else 1 if last_state else 0,
            "audit_hash": last_state.get("audit_hash"),
            "state_hash": last_state.get("state_hash"),
            "convergence_matched": convergence.get("matched"),
            "convergence_hash": convergence.get("convergence_hash"),
            "token_count": len(tokens),
            "token_failures": last_state.get("token_verification_failures", []),
        },
        "latest_events": RUNTIME_EVENTS.latest(25),
        "replay_ledger_size": PIPELINE_REPLAY_LEDGER.size(),
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
    .pipeline-visual-dock {{
      width: min(560px, calc(100% - 24px));
      margin: 0 0 18px min(2.5cm, 6vw);
      padding: 14px 16px 16px;
      border: 1px solid rgba(83, 171, 255, .34);
      border-radius: 16px;
      background: linear-gradient(145deg, rgba(3, 12, 31, .72), rgba(2, 8, 20, .48));
      box-shadow: 0 18px 48px rgba(0, 0, 0, .34), inset 0 1px rgba(255, 255, 255, .05);
      backdrop-filter: blur(10px);
      pointer-events: none;
    }}
    .pipeline-visual-heading {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 10px;
      color: var(--sbp-white);
      font-size: 12px;
      font-weight: 900;
      letter-spacing: .13em;
      text-transform: uppercase;
    }}
    .pipeline-visual-reason {{
      margin-bottom: 10px;
      color: var(--sbp-white);
      font-size: 13px;
      font-weight: 800;
      line-height: 1.4;
    }}
    .pipeline-visual-outcome {{ margin-bottom: 12px; }}
    .pipeline-lanes {{ display: grid; gap: 10px; }}
    .pipeline-lane {{
      display: grid;
      grid-template-columns: 82px minmax(0, 1fr);
      align-items: center;
      gap: 12px;
    }}
    .pipeline-lane-label {{
      color: var(--sbp-white);
      font-size: 12px;
      font-weight: 900;
      letter-spacing: .08em;
      text-transform: uppercase;
    }}
    .pipeline-cylinder {{
      position: relative;
      height: 34px;
      overflow: hidden;
      border: 1px solid rgba(113, 128, 150, .72);
      border-radius: 50% / 42%;
      background:
        linear-gradient(180deg, rgba(255,255,255,.08), transparent 38%, rgba(0,0,0,.24)),
        linear-gradient(90deg, rgba(71,85,105,.16), rgba(71,85,105,.44), rgba(71,85,105,.16));
      box-shadow: inset 0 0 18px rgba(113,128,150,.2), 0 0 12px rgba(71,85,105,.18);
    }}
    .pipeline-cylinder::before,
    .pipeline-cylinder::after {{
      content: "";
      position: absolute;
      top: 2px;
      bottom: 2px;
      width: 18px;
      border: 1px solid currentColor;
      border-radius: 50%;
      opacity: .72;
    }}
    .pipeline-cylinder::before {{ left: 2px; }}
    .pipeline-cylinder::after {{ right: 2px; }}
    .pipeline-pulse {{
      position: absolute;
      top: 3px;
      bottom: 3px;
      left: -34%;
      width: 32%;
      border-radius: 50%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,.78), transparent);
      opacity: 0;
    }}
    .pipeline-lane.reverse .pipeline-pulse {{ left: auto; right: -34%; }}
    .pipeline-state-active .pipeline-cylinder {{
      color: var(--status-active);
      border-color: rgba(34,211,238,.92);
      background:
        linear-gradient(180deg, rgba(255,255,255,.22), transparent 42%, rgba(0,36,58,.3)),
        linear-gradient(90deg, rgba(6,182,212,.12), rgba(34,211,238,.58), rgba(6,182,212,.12));
      box-shadow: inset 0 0 22px rgba(34,211,238,.48), 0 0 21px rgba(34,211,238,.52);
      animation: cylinder-strobe 1.1s ease-in-out infinite alternate;
    }}
    .pipeline-state-active .pipeline-pulse {{
      opacity: .88;
      animation: pipeline-flow 1.35s linear infinite;
    }}
    .pipeline-state-active .pipeline-lane.reverse .pipeline-pulse {{
      animation-name: pipeline-flow-reverse;
    }}
    .pipeline-state-pass .pipeline-cylinder {{
      color: var(--status-pass);
      border-color: rgba(25,217,139,.9);
      background:
        linear-gradient(180deg, rgba(255,255,255,.2), transparent 42%, rgba(0,45,32,.28)),
        linear-gradient(100deg, rgba(16,185,129,.14), rgba(25,217,139,.58), rgba(45,212,191,.24));
      box-shadow: inset 0 0 22px rgba(25,217,139,.38), 0 0 20px rgba(25,217,139,.4);
    }}
    .pipeline-state-escalate .pipeline-cylinder {{
      color: var(--status-escalate);
      border-color: rgba(255,159,28,.94);
      background:
        linear-gradient(180deg, rgba(255,255,255,.18), transparent 42%, rgba(67,28,0,.28)),
        linear-gradient(90deg, rgba(249,115,22,.12), rgba(255,159,28,.62), rgba(249,115,22,.12));
      box-shadow: inset 0 0 22px rgba(255,159,28,.4), 0 0 21px rgba(255,159,28,.46);
      animation: warning-pulse 1.8s ease-in-out infinite;
    }}
    .pipeline-state-deny .pipeline-cylinder,
    .pipeline-state-fail .pipeline-cylinder {{
      color: var(--status-deny);
      border-color: rgba(255,59,48,.96);
      background:
        linear-gradient(180deg, rgba(255,255,255,.18), transparent 42%, rgba(66,0,0,.3)),
        linear-gradient(90deg, rgba(220,38,38,.16), rgba(255,59,48,.62), rgba(220,38,38,.16));
      box-shadow: inset 0 0 22px rgba(255,59,48,.44), 0 0 22px rgba(255,59,48,.5);
    }}
    @keyframes pipeline-flow {{
      from {{ transform: translateX(0); }}
      to {{ transform: translateX(440%); }}
    }}
    @keyframes pipeline-flow-reverse {{
      from {{ transform: translateX(0); }}
      to {{ transform: translateX(-440%); }}
    }}
    @keyframes cylinder-strobe {{
      from {{ filter: brightness(.86); }}
      to {{ filter: brightness(1.22); }}
    }}
    @keyframes warning-pulse {{
      0%, 100% {{ filter: brightness(.9); }}
      50% {{ filter: brightness(1.18); }}
    }}
    @media (prefers-reduced-motion: reduce) {{
      .pipeline-cylinder, .pipeline-pulse {{ animation: none !important; }}
    }}
    @media (max-width: 720px) {{
      .desktop-shell {{ padding: 12px; }}
      .metric {{ grid-template-columns: 1fr; gap: 5px; }}
      .value {{ text-align: left; }}
      .pipeline-visual-dock {{ width: 100%; margin-left: 0; }}
      .pipeline-lane {{ grid-template-columns: 70px minmax(0, 1fr); gap: 8px; }}
    }}
  </style>
</head>
<body>
  <div class=\"desktop-shell\">
    <main class=\"content\">
      <header class=\"hero\">
        <h1>SBP-LEX V1 Desktop Runtime Dashboard</h1>
        <p>Local operator interface for canonical runtime, dual adaptive deterministic pipelines, parity/convergence, execution decision, audit, replay, and observability.</p>
      </header>

      <div id=\"notice\" class=\"notice\"></div>
      <aside id=\"pipelineVisual\" class=\"pipeline-visual-dock\" aria-live=\"polite\"></aside>
      <div class=\"grid\">
        <section class=\"card\">
          <h2>Runtime Health</h2>
          <div id=\"health\"></div>
          <button onclick=\"refreshAll()\">Refresh</button>
        </section>

        <section class=\"card\">
          <h2>Pipeline / Convergence</h2>
          <p class="section-kicker">Pipeline A / Pipeline B deterministic parity</p>
          <div id=\"pipeline\"></div>
        </section>

        <section class=\"card\">
          <h2>Execution Decision</h2>
          <div id=\"decision\"></div>
        </section>

        <section class=\"card\">
          <h2>Audit / Replay</h2>
          <div id=\"audit\"></div>
          <button class=\"secondary\" onclick=\"downloadJson('/desktop/export/latest','latest_runtime_snapshot.json')\">Export Latest JSON</button>
          <button class=\"secondary\" onclick=\"downloadJson('/desktop/export/replay-ledger','replay_ledger.json')\">Export Replay Ledger</button>
          <button class=\"secondary\" onclick=\"downloadJson('/desktop/export/events','traversal_events.json')\">Export Events</button>
        </section>
      </div>

      <div class=\"grid\">
        <section class=\"card\">
          <h2>Controlled Test Request</h2>
          <textarea id=\"requestBox\">{__import__('json').dumps(sample, indent=2)}</textarea>
          <button onclick=\"runTraverse()\">Run Traversal</button>
          <button class=\"secondary\" onclick=\"runReplay()\">Run Replay</button>
        </section>

        <section class=\"card\">
          <h2>Traversal Events</h2>
          <div id=\"events\"></div>
        </section>
      </div>

      <section class=\"card\">
        <h2>Last Response / JSON Output</h2>
        <div id=\"responseStatus\"></div>
        <pre id=\"response\">{{}}</pre>
      </section>
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

function pipelineVisualState(last, overrideState) {{
  if (overrideState) return normalizeOutcome(overrideState);
  if (!last || !last.pipeline_mode) return 'IDLE';
  if (normalizeOutcome(last.decision) === 'ESCALATE') return 'ESCALATE';
  if (normalizeOutcome(last.decision) === 'DENY') return 'DENY';
  if (normalizeOutcome(last.execution_result) === 'HALT') return 'FAIL';
  if (last.convergence_matched === false) return 'DENY';
  if (last.convergence_matched === true) return 'PASS';
  return 'IDLE';
}}

function pipelineVisualReason(last, state, overrideReason) {{
  if (overrideReason) return overrideReason;
  if (state === 'IDLE') return 'No active or completed pipeline traversal is available';
  if (state === 'ACTIVE') return 'Canonical pipeline traversal is in progress';
  if (state === 'PASS') return 'Pipeline traversal completed with deterministic convergence';
  return outcomeReason(state);
}}

function pipelineCylinder(label, state, reverse) {{
  return `<div class=\"pipeline-lane ${{reverse ? 'reverse' : ''}}\">
    <div class=\"pipeline-lane-label\">${{escapeHtml(label)}}</div>
    <div class=\"pipeline-cylinder\" aria-hidden=\"true\"><span class=\"pipeline-pulse\"></span></div>
  </div>`;
}}

function renderPipelineVisual(last, options = {{}}) {{
  const state = pipelineVisualState(last, options.state);
  const countValue = Number(options.pipelineCount ?? last?.pipeline_count ?? 0);
  const pipelineCount = countValue === 2 ? 2 : countValue === 1 ? 1 : 0;
  const lanes = pipelineCount === 2
    ? pipelineCylinder('Pipeline A', state, false) + pipelineCylinder('Pipeline B', state, true)
    : pipelineCount === 1
      ? pipelineCylinder('Pipeline A', state, false)
      : pipelineCylinder('Pipeline', 'IDLE', false);
  const reason = pipelineVisualReason(last, state, options.reason);
  document.getElementById('pipelineVisual').className =
    `pipeline-visual-dock pipeline-state-${{state.toLowerCase()}}`;
  document.getElementById('pipelineVisual').innerHTML =
    `<div class=\"pipeline-visual-heading\"><span>Traversal Pipeline</span></div>
     <div class=\"pipeline-visual-reason\">Reason: ${{escapeHtml(reason)}}</div>
     <div class=\"pipeline-visual-outcome\">${{statusBadge(state)}}</div>
     <div class=\"pipeline-lanes\">${{lanes}}</div>`;
}}

function metric(label, value) {{
  return `<div class=\"metric\"><span class=\"label\">${{escapeHtml(label)}}</span><span class=\"value\">${{escapeHtml(value ?? '')}}</span></div>`;
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

function renderSnapshot(data) {{
  const status = data.status || {{}};
  const last = data.last_state_summary || {{}};
  window.lastPipelineSnapshot = last;
  renderPipelineVisual(last);
  document.getElementById('health').innerHTML =
    reasonOutcome(status.chronology_valid && status.event_bus_valid && status.persistence_valid ?
      'Chronology, event bus, and persistence integrity verified' : 'One or more runtime health checks require attention',
      status.chronology_valid && status.event_bus_valid && status.persistence_valid ? 'PASS' : 'FAIL') +
    metric('Runtime', status.runtime_id) +
    metric('Security Mode', status.api_security_mode) +
    metric('Traversals', status.traversal_count) +
    metric('Chronology', status.chronology_valid) +
    metric('Event Bus', status.event_bus_valid) +
    metric('Persistence', status.persistence_valid);
  document.getElementById('pipeline').innerHTML =
    reasonOutcome(last.convergence_matched === true ? 'Pipeline A and Pipeline B parity matched' :
      last.convergence_matched === false ? 'Parity mismatch' : 'No completed convergence result is available',
      last.convergence_matched === true ? 'PASS' : last.convergence_matched === false ? 'DENY' : 'IDLE') +
    metric('Mode', last.pipeline_mode) +
    metric('Convergence Matched', last.convergence_matched) +
    metric('Convergence Hash', last.convergence_hash) +
    metric('State Hash', last.state_hash);
  document.getElementById('decision').innerHTML =
    reasonOutcome(outcomeReason(last.decision), last.decision || 'IDLE') +
    reasonOutcome(outcomeReason(last.execution_result), last.execution_result || 'IDLE') +
    metric('Decision', last.decision) +
    metric('Execution Result', last.execution_result) +
    metric('Token Count', last.token_count) +
    metric('Token Failures', JSON.stringify(last.token_failures || []));
  document.getElementById('audit').innerHTML =
    reasonOutcome(last.audit_hash ? 'Audit record finalised and available' : 'No finalised audit record is available',
      last.audit_hash ? 'PASS' : 'IDLE') +
    metric('Audit Hash', last.audit_hash) +
    metric('Request Fingerprint', last.request_fingerprint) +
    metric('Replay Ledger Size', data.replay_ledger_size);
}}

async function refreshAll() {{
  try {{
    const data = await getJson('/desktop/latest');
    renderSnapshot(data);
    const events = await getJson('/runtime/events?after=0');
    document.getElementById('events').innerHTML = renderEvents(events.events || []);
    document.getElementById('notice').innerHTML = '';
  }} catch (error) {{
    renderPipelineVisual(window.lastPipelineSnapshot || {{}}, {{state: 'FAIL', reason: error.message}});
    document.getElementById('notice').innerHTML = reasonOutcome(error.message, 'FAIL');
  }}
}}

async function runTraverse() {{
  try {{
    const payload = JSON.parse(document.getElementById('requestBox').value);
    renderPipelineVisual(window.lastPipelineSnapshot || {{}}, {{
      state: 'ACTIVE',
      pipelineCount: window.lastPipelineSnapshot?.pipeline_count || 1,
      reason: 'Canonical pipeline traversal is in progress'
    }});
    const result = await postJson('/runtime/traverse', payload);
    const state = result.state || {{}};
    document.getElementById('responseStatus').innerHTML =
      reasonOutcome(outcomeReason(state.decision), state.decision || 'ACTIVE');
    document.getElementById('response').textContent = JSON.stringify(result, null, 2);
    await refreshAll();
  }} catch (error) {{
    renderPipelineVisual(window.lastPipelineSnapshot || {{}}, {{state: 'FAIL', reason: error.message}});
    document.getElementById('responseStatus').innerHTML = reasonOutcome(error.message, 'FAIL');
  }}
}}

async function runReplay() {{
  try {{
    const payload = JSON.parse(document.getElementById('requestBox').value);
    payload.replay_count = 2;
    renderPipelineVisual(window.lastPipelineSnapshot || {{}}, {{
      state: 'ACTIVE',
      pipelineCount: window.lastPipelineSnapshot?.pipeline_count || 1,
      reason: 'Deterministic pipeline replay comparison is in progress'
    }});
    const result = await postJson('/runtime/replay', payload);
    document.getElementById('responseStatus').innerHTML =
      reasonOutcome(result.matched ? 'Replay checkpoints matched deterministically' : 'Replay checkpoint mismatch',
        result.matched ? 'PASS' : 'DENY');
    document.getElementById('response').textContent = JSON.stringify(result, null, 2);
    await refreshAll();
  }} catch (error) {{
    renderPipelineVisual(window.lastPipelineSnapshot || {{}}, {{state: 'FAIL', reason: error.message}});
    document.getElementById('responseStatus').innerHTML = reasonOutcome(error.message, 'FAIL');
  }}
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
