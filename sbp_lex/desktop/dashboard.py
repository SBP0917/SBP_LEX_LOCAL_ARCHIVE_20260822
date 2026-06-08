from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict

from sbp_lex.audit.pipeline_replay_ledger import PIPELINE_REPLAY_LEDGER
from sbp_lex.runtime.canonical_runtime import CANONICAL_RUNTIME
from sbp_lex.runtime.event_bus import RUNTIME_EVENTS


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
    :root {{ font-family: Arial, sans-serif; color: #111; background: #f5f5f5; }}
    body {{ margin: 0; padding: 18px; }}
    h1 {{ margin: 0 0 6px; font-size: 22px; }}
    h2 {{ margin: 0 0 8px; font-size: 16px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; }}
    .card {{ background: white; border: 1px solid #ddd; border-radius: 8px; padding: 12px; box-shadow: 0 1px 2px rgba(0,0,0,.05); }}
    .metric {{ display: flex; justify-content: space-between; border-bottom: 1px solid #eee; padding: 5px 0; gap: 10px; }}
    .label {{ color: #555; }}
    .value {{ font-family: monospace; text-align: right; word-break: break-all; }}
    button {{ padding: 8px 10px; margin: 4px 4px 4px 0; border: 1px solid #333; background: #111; color: white; border-radius: 6px; cursor: pointer; }}
    button.secondary {{ background: white; color: #111; }}
    textarea {{ width: 100%; min-height: 260px; font-family: monospace; font-size: 12px; }}
    pre {{ background: #111; color: #eee; padding: 10px; border-radius: 6px; overflow: auto; max-height: 360px; }}
    .ok {{ color: #0b6b2b; font-weight: bold; }}
    .bad {{ color: #9b111e; font-weight: bold; }}
  </style>
</head>
<body>
  <h1>SBP-LEX V1 Desktop Runtime Dashboard</h1>
  <p>Local operator interface for canonical runtime, dual adaptive deterministic pipelines, parity/convergence, execution decision, audit, replay, and observability.</p>

  <div class=\"grid\">
    <section class=\"card\">
      <h2>Runtime Health</h2>
      <div id=\"health\"></div>
      <button onclick=\"refreshAll()\">Refresh</button>
    </section>

    <section class=\"card\">
      <h2>Pipeline / Convergence</h2>
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

  <div class=\"grid\" style=\"margin-top:12px;\">
    <section class=\"card\">
      <h2>Controlled Test Request</h2>
      <textarea id=\"requestBox\">{__import__('json').dumps(sample, indent=2)}</textarea>
      <button onclick=\"runTraverse()\">Run Traversal</button>
      <button class=\"secondary\" onclick=\"runReplay()\">Run Replay</button>
    </section>

    <section class=\"card\">
      <h2>Traversal Events</h2>
      <pre id=\"events\">[]</pre>
    </section>
  </div>

  <section class=\"card\" style=\"margin-top:12px;\">
    <h2>Last Response</h2>
    <pre id=\"response\">{{}}</pre>
  </section>

<script>
function metric(label, value, cls='') {{
  return `<div class=\"metric\"><span class=\"label\">${{label}}</span><span class=\"value ${{cls}}\">${{value ?? ''}}</span></div>`;
}}

async function getJson(path) {{
  const res = await fetch(path, {{cache:'no-store'}});
  return await res.json();
}}

async function postJson(path, payload) {{
  const res = await fetch(path, {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify(payload)}});
  return await res.json();
}}

function renderSnapshot(data) {{
  const status = data.status || {{}};
  const last = data.last_state_summary || {{}};
  document.getElementById('health').innerHTML =
    metric('Runtime', status.runtime_id) +
    metric('Security Mode', status.api_security_mode) +
    metric('Traversals', status.traversal_count) +
    metric('Chronology', status.chronology_valid, status.chronology_valid ? 'ok' : 'bad') +
    metric('Event Bus', status.event_bus_valid, status.event_bus_valid ? 'ok' : 'bad') +
    metric('Persistence', status.persistence_valid, status.persistence_valid ? 'ok' : 'bad');
  document.getElementById('pipeline').innerHTML =
    metric('Mode', last.pipeline_mode) +
    metric('Convergence Matched', last.convergence_matched, last.convergence_matched ? 'ok' : 'bad') +
    metric('Convergence Hash', last.convergence_hash) +
    metric('State Hash', last.state_hash);
  document.getElementById('decision').innerHTML =
    metric('Decision', last.decision, last.decision === 'ALLOW' ? 'ok' : 'bad') +
    metric('Execution Result', last.execution_result, last.execution_result === 'EXECUTE' ? 'ok' : 'bad') +
    metric('Token Count', last.token_count) +
    metric('Token Failures', JSON.stringify(last.token_failures || []));
  document.getElementById('audit').innerHTML =
    metric('Audit Hash', last.audit_hash) +
    metric('Request Fingerprint', last.request_fingerprint) +
    metric('Replay Ledger Size', data.replay_ledger_size);
}}

async function refreshAll() {{
  const data = await getJson('/desktop/latest');
  renderSnapshot(data);
  const events = await getJson('/runtime/events?after=0');
  document.getElementById('events').textContent = JSON.stringify(events.events || [], null, 2);
}}

async function runTraverse() {{
  const payload = JSON.parse(document.getElementById('requestBox').value);
  const result = await postJson('/runtime/traverse', payload);
  document.getElementById('response').textContent = JSON.stringify(result, null, 2);
  await refreshAll();
}}

async function runReplay() {{
  const payload = JSON.parse(document.getElementById('requestBox').value);
  payload.replay_count = 2;
  const result = await postJson('/runtime/replay', payload);
  document.getElementById('response').textContent = JSON.stringify(result, null, 2);
  await refreshAll();
}}

async function downloadJson(path, filename) {{
  const data = await getJson(path);
  const blob = new Blob([JSON.stringify(data, null, 2)], {{type:'application/json'}});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click(); URL.revokeObjectURL(url);
}}

refreshAll();
setInterval(refreshAll, 3000);
</script>
</body>
</html>"""
