from __future__ import annotations

import json
from typing import Any, Mapping


def render_operator_cockpit(sample: Mapping[str, Any], background_url: str) -> str:
    """Render the Desktop V1 operator cockpit without changing runtime authority."""
    approved_demo = json.dumps(sample)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SBP-LEX Desktop V1 Operator Cockpit</title>
  <style>
    :root {{
      color-scheme: dark;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      --white: #fff;
      --muted: #b9c7dc;
      --panel: rgba(3, 9, 23, .82);
      --panel-strong: rgba(2, 6, 16, .94);
      --line: rgba(146, 181, 230, .25);
      --status-pass: #19d98b;
      --status-pass-fill: rgba(25, 217, 139, .18);
      --status-escalate: #ff9f1c;
      --status-escalate-fill: rgba(255, 159, 28, .2);
      --status-deny: #ff3b30;
      --status-deny-fill: rgba(255, 59, 48, .2);
      --status-fail: #ff3b30;
      --status-fail-fill: rgba(255, 59, 48, .2);
      --status-active: #19cfff;
      --status-active-fill: rgba(25, 207, 255, .2);
      --status-idle: #718096;
      --status-idle-fill: rgba(113, 128, 150, .2);
      --semantic: var(--status-idle);
      --semantic-fill: var(--status-idle-fill);
    }}
    * {{ box-sizing: border-box; }}
    html {{ min-height: 100%; background: #01040d url('{background_url}') center/cover fixed no-repeat; }}
    body {{
      min-height: 100vh; margin: 0; overflow-x: hidden; color: var(--white); font-weight: 700;
      background: linear-gradient(180deg, rgba(1,4,13,.6), rgba(1,6,18,.86));
    }}
    button {{ font: inherit; }}
    .environment {{ position: fixed; inset: 0; z-index: -1; overflow: hidden; pointer-events: none; }}
    .star-field {{
      position: absolute; inset: -10%; opacity: .55;
      background-image:
        radial-gradient(circle at 12% 28%, rgba(255,255,255,.9) 0 1px, transparent 1.5px),
        radial-gradient(circle at 72% 18%, rgba(178,218,255,.8) 0 1px, transparent 1.6px),
        radial-gradient(circle at 42% 72%, rgba(255,255,255,.72) 0 1px, transparent 1.4px),
        radial-gradient(circle at 86% 65%, rgba(172,205,255,.75) 0 1px, transparent 1.5px);
      background-size: 170px 160px, 230px 210px, 140px 190px, 270px 240px;
      animation: star-drift 48s linear infinite;
    }}
    .nebula {{
      position: absolute; inset: -20%; opacity: .3;
      background: radial-gradient(ellipse at 22% 35%, rgba(31,81,170,.44), transparent 38%),
                  radial-gradient(ellipse at 80% 58%, rgba(29,74,145,.34), transparent 38%);
      filter: blur(24px); animation: nebula-breathe 18s ease-in-out infinite alternate;
    }}
    .storm-front {{
      position: absolute; width: 74vw; height: 48vh; top: -9vh; right: -18vw; opacity: .08;
      border-radius: 50%; filter: blur(34px);
      background: radial-gradient(ellipse, rgba(52,71,105,.9), rgba(12,22,45,.74) 42%, transparent 72%);
      transform: translate3d(18vw,-8vh,0); transition: opacity .8s, transform 1.1s, filter 1s;
    }}
    .storm-front.secondary {{ left: -22vw; right: auto; top: 16vh; transform: translate3d(-18vw,0,0); opacity: .05; }}
    .wind {{ position:absolute; inset:0; opacity:0; transition:opacity .7s; }}
    .wind::before, .wind::after {{
      content:""; position:absolute; left:-35%; width:45%; height:1px;
      background:linear-gradient(90deg,transparent,rgba(202,226,255,.42),transparent);
      transform:rotate(-8deg); animation:gust 3.8s linear infinite;
    }}
    .wind::before {{ top:34%; }} .wind::after {{ top:64%; animation-delay:1.7s; }}
    .lightning {{
      position:absolute; top:8%; right:24%; width:2px; height:34vh; opacity:0;
      background:linear-gradient(#fff, var(--status-active), transparent);
      transform:skew(-18deg); filter:drop-shadow(0 0 10px var(--status-active));
    }}
    .storm-live .storm-front {{ opacity:.48; transform:translate3d(-9vw,8vh,0); filter:blur(23px); }}
    .storm-live .storm-front.secondary {{ opacity:.3; transform:translate3d(9vw,0,0); }}
    .storm-live .wind {{ opacity:.54; }}
    .storm-live .lightning {{ animation:distant-lightning 4.8s ease-in-out infinite; }}
    .storm-alive .storm-front {{ opacity:.28; transform:translate3d(-2vw,13vh,0); animation:storm-circle 13s ease-in-out infinite alternate; }}
    .storm-alive .storm-front.secondary {{ opacity:.18; transform:translate3d(5vw,2vh,0); }}
    .storm-alive .wind {{ opacity:.2; }}
    .storm-alive .lightning {{ animation:distant-lightning 9s ease-in-out infinite; }}
    .storm-escalate .storm-front {{ opacity:.68; transform:translate3d(-16vw,17vh,0); filter:blur(18px); }}
    .storm-escalate .storm-front.secondary {{ opacity:.46; transform:translate3d(13vw,-2vh,0); }}
    .storm-escalate .wind {{ opacity:.75; }}
    .storm-escalate .lightning {{ animation:distant-lightning 2.4s ease-in-out infinite; filter:drop-shadow(0 0 10px var(--status-escalate)); }}
    .storm-deny .storm-front {{ animation:storm-withdraw 2.6s ease-out forwards; }}
    .storm-deny .wind {{ animation:wind-release 2s ease-out forwards; }}
    .storm-deny .lightning {{ animation:deny-strike 1.15s ease-out 1; filter:drop-shadow(0 0 12px var(--status-deny)); }}
    .storm-calm .storm-front, .storm-historical .storm-front, .storm-terminal .storm-front {{ opacity:.07; transform:translate3d(20vw,-8vh,0); }}
    .storm-execute .storm-front {{ opacity:0; transform:translate3d(28vw,-18vh,0); }}
    .storm-execute .star-field {{ opacity:.82; }}

    .desktop-shell {{ min-height:100vh; padding:10px; transition:margin-right .25s ease; }}
    .cockpit-primary {{
      width:min(1760px,100%); min-height:calc(100svh - 20px); margin:auto; padding:12px;
      display:grid; grid-template-rows:auto auto 1fr auto; gap:10px;
      border:1px solid rgba(82,145,235,.3); border-radius:18px;
      background:linear-gradient(145deg,rgba(2,8,22,.77),rgba(2,7,18,.55));
      box-shadow:0 28px 90px rgba(0,0,0,.5), inset 0 1px rgba(255,255,255,.05);
      backdrop-filter:blur(10px);
    }}
    .cockpit-header {{ display:grid; grid-template-columns:minmax(260px,.8fr) minmax(420px,1.4fr); gap:14px; align-items:center; }}
    .eyebrow {{ color:#7dd3fc; font-size:10px; letter-spacing:.16em; text-transform:uppercase; }}
    h1 {{ margin:2px 0; font-size:clamp(20px,2vw,31px); letter-spacing:.04em; }}
    h2 {{ margin:0; font-size:13px; letter-spacing:.1em; text-transform:uppercase; }}
    p {{ margin:0; color:var(--muted); line-height:1.4; }}
    .landing-status {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:6px; }}
    .landing-item {{ padding:7px 8px; min-width:0; border:1px solid var(--line); border-radius:9px; background:rgba(0,0,0,.28); }}
    .landing-item .label {{ display:block; margin-bottom:3px; color:var(--muted); font-size:8px; letter-spacing:.1em; text-transform:uppercase; }}
    .landing-item .value {{ display:block; overflow:hidden; color:var(--white); font:700 10px "Cascadia Mono",Consolas,monospace; text-overflow:ellipsis; white-space:nowrap; }}
    .operator-controls {{
      position:sticky; top:6px; z-index:12; display:grid; grid-template-columns:repeat(9,minmax(92px,1fr)); gap:6px;
      padding:7px; border:1px solid rgba(116,166,238,.28); border-radius:11px; background:rgba(2,7,18,.94); box-shadow:0 12px 30px rgba(0,0,0,.38);
    }}
    .operator-controls button, .detail-actions button {{
      min-height:38px; padding:7px 8px; border:1px solid rgba(151,180,218,.36); border-radius:8px;
      color:var(--white); background:rgba(17,29,51,.84); font-size:10px; font-weight:800; cursor:pointer;
    }}
    .operator-controls button:hover, .detail-actions button:hover {{ border-color:#7dd3fc; background:rgba(26,47,79,.95); }}
    .operator-controls button:disabled {{ opacity:.44; cursor:not-allowed; }}
    .operator-controls .action-description {{ display:block; margin-top:2px; color:var(--muted); font-size:8px; font-weight:650; }}
    .cockpit-grid {{ display:grid; grid-template-columns:minmax(240px,1fr) minmax(330px,1.18fr) minmax(240px,1fr); gap:10px; min-height:0; }}
    .surface {{ min-width:0; border:1px solid var(--line); border-radius:13px; background:var(--panel); box-shadow:0 15px 38px rgba(0,0,0,.34); }}
    .pipeline-wing {{ padding:12px; display:grid; grid-template-rows:auto 1fr auto; gap:9px; overflow:hidden; }}
    .wing-a {{ border-left:2px solid rgba(125,211,252,.48); }} .wing-b {{ border-right:2px solid rgba(125,211,252,.48); }}
    .wing-heading {{ display:flex; justify-content:space-between; gap:8px; align-items:center; }}
    .wing-heading span {{ color:var(--muted); font-size:9px; letter-spacing:.1em; text-transform:uppercase; }}
    .pipeline-cylinder {{
      --semantic:var(--status-idle); --semantic-fill:var(--status-idle-fill);
      position:relative; min-height:90px; overflow:hidden; border:1px solid var(--semantic); border-radius:45% / 13%;
      background:linear-gradient(180deg,rgba(255,255,255,.09),transparent 35%,rgba(0,0,0,.28)),
                 linear-gradient(90deg,transparent,var(--semantic-fill),transparent);
      box-shadow:inset 0 0 30px var(--semantic-fill),0 0 15px var(--semantic-fill);
    }}
    .pipeline-cylinder::before,.pipeline-cylinder::after {{ content:""; position:absolute; inset:7px auto 7px 6px; width:28px; border:1px solid var(--semantic); border-radius:50%; opacity:.62; }}
    .pipeline-cylinder::after {{ left:auto; right:6px; }}
    .pipeline-track {{ position:absolute; inset:18px 32px; border-top:1px solid var(--semantic); border-bottom:1px solid var(--semantic); opacity:.5; }}
    .path-light {{ position:absolute; top:20px; bottom:20px; left:-28%; width:25%; border-radius:50%; opacity:0; background:linear-gradient(90deg,transparent,rgba(255,255,255,.9),transparent); }}
    .wing-b .path-light {{ left:auto; right:-28%; }}
    .pipeline-mode-live .pipeline-cylinder {{ --semantic:var(--status-active); --semantic-fill:var(--status-active-fill); animation:live-strobe 1.05s ease-in-out infinite alternate; }}
    .pipeline-mode-live .path-light {{ opacity:.95; animation:path-travel 1.35s linear infinite; }}
    .pipeline-mode-live .wing-b .path-light {{ animation-name:path-travel-reverse; }}
    .pipeline-mode-alive .pipeline-cylinder {{ animation:heartbeat-glow 2s ease-in-out infinite; }}
    .pipeline-mode-alive .pipeline-cylinder::after {{ box-shadow:0 0 18px var(--semantic); animation:near-life 2s ease-in-out infinite; }}
    .pipeline-mode-historical .pipeline-cylinder,.pipeline-mode-terminal .pipeline-cylinder,.pipeline-mode-idle .pipeline-cylinder {{ animation:none; }}
    .semantic-pass {{ --semantic:var(--status-pass); --semantic-fill:var(--status-pass-fill); }}
    .semantic-escalate {{ --semantic:var(--status-escalate); --semantic-fill:var(--status-escalate-fill); }}
    .semantic-deny {{ --semantic:var(--status-deny); --semantic-fill:var(--status-deny-fill); }}
    .semantic-active {{ --semantic:var(--status-active); --semantic-fill:var(--status-active-fill); }}
    .semantic-idle {{ --semantic:var(--status-idle); --semantic-fill:var(--status-idle-fill); }}
    .ecg-trace {{ position:absolute; inset:28px 34px; color:var(--status-active); filter:drop-shadow(0 0 7px var(--status-active)); }}
    .ecg-trace polyline {{ fill:none; stroke:currentColor; stroke-width:2; vector-effect:non-scaling-stroke; stroke-dasharray:11 5; animation:ecg-travel 1.05s linear infinite; }}
    .wing-status {{ display:grid; gap:6px; }}
    .mini-metric {{ display:flex; justify-content:space-between; gap:8px; padding-top:6px; border-top:1px solid rgba(255,255,255,.08); color:var(--muted); font-size:9px; }}
    .mini-metric strong {{ color:var(--white); font-family:"Cascadia Mono",Consolas,monospace; text-align:right; overflow-wrap:anywhere; }}

    .scale-arena {{ position:relative; padding:10px; display:grid; grid-template-rows:auto 1fr auto; overflow:hidden; }}
    .celestial-ring {{
      position:absolute; width:min(48vh,86%); aspect-ratio:1; left:50%; top:50%; transform:translate(-50%,-50%); border-radius:50%; opacity:.26;
      background:repeating-conic-gradient(from -90deg,rgba(190,218,255,.8) 0 .35deg,transparent .35deg 5deg);
      -webkit-mask:radial-gradient(circle,transparent 0 45%,#000 45.5% 48%,transparent 48.5%);
      mask:radial-gradient(circle,transparent 0 45%,#000 45.5% 48%,transparent 48.5%);
    }}
    .celestial-ring::before {{ content:"360° · degree / minute / second markings"; position:absolute; left:50%; top:5%; transform:translateX(-50%); color:var(--muted); font-size:8px; white-space:nowrap; }}
    .scale-wrap {{ position:relative; z-index:2; min-height:250px; display:flex; align-items:center; justify-content:center; }}
    .scale {{ position:relative; width:min(340px,88%); height:235px; transform-origin:50% 42%; }}
    .scale-column {{ position:absolute; left:50%; bottom:16px; width:12px; height:145px; transform:translateX(-50%); border-radius:8px; background:linear-gradient(90deg,#60758f,#d2e6ff,#60758f); box-shadow:0 0 14px rgba(154,202,255,.32); }}
    .scale-column::after {{ content:""; position:absolute; left:50%; bottom:-13px; width:110px; height:18px; transform:translateX(-50%); border-radius:50%; background:linear-gradient(#8ba6c6,#34465e); }}
    .scale-beam {{ position:absolute; left:50%; top:76px; width:90%; height:8px; transform:translateX(-50%) rotate(var(--tilt,0deg)); transform-origin:center; border-radius:8px; background:linear-gradient(180deg,#d9eaff,#627993); box-shadow:0 0 18px rgba(165,211,255,.4); transition:transform .8s cubic-bezier(.2,.8,.2,1); }}
    .scale-pan {{ position:absolute; top:20px; width:35%; height:94px; border-bottom:3px solid #a8bfd9; border-radius:0 0 50% 50%; }}
    .scale-pan::before,.scale-pan::after {{ content:""; position:absolute; top:-19px; width:1px; height:79px; background:#a8bfd9; transform-origin:top; }}
    .scale-pan::before {{ left:15%; transform:rotate(15deg); }} .scale-pan::after {{ right:15%; transform:rotate(-15deg); }}
    .pan-left {{ left:0; }} .pan-right {{ right:0; }}
    .scale-state-live .scale {{ animation:scale-live 2.8s ease-in-out infinite; }}
    .scale-state-alive .scale {{ animation:scale-alive 2s ease-in-out infinite; }}
    .scale-state-escalate .scale-beam {{ --tilt:-5deg; }}
    .scale-state-deny .scale {{ animation:scale-deny .75s ease-out 1; }}
    .scale-state-pass .scale-beam,.scale-state-execute .scale-beam {{ --tilt:0deg; }}
    .state-title {{ position:relative; z-index:3; display:flex; justify-content:space-between; gap:10px; align-items:center; }}
    .state-title span {{ color:var(--muted); font-size:9px; letter-spacing:.1em; text-transform:uppercase; }}
    .central-state {{ position:relative; z-index:3; text-align:center; }}
    .central-state strong {{ display:block; color:var(--semantic); font-size:clamp(21px,3vw,38px); letter-spacing:.08em; text-shadow:0 0 22px var(--semantic-fill); }}
    .central-state span {{ color:var(--muted); font-size:10px; }}

    .state-deck {{ display:grid; grid-template-columns:1.05fr 1.05fr .9fr .9fr .9fr; gap:7px; }}
    .state-card {{ position:relative; min-width:0; padding:9px; overflow:hidden; border:1px solid var(--semantic); border-radius:10px; background:linear-gradient(135deg,var(--semantic-fill),rgba(0,0,0,.34)); }}
    .state-card .state-label {{ display:block; margin-bottom:4px; color:var(--muted); font-size:8px; letter-spacing:.1em; text-transform:uppercase; }}
    .state-card .state-value {{ display:block; overflow:hidden; color:var(--white); font-size:12px; text-overflow:ellipsis; white-space:nowrap; }}
    .state-card .state-note {{ display:block; margin-top:4px; color:var(--muted); font-size:8px; }}
    .state-glow {{ box-shadow:0 0 19px var(--semantic-fill),inset 0 0 14px var(--semantic-fill); }}
    .heartbeat-state {{ animation:heartbeat-glow 2s ease-in-out infinite; }}
    .state-historical,.state-terminal {{ box-shadow:none; animation:none; }}
    .reason-banner {{ display:none; grid-column:1/-1; padding:7px 10px; border:1px solid var(--semantic); border-radius:8px; color:#fff; background:rgba(0,0,0,.56); font-size:11px; font-weight:900; }}
    .reason-banner.visible {{ display:block; }}
    .identity-envelope {{ grid-column:1/-1; display:grid; grid-template-columns:repeat(6,minmax(0,1fr)); gap:5px; padding-top:7px; border-top:1px solid var(--line); }}
    .identity-item {{ min-width:0; padding:5px 7px; border-radius:7px; background:rgba(0,0,0,.3); }}
    .identity-item span {{ display:block; color:var(--muted); font-size:7px; letter-spacing:.09em; text-transform:uppercase; }}
    .identity-item strong {{ display:block; overflow:hidden; margin-top:2px; color:var(--white); font:700 9px "Cascadia Mono",Consolas,monospace; text-overflow:ellipsis; white-space:nowrap; }}
    .notice {{ min-height:0; }}

    .detail-panel {{
      position:fixed; z-index:30; top:10px; right:10px; bottom:10px; width:380px; padding:14px; overflow:auto;
      border:1px solid rgba(125,211,252,.42); border-radius:14px; background:var(--panel-strong); box-shadow:-24px 0 54px rgba(0,0,0,.56);
      transform:translateX(calc(100% + 24px)); transition:transform .25s ease;
    }}
    .detail-panel.open {{ transform:translateX(0); }}
    .detail-open .desktop-shell {{ margin-right:390px; }}
    .detail-header {{ display:flex; align-items:center; justify-content:space-between; gap:8px; margin-bottom:10px; }}
    .detail-header button {{ width:30px; height:30px; border:1px solid var(--line); border-radius:50%; color:#fff; background:transparent; cursor:pointer; }}
    .detail-actions {{ display:grid; grid-template-columns:1fr 1fr; gap:6px; margin:10px 0; }}
    .detail-content {{ font-size:11px; }}
    .metric {{ display:grid; grid-template-columns:minmax(100px,.8fr) minmax(0,1.2fr); gap:8px; padding:7px 0; border-bottom:1px solid rgba(255,255,255,.08); }}
    .metric .label {{ color:var(--muted); }} .metric .value {{ color:#fff; text-align:right; overflow-wrap:anywhere; font-family:"Cascadia Mono",Consolas,monospace; }}
    .reason-outcome {{ margin:7px 0; padding:9px; border:1px solid rgba(255,255,255,.1); border-radius:9px; background:rgba(0,0,0,.3); }}
    .reason {{ margin-bottom:7px; color:#fff; font-weight:900; }}
    .status-badge {{ display:inline-flex; padding:5px 9px; border:1px solid; border-radius:999px; color:#fff; font-size:9px; letter-spacing:.08em; text-transform:uppercase; }}
    .status-pass {{ border-color:var(--status-pass); background:var(--status-pass-fill); }}
    .status-escalate {{ border-color:var(--status-escalate); background:var(--status-escalate-fill); }}
    .status-deny,.status-fail {{ border-color:var(--status-deny); background:var(--status-deny-fill); }}
    .status-active {{ border-color:var(--status-active); background:var(--status-active-fill); }}
    .status-idle {{ border-color:var(--status-idle); background:var(--status-idle-fill); }}
    .timeline,.events-list {{ display:grid; gap:6px; }}
    .timeline-row,.event-row {{ padding:8px; border:1px solid var(--line); border-radius:8px; background:rgba(0,0,0,.24); }}
    .timeline-stage,.event-meta {{ color:#fff; font-size:9px; letter-spacing:.05em; text-transform:uppercase; }}
    .timeline-reason {{ margin:4px 0; color:var(--muted); font-size:9px; }}
    pre {{ max-height:320px; padding:9px; overflow:auto; border:1px solid var(--line); border-radius:8px; color:#fff; background:#020611; white-space:pre-wrap; font:650 9px "Cascadia Mono",Consolas,monospace; }}
    .data-cache {{ display:none !important; }}

    @keyframes star-drift {{ to {{ transform:translate3d(4%,2%,0); }} }}
    @keyframes nebula-breathe {{ to {{ opacity:.46; transform:scale(1.06); }} }}
    @keyframes gust {{ from {{ transform:translateX(0) rotate(-8deg); }} to {{ transform:translateX(320%) rotate(-8deg); }} }}
    @keyframes distant-lightning {{ 0%,72%,76%,100% {{ opacity:0; }} 73% {{ opacity:.75; }} 74% {{ opacity:.15; }} 75% {{ opacity:.5; }} }}
    @keyframes storm-circle {{ to {{ transform:translate3d(-6vw,10vh,0) rotate(6deg); }} }}
    @keyframes storm-withdraw {{ 0% {{ opacity:.78; transform:translate3d(-14vw,16vh,0); }} 25% {{ opacity:.92; }} 100% {{ opacity:.08; transform:translate3d(26vw,-12vh,0); }} }}
    @keyframes wind-release {{ 0% {{ opacity:.9; }} 100% {{ opacity:0; }} }}
    @keyframes deny-strike {{ 0%,15% {{ opacity:0; }} 20% {{ opacity:1; }} 28% {{ opacity:.1; }} 36% {{ opacity:.8; }} 100% {{ opacity:0; }} }}
    @keyframes live-strobe {{ from {{ filter:brightness(.82); }} to {{ filter:brightness(1.27); }} }}
    @keyframes path-travel {{ to {{ transform:translateX(520%); }} }}
    @keyframes path-travel-reverse {{ to {{ transform:translateX(-520%); }} }}
    @keyframes ecg-travel {{ to {{ stroke-dashoffset:-32; }} }}
    @keyframes heartbeat-glow {{
      0%,8%,18%,48%,56%,66%,100% {{ filter:brightness(1); box-shadow:0 0 12px var(--semantic-fill),inset 0 0 8px var(--semantic-fill); transform:scale(1); }}
      4%,52% {{ filter:brightness(1.25); box-shadow:0 0 23px var(--semantic),inset 0 0 16px var(--semantic-fill); transform:scale(1.006); }}
      13%,61% {{ filter:brightness(1.5); box-shadow:0 0 31px var(--semantic),inset 0 0 20px var(--semantic-fill); transform:scale(1.012); }}
    }}
    @keyframes near-life {{ 0%,18%,48%,66%,100% {{ opacity:.25; }} 4%,13%,52%,61% {{ opacity:.9; }} }}
    @keyframes scale-live {{ 0%,100% {{ transform:rotate(-.5deg); }} 50% {{ transform:rotate(.7deg); }} }}
    @keyframes scale-alive {{ 0%,18%,48%,66%,100% {{ transform:translateY(0) rotate(0); }} 4%,52% {{ transform:translateY(-1px) rotate(.3deg); }} 13%,61% {{ transform:translateY(-2px) rotate(-.4deg); }} }}
    @keyframes scale-deny {{ 0% {{ transform:rotate(0); }} 30% {{ transform:rotate(-4deg); }} 55% {{ transform:rotate(3deg); }} 100% {{ transform:rotate(0); }} }}
    @media (prefers-reduced-motion:reduce) {{ * {{ animation-duration:.001ms !important; animation-iteration-count:1 !important; scroll-behavior:auto !important; }} }}
    @media (max-width:1180px) {{
      .cockpit-primary {{ min-height:auto; }} .operator-controls {{ grid-template-columns:repeat(3,1fr); }}
      .cockpit-grid {{ grid-template-columns:1fr 1.2fr; }} .wing-b {{ grid-column:1; grid-row:2; }} .scale-arena {{ grid-column:2; grid-row:1/3; }}
      .state-deck {{ grid-template-columns:repeat(3,1fr); }} .identity-envelope {{ grid-template-columns:repeat(3,1fr); }}
      .detail-open .desktop-shell {{ margin-right:0; }} .detail-panel {{ position:relative; inset:auto; width:min(100%,1760px); margin:10px auto; display:none; transform:none; }} .detail-panel.open {{ display:block; }}
    }}
    @media (max-width:760px) {{
      .cockpit-header,.cockpit-grid {{ grid-template-columns:1fr; }} .landing-status {{ grid-template-columns:repeat(2,1fr); }}
      .wing-b,.scale-arena {{ grid-column:auto; grid-row:auto; }} .scale-arena {{ min-height:330px; }}
      .state-deck,.identity-envelope {{ grid-template-columns:repeat(2,1fr); }} .operator-controls {{ grid-template-columns:repeat(2,1fr); position:relative; top:auto; }}
    }}
  </style>
</head>
<body class="storm-calm">
  <div class="environment" aria-hidden="true"><div class="star-field"></div><div class="nebula"></div><div class="storm-front"></div><div class="storm-front secondary"></div><div class="wind"></div><div class="lightning"></div></div>
  <div class="desktop-shell">
    <main class="cockpit-primary" id="liveCockpit">
      <header class="cockpit-header">
        <div><div class="eyebrow">Institutional Operator Surface · Desktop V1</div><h1>SBP-LEX Operator Cockpit</h1><p>Local Governance Observability Console · Dual Adaptive Deterministic Pipelines</p></div>
        <div id="landingStatus" class="landing-status"></div>
      </header>
      <nav class="operator-controls" aria-label="Controlled Operator Actions">
        <button onclick="runApprovedDemo()">Start Live Test<span class="action-description">Run Approved Demo Traversal</span></button>
        <button onclick="runReplay()">Run Replay<span class="action-description">Deterministic comparison</span></button>
        <button onclick="openDetail('runtime')">Runtime Status<span class="action-description">Read-only status</span></button>
        <button onclick="resetCockpit()">Reset / Clear View<span class="action-description">Presentation only</span></button>
        <button onclick="loadDemoRequest()">Load Demo Request<span class="action-description">Preview only</span></button>
        <button disabled title="No existing Desktop V1 halt endpoint">Stop / Halt<span class="action-description">Unavailable</span></button>
        <button onclick="openDetail('audit')">Audit / Details<span class="action-description">Non-blocking panel</span></button>
        <button onclick="openDetail('truth')">Procedural Truth Details<span class="action-description">Retained status</span></button>
        <button onclick="openDetail('bridge')">SKG/DTN Bridge Details<span class="action-description">External readiness only</span></button>
      </nav>

      <section id="pipelineVisual" class="cockpit-grid pipeline-mode-idle semantic-idle" aria-live="polite">
        <article class="pipeline-wing wing-a surface" id="pipelineA">
          <div class="wing-heading"><h2>Pipeline A</h2><span>Canonical traversal</span></div>
          <div class="pipeline-cylinder"><div class="pipeline-track"></div><div class="path-light"></div><div class="ecg-slot"></div></div>
          <div class="wing-status" id="pipelineAStatus"></div>
        </article>
        <article class="scale-arena surface scale-state-idle" id="scaleArena">
          <div class="celestial-ring"></div>
          <div class="state-title"><h2>Governed State</h2><span id="environmentLabel">CALM SPACE</span></div>
          <div class="scale-wrap"><div class="scale"><div class="scale-column"></div><div class="scale-beam"><div class="scale-pan pan-left"></div><div class="scale-pan pan-right"></div></div></div></div>
          <div class="central-state"><strong id="currentSemantic">IDLE</strong><span id="currentMeaning">Awaiting work</span></div>
        </article>
        <article class="pipeline-wing wing-b surface" id="pipelineB">
          <div class="wing-heading"><h2>Pipeline B</h2><span>Deterministic validator</span></div>
          <div class="pipeline-cylinder"><div class="pipeline-track"></div><div class="path-light"></div><div class="ecg-slot"></div></div>
          <div class="wing-status" id="pipelineBStatus"></div>
        </article>
      </section>

      <section class="state-deck" aria-label="Current and retained state">
        <div id="reasonBanner" class="reason-banner semantic-idle"></div>
        <div id="currentStateCard" class="state-card semantic-idle"><span class="state-label">Current State</span><strong class="state-value">IDLE</strong><span class="state-note">No active traversal</span></div>
        <div id="lastCurrentCard" class="state-card semantic-idle state-historical"><span class="state-label">Last Current Traversed</span><strong class="state-value">Not available</strong><span class="state-note">Retained until replaced</span></div>
        <div id="aliveStateCard" class="state-card semantic-idle state-historical"><span class="state-label">Recoverable / Alive</span><strong class="state-value">None</strong><span class="state-note">Heartbeat only when recoverable</span></div>
        <div id="truthStateCard" class="state-card semantic-idle"><span class="state-label">Procedural Truth</span><strong class="state-value">IDLE</strong><span class="state-note">Internal retained status</span></div>
        <div id="outcomeStateCard" class="state-card semantic-idle"><span class="state-label">Execution Outcome</span><strong class="state-value">IDLE</strong><span class="state-note">Existing runtime result</span></div>
        <div id="identityEnvelope" class="identity-envelope"></div>
      </section>
      <div id="notice" class="notice"></div>
    </main>

    <aside id="detailPanel" class="detail-panel" aria-hidden="true" aria-label="Operator detail panel">
      <div class="detail-header"><h2 id="detailTitle">Operator Details</h2><button onclick="closeDetail()" aria-label="Close details">×</button></div>
      <div class="detail-actions"><button onclick="openSecondaryWorkspace()">Pop Out Celestial Workspace</button><button onclick="refreshAll()">Refresh Details</button></div>
      <div id="detailContent" class="detail-content"></div>
    </aside>

    <div class="data-cache" aria-hidden="true">
      <div id="integrity"></div><div id="admissibility"></div><div id="pipelineTimeline"></div><div id="convergenceProof"></div>
      <div id="auditContinuity"></div><div id="replayComparison"></div><div id="events"></div><div id="responseStatus"></div><pre id="response">{{}}</pre>
    </div>
  </div>

<script>
const STATUS_CLASS = Object.freeze({{
  PASS:'status-pass',ALLOW:'status-pass',EXECUTE:'status-pass',MATCHED:'status-pass',VALID:'status-pass',TRUE:'status-pass',
  ESCALATE:'status-escalate',REFINE:'status-escalate',DENY:'status-deny',REJECTED:'status-deny',FAIL:'status-fail',HALT:'status-fail',STOP:'status-fail',FALSE:'status-fail',
  ACTIVE:'status-active',PROCESSING:'status-active',LIVE:'status-active',LIVE_TRAVERSING:'status-active',IN_PROGRESS:'status-active',
  IDLE:'status-idle',WAITING:'status-idle',INACTIVE:'status-idle',UNKNOWN:'status-idle'
}});
const APPROVED_DEMO = {approved_demo};
const DETAIL_TITLES = Object.freeze({{runtime:'Runtime Status',audit:'Audit / Details',truth:'Procedural Truth Details',bridge:'SKG/DTN Bridge Details'}});
window.lastPipelineSnapshot = {{}}; window.lastIdentitySummary = {{}}; window.lastCockpitData = {{}}; window.lastCompletedState = null;

function escapeHtml(value) {{ return String(value ?? '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#039;'); }}
function normalizeOutcome(value) {{ if(value===true)return'PASS'; if(value===false)return'FAIL'; return String(value??'IDLE').trim().toUpperCase().replaceAll(' ','_')||'IDLE'; }}
function semanticClass(value) {{ const state=normalizeOutcome(value); if(['PASS','ALLOW','EXECUTE','MATCHED','VALID','TRUE'].includes(state))return'semantic-pass'; if(['ESCALATE','REFINE'].includes(state))return'semantic-escalate'; if(['DENY','FAIL','HALT','STOP','REJECTED','FALSE'].includes(state))return'semantic-deny'; if(['ACTIVE','PROCESSING','LIVE','LIVE_TRAVERSING','IN_PROGRESS'].includes(state))return'semantic-active'; return'semantic-idle'; }}
function statusBadge(outcome) {{ const value=normalizeOutcome(outcome); return `<span class="status-badge ${{STATUS_CLASS[value]||'status-idle'}}">${{escapeHtml(value.replaceAll('_',' '))}}</span>`; }}
function reasonOutcome(reason,outcome) {{ return `<div class="reason-outcome"><div class="reason">Reason: ${{escapeHtml(reason||'No runtime result available')}}</div>${{statusBadge(outcome)}}</div>`; }}
function metric(label,value) {{ const display=value===null||value===undefined||value===''?'Not available':value; return `<div class="metric"><span class="label">${{escapeHtml(label)}}</span><span class="value">${{escapeHtml(display)}}</span></div>`; }}
function miniMetric(label,value) {{ const display=value===null||value===undefined||value===''?'—':value; return `<div class="mini-metric"><span>${{escapeHtml(label)}}</span><strong>${{escapeHtml(display)}}</strong></div>`; }}
function landingItem(label,value) {{ const display=value===null||value===undefined||value===''?'—':value; return `<div class="landing-item"><span class="label">${{escapeHtml(label)}}</span><span class="value">${{escapeHtml(display)}}</span></div>`; }}
function shortValue(value,length=12) {{ const text=String(value??''); return text?`${{text.slice(0,length)}}${{text.length>length?'…':''}}`:'—'; }}
function outcomeReason(outcome,fallback) {{ const value=normalizeOutcome(outcome); const reasons={{PASS:'Governed verification completed',ALLOW:'Execution admissibility verified',EXECUTE:'Governed execution completed',ESCALATE:'Further governed handling required',REFINE:'Governed refinement required',DENY:'Governed refusal concluded traversal',FAIL:'Runtime verification did not pass',HALT:'Execution-control stop applied',STOP:'Controlled stop applied',LIVE:'Canonical traversal is active',ACTIVE:'Canonical traversal is active',IDLE:'Awaiting work'}}; return reasons[value]||fallback||`Runtime reported ${{value.replaceAll('_',' ')}}`; }}

function cockpitMode(last,overrideMode) {{
  if(overrideMode)return normalizeOutcome(overrideMode);
  if(!last||!last.pipeline_mode)return'IDLE';
  const decision=normalizeOutcome(last.decision), execution=normalizeOutcome(last.execution_result);
  if((execution==='HALT'&&last.recoverable)||decision==='ESCALATE')return'ALIVE';
  if(decision==='DENY'||execution==='HALT'||execution==='STOP')return'TERMINAL';
  if(['PASS','ALLOW','EXECUTE'].includes(decision)||execution==='EXECUTE')return'HISTORICAL';
  return'IDLE';
}}
function retainedOutcome(last) {{ return normalizeOutcome(last.execution_result==='HALT'?'HALT':last.decision||last.execution_result||'IDLE'); }}
function ecgMarkup(mode) {{ return mode==='LIVE'?`<svg class="ecg-trace" viewBox="0 0 240 50" preserveAspectRatio="none" aria-label="Live traversal ECG"><polyline points="0,25 45,25 55,16 63,36 73,5 84,43 96,25 145,25 155,18 164,32 174,10 184,39 196,25 240,25"/></svg>`:''; }}
function environmentFor(mode,outcome) {{ if(mode==='LIVE')return'live'; if(mode==='ALIVE')return normalizeOutcome(outcome)==='ESCALATE'?'escalate':'alive'; if(normalizeOutcome(outcome)==='DENY')return'deny'; if(normalizeOutcome(outcome)==='EXECUTE')return'execute'; if(mode==='HISTORICAL')return'historical'; if(mode==='TERMINAL')return'terminal'; return'calm'; }}
function setEnvironmentMode(mode,outcome) {{ const env=environmentFor(mode,outcome); document.body.className=`storm-${{env}}${{document.body.classList.contains('detail-open')?' detail-open':''}}`; const labels={{calm:'CALM SPACE',live:'LIVE STORM FORMING',alive:'RESIDUAL WEATHER',escalate:'PROCEDURAL TENSION',deny:'DENY · STORM WITHDRAWING',historical:'HISTORICAL CALM',terminal:'TERMINAL CALM',execute:'MAXIMUM STABILITY'}}; document.getElementById('environmentLabel').textContent=labels[env]||'CALM SPACE'; }}
function scaleState(mode,outcome) {{ const state=normalizeOutcome(outcome); if(mode==='LIVE')return'live'; if(mode==='ALIVE')return'alive'; if(state==='ESCALATE')return'escalate'; if(['DENY','HALT','FAIL','STOP'].includes(state))return'deny'; if(state==='EXECUTE')return'execute'; if(['PASS','ALLOW'].includes(state))return'pass'; return'idle'; }}

function renderPipelineVisual(last,options={{}}) {{
  const mode=cockpitMode(last,options.mode), outcome=normalizeOutcome(options.outcome||retainedOutcome(last));
  const semantic=semanticClass(mode==='LIVE'?'LIVE':outcome); const grid=document.getElementById('pipelineVisual');
  grid.className=`cockpit-grid pipeline-mode-${{mode.toLowerCase()}} ${{semantic}}`;
  grid.querySelectorAll('.pipeline-cylinder').forEach(c=>c.className=`pipeline-cylinder ${{semantic}}`);
  grid.querySelectorAll('.ecg-slot').forEach(slot=>slot.innerHTML=ecgMarkup(mode));
  const count=Number(options.pipelineCount??last?.pipeline_count??0);
  document.getElementById('pipelineA').style.opacity=count===0?'.62':'1'; document.getElementById('pipelineB').style.opacity=count===2?'1':'.62';
  document.getElementById('pipelineAStatus').innerHTML=miniMetric('Mode',last?.pipeline_mode)+miniMetric('State',mode)+miniMetric('Convergence',last?.convergence_matched);
  document.getElementById('pipelineBStatus').innerHTML=miniMetric('Role','Validator')+miniMetric('State',count===2?mode:'WAITING')+miniMetric('Parity',last?.convergence_matched);
  const scale=document.getElementById('scaleArena'); scale.className=`scale-arena surface scale-state-${{scaleState(mode,outcome)}}`;
  const central=document.getElementById('currentSemantic'); central.className=semantic; central.textContent=mode==='LIVE'?'LIVE':outcome;
  document.getElementById('currentMeaning').textContent=mode==='LIVE'?'It is working':mode==='ALIVE'?'It is still alive':mode==='HISTORICAL'?'Finished · retained memory':mode==='TERMINAL'?'Traversal concluded':outcomeReason(outcome);
  setEnvironmentMode(mode,outcome); renderStateDeck(last,mode,outcome,options.reason);
}}

function setStateCard(id,label,note,semantic,extraClass='') {{ const card=document.getElementById(id); card.className=`state-card ${{semantic}} ${{extraClass}}`; card.querySelector('.state-value').textContent=label; card.querySelector('.state-note').textContent=note; }}
function renderStateDeck(last,mode,outcome,reason) {{
  const semantic=semanticClass(mode==='LIVE'?'LIVE':outcome);
  setStateCard('currentStateCard',mode==='LIVE'?'LIVE':outcome,mode==='LIVE'?'ECG · active traversal':mode==='ALIVE'?'Heartbeat · governed continuation possible':mode==='HISTORICAL'?'Static historical state':'No ECG',semantic,mode==='ALIVE'?'heartbeat-state':'');
  if(mode!=='LIVE'&&last?.pipeline_mode) {{ window.lastCompletedState={{outcome,semantic}}; }}
  const retained=window.lastCompletedState;
  setStateCard('lastCurrentCard',retained?.outcome||'Not available',retained?'Steady glow · no ECG':'Retained until replaced',retained?.semantic||'semantic-idle',retained?'state-glow':'state-historical');
  const alive=mode==='ALIVE'; setStateCard('aliveStateCard',alive?outcome:'None',alive?'Thump-thump · pause · recoverable':'No recoverable state present',alive?semantic:'semantic-idle',alive?'heartbeat-state':'state-historical');
  const truth=normalizeOutcome(last?.procedural_truth_status); setStateCard('truthStateCard',truth,'Internal retained status',semanticClass(truth));
  const execution=normalizeOutcome(last?.execution_result); setStateCard('outcomeStateCard',execution,'Existing Execution Gate result',semanticClass(execution));
  const relevant=['DENY','FAIL','HALT','STOP','ESCALATE','REFINE'].includes(outcome); const banner=document.getElementById('reasonBanner'); banner.className=`reason-banner ${{semantic}} ${{relevant?'visible':''}}`; banner.textContent=relevant?`Reason: ${{reason||outcomeReason(outcome)}}`:'';
}}

function renderIdentity(identity,last) {{ const entries=[['Manufacturer',identity.manufacturer],['System',identity.system_name],['Model / Version',[identity.model,identity.version].filter(Boolean).join(' / ')],['System ID',identity.unique_system_identifier],['AP-ACF',[identity.ap_acf_class,identity.ap_acf_subclass].filter(Boolean).join(' / ')],['Autonomy',`${{identity.autonomy_level??'—'}} / ceiling ${{identity.autonomy_ceiling??'—'}}`],['Scope',identity.operational_scope],['Environment',identity.operational_environment],['Licence',identity.licence_state],['Licence Authority',identity.licence_authority],['Traversal',shortValue(identity.request_fingerprint)],['Semantic',retainedOutcome(last)]]; document.getElementById('identityEnvelope').innerHTML=entries.map(([label,value])=>`<div class="identity-item"><span>${{escapeHtml(label)}}</span><strong>${{escapeHtml(value||'—')}}</strong></div>`).join(''); }}
function stageOutcome(value) {{ const normalized=normalizeOutcome(value); if(STATUS_CLASS[normalized])return normalized; if(normalized.includes('REJECT')||normalized.includes('DENY'))return'DENY'; if(normalized.includes('FAIL')||normalized.includes('INVALID'))return'FAIL'; if(normalized.includes('ALLOW')||normalized.includes('PASS')||normalized.includes('COMPLETE'))return'PASS'; return'IDLE'; }}
function renderTimelineRows(items) {{ if(!items||!items.length)return'<div class="timeline-row">No retained stage timeline is available.</div>'; return `<div class="timeline">${{items.map(item=>`<div class="timeline-row"><div class="timeline-stage">${{escapeHtml(item.stage||'runtime stage')}}</div><div class="timeline-reason">${{escapeHtml(item.reason||'No stage reason retained')}}</div>${{statusBadge(stageOutcome(item.status))}}</div>`).join('')}}</div>`; }}
function renderPipelineB(summary) {{ if(!summary)return'<div class="timeline-row">Pipeline B detail is not available.</div>'; return renderTimelineRows([{{stage:'governance',status:summary.governance_result}},{{stage:'domain',status:summary.domain_result}},{{stage:'aurion runtime',status:summary.aurion15_result}},{{stage:'execution gate',status:summary.execution_result}},{{stage:'final decision',status:summary.decision}}]); }}
function inferEventOutcome(event) {{ const p=event.payload||{{}}; return p.outcome||p.decision||p.result||p.status||(String(event.event_type||'').includes('rejected')?'DENY':'ACTIVE'); }}
function renderEvents(events) {{ if(!events.length)return reasonOutcome('No traversal events recorded','IDLE'); return `<div class="events-list">${{events.slice().reverse().map(event=>`<div class="event-row"><div class="event-meta">${{escapeHtml(event.timestamp||'')}} · ${{escapeHtml(event.event_type||'runtime event')}}</div>${{reasonOutcome((event.payload||{{}}).reason||outcomeReason(inferEventOutcome(event)),inferEventOutcome(event))}}</div>`).join('')}}</div>`; }}

async function getJson(path) {{ const res=await fetch(path,{{cache:'no-store'}}); const data=await res.json(); if(!res.ok)throw new Error(data.error||`${{res.status}} ${{res.statusText}}`); return data; }}
async function postJson(path,payload) {{ const res=await fetch(path,{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(payload)}}); const data=await res.json(); if(!res.ok)throw new Error(data.error||`${{res.status}} ${{res.statusText}}`); return data; }}
const minimumVisualBeat=ms=>new Promise(resolve=>setTimeout(resolve,ms));

function renderSnapshot(data,integrityData) {{
  const status=data.status||{{}}, operator=data.operator_summary||{{}}, integrity=data.integrity_summary||{{}}, last=data.last_state_summary||{{}}, replay=data.latest_replay_summary||{{}}, identity=data.identity_summary||{{}}, endpoint=integrityData||{{}};
  window.lastPipelineSnapshot=last; window.lastIdentitySummary=identity; window.lastCockpitData=data;
  renderPipelineVisual(last); renderIdentity(identity,last);
  document.getElementById('landingStatus').innerHTML=landingItem('Runtime',operator.runtime_mode)+landingItem('Posture',operator.binding_posture)+landingItem('Health',operator.runtime_health)+landingItem('Traversal',shortValue(operator.latest_traversal_id));
  document.getElementById('integrity').innerHTML=reasonOutcome(integrity.healthy?'Runtime integrity verified':'Runtime integrity requires attention',integrity.healthy?'PASS':'FAIL')+metric('Runtime',status.runtime_id)+metric('Security Mode',status.api_security_mode)+metric('Binding',operator.binding_posture)+metric('Integrity Contract',endpoint.status_contract_valid)+metric('Chronology',status.chronology_valid)+metric('Event Bus',status.event_bus_valid)+metric('Replay Ledger',status.replay_ledger_valid)+metric('Persistence',status.persistence_valid);
  document.getElementById('pipelineTimeline').innerHTML=`<h2>Pipeline A / Pipeline B Progression</h2>${{renderTimelineRows(last.pipeline_a_timeline)}}<h2 style="margin-top:12px">Pipeline B</h2>${{renderPipelineB(last.pipeline_b_summary)}}`;
  document.getElementById('convergenceProof').innerHTML=reasonOutcome(last.convergence_matched===true?'Pipeline parity matched':last.convergence_matched===false?'Parity mismatch detected':'No convergence record',last.convergence_matched===true?'PASS':last.convergence_matched===false?'DENY':'IDLE')+metric('Pipeline Mode',last.pipeline_mode)+metric('Convergence Hash',last.convergence_hash);
  document.getElementById('admissibility').innerHTML=reasonOutcome(last.admissibility_reason||last.execution_reason||outcomeReason(last.decision),last.decision||'IDLE')+metric('Decision',last.decision)+metric('Execution Result',last.execution_result)+metric('Verified',last.execution_verified)+metric('Failures',JSON.stringify(last.admissibility_failures||[]));
  document.getElementById('auditContinuity').innerHTML=reasonOutcome(last.audit_complete?'Audit Continuity verified':'No final audit record',last.audit_complete?'PASS':'IDLE')+metric('Audit Verified',last.audit_verified)+metric('Audit Hash',last.audit_hash)+metric('State Hash',last.state_hash)+metric('Request Fingerprint',last.request_fingerprint);
  document.getElementById('replayComparison').innerHTML=reasonOutcome(replay.matched===true?'Replay Comparison matched':replay.matched===false?'Replay mismatch':'No replay recorded',replay.matched===true?'PASS':replay.matched===false?'DENY':'IDLE')+metric('Replay Hash',replay.replay_hash)+metric('Ledger Reference',replay.ledger_reference);
  if(document.getElementById('detailPanel').classList.contains('open'))openDetail(window.activeDetail||'runtime');
}}

async function refreshAll() {{ try {{ const [data,integrityData,events]=await Promise.all([getJson('/desktop/latest'),getJson('/runtime/integrity'),getJson('/runtime/events?after=0')]); renderSnapshot(data,integrityData); document.getElementById('events').innerHTML=renderEvents(events.events||[]); document.getElementById('notice').innerHTML=''; }} catch(error) {{ renderPipelineVisual(window.lastPipelineSnapshot||{{}},{{outcome:'FAIL',reason:error.message}}); document.getElementById('notice').innerHTML=reasonOutcome(error.message,'FAIL'); }} }}
async function runApprovedDemo() {{ try {{ renderPipelineVisual(window.lastPipelineSnapshot||{{}},{{mode:'LIVE',outcome:'LIVE',pipelineCount:window.lastPipelineSnapshot?.pipeline_count||2,reason:'Canonical traversal in progress'}}); document.getElementById('responseStatus').innerHTML=reasonOutcome('Approved Desktop V1 demo traversal is in progress','ACTIVE'); const [result]=await Promise.all([postJson('/runtime/traverse',APPROVED_DEMO),minimumVisualBeat(800)]); document.getElementById('response').textContent=JSON.stringify(result,null,2); await refreshAll(); }} catch(error) {{ renderPipelineVisual(window.lastPipelineSnapshot||{{}},{{outcome:'FAIL',reason:error.message}}); document.getElementById('responseStatus').innerHTML=reasonOutcome(error.message,'FAIL'); }} }}
async function runReplay() {{ try {{ const payload=JSON.parse(JSON.stringify(APPROVED_DEMO)); payload.replay_count=2; renderPipelineVisual(window.lastPipelineSnapshot||{{}},{{mode:'LIVE',outcome:'LIVE',pipelineCount:2,reason:'Deterministic replay in progress'}}); const [result]=await Promise.all([postJson('/runtime/replay',payload),minimumVisualBeat(800)]); document.getElementById('response').textContent=JSON.stringify(result,null,2); await refreshAll(); }} catch(error) {{ renderPipelineVisual(window.lastPipelineSnapshot||{{}},{{outcome:'FAIL',reason:error.message}}); }} }}
function loadDemoRequest() {{ document.getElementById('response').textContent=JSON.stringify(APPROVED_DEMO,null,2); openDetail('response'); }}
function resetCockpit() {{ window.lastCompletedState=null; document.getElementById('response').textContent='{{}}'; document.getElementById('notice').innerHTML=''; renderPipelineVisual({{}},{{mode:'IDLE',outcome:'IDLE'}}); closeDetail(); }}

function openDetail(kind) {{
  window.activeDetail=kind; const panel=document.getElementById('detailPanel'), content=document.getElementById('detailContent'); document.getElementById('detailTitle').textContent=DETAIL_TITLES[kind]||'Operator Details';
  const sources={{runtime:()=>document.getElementById('integrity').innerHTML+document.getElementById('convergenceProof').innerHTML,audit:()=>document.getElementById('auditContinuity').innerHTML+document.getElementById('pipelineTimeline').innerHTML,truth:()=>reasonOutcome('Procedural Truth status is retained from the internal control plane',window.lastPipelineSnapshot?.procedural_truth_status||'IDLE')+metric('Status',window.lastPipelineSnapshot?.procedural_truth_status)+metric('Recoverable',window.lastPipelineSnapshot?.recoverable)+metric('Governed Re-entry',JSON.stringify(window.lastPipelineSnapshot?.governed_reentry||{{}})),bridge:()=>reasonOutcome('External bridge packages remain untrusted until Hard Entry Gate validation','IDLE')+metric('Bridge Role','Readiness metadata only')+metric('Runtime Injection','None')+metric('Execution Authority','None'),response:()=>document.getElementById('responseStatus').innerHTML+document.getElementById('response').outerHTML}};
  content.innerHTML=(sources[kind]||sources.runtime)(); panel.classList.add('open'); panel.setAttribute('aria-hidden','false'); document.body.classList.add('detail-open');
}}
function closeDetail() {{ const panel=document.getElementById('detailPanel'); panel.classList.remove('open'); panel.setAttribute('aria-hidden','true'); document.body.classList.remove('detail-open'); }}
function openSecondaryWorkspace() {{
  const win=window.open('','SBPLEX_CELESTIAL_WORKSPACE','width=1100,height=760'); if(!win)return; win.opener=null;
  const title=escapeHtml(DETAIL_TITLES[window.activeDetail]||'Operator Details'); const content=document.getElementById('detailContent').innerHTML;
  win.document.write(`<!doctype html><title>${{title}}</title><style>html,body{{min-height:100%;margin:0;color:#fff;background:#020611 radial-gradient(circle at 50% 30%,#102b58,transparent 55%);font:700 14px system-ui}}body{{padding:32px;overflow:auto}}.ring{{position:fixed;inset:6vh auto auto 50%;width:78vh;aspect-ratio:1;transform:translateX(-50%);border-radius:50%;opacity:.22;background:repeating-conic-gradient(#c7e1ff 0 .3deg,transparent .3deg 1deg);mask:radial-gradient(circle,transparent 0 47%,#000 47.2% 48%,transparent 48.2%);pointer-events:none}}main{{position:relative;z-index:2;max-width:920px;margin:auto;padding:24px;border:1px solid #456b9b;border-radius:16px;background:rgba(2,8,20,.82)}}h1{{letter-spacing:.08em}}.metric{{display:grid;grid-template-columns:1fr 1fr;padding:8px;border-bottom:1px solid #29405f}}.value{{text-align:right}}.status-badge{{display:inline-block;padding:6px 10px;border:1px solid #718096;border-radius:999px}}</style><div class="ring"></div><main><h1>${{title}}</h1><p>360° celestial workspace · degree, minute, and second markings</p>${{content}}</main>`); win.document.close();
}}
function openEndpoint(path) {{ window.open(path,'_blank','noopener,noreferrer'); }}
async function downloadJson(path,filename) {{ const data=await getJson(path); const blob=new Blob([JSON.stringify(data,null,2)],{{type:'application/json'}}); const url=URL.createObjectURL(blob); const a=document.createElement('a'); a.href=url; a.download=filename; a.click(); URL.revokeObjectURL(url); }}
refreshAll(); setInterval(refreshAll,5000);
</script>
</body>
</html>"""
