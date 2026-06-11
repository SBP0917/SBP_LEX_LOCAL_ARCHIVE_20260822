# Local Operator Guide

## Runtime posture

Desktop V1 is local-first, private operator-facing, observability-oriented, and
non-authoritative over execution. The canonical runtime remains authoritative.
The default server binds to `127.0.0.1`.

## Direct launch

Extract the downloaded ZIP, open the extracted folder containing `main.py`,
click the File Explorer address bar, type `cmd`, and press Enter.

Install dependencies if required:

```text
python -m pip install -r requirements.txt
```

Start the runtime:

```text
python main.py server 8000
```

Open:

```text
http://127.0.0.1:8000/dashboard
```

Keep the command window open. Stop the runtime with `Ctrl+C`.

Optional Windows launch script:

```text
scripts\run_desktop_runtime.bat
```

## Verification commands

```text
python main.py
python main.py replay
python -m pytest -q
scripts\run_tests.bat
```

## Troubleshooting

### Browser says it cannot connect

Confirm the runtime command is still running and the black command window has
not been closed. Start it again with `python main.py server 8000`.

### Python not found

Install Python 3.10 or newer and enable the installer option that adds Python to
PATH. Open a new command window afterward.

### Pytest not found or dependencies unavailable

Run:

```text
python -m pip install -r requirements.txt
```

If internet access is restricted, dependency installation may need to be
performed later from a permitted network.

### Pip displays warnings

Read the final line. Upgrade notices and PATH warnings do not necessarily mean
installation failed. Confirm with `python -m pytest -q`.

### Port 8000 is already in use

Use the alternate port:

```text
python main.py server 8773
```

Then open:

```text
http://127.0.0.1:8773/dashboard
```

### OneDrive or synchronized-folder concerns

Extract the release into a normal local folder when possible. Synchronization
can lock cache or runtime output files while tests are running.

### Firewall warning

Keep access restricted to private/local networks. Desktop V1 is intended for
localhost operation and should not be exposed publicly.

### Dashboard route does not load

Use the exact `/dashboard` path and confirm the port matches the server command.
Check `http://127.0.0.1:8000/health` to confirm the runtime is active.

### Background image does not load

Refresh the dashboard. Confirm this exact local route returns the image:

```text
http://127.0.0.1:8000/desktop/static/images/sbp_lex_background.png
```

Do not rename or move files inside `sbp_lex/desktop/static/images/`.

## Preserved V1 constraints

- Canonical runtime remains the execution authority.
- Dashboard remains observability-only.
- Dual Adaptive Deterministic Pipelines remain active.
- Execution gating remains fail-closed.
- Audit, replay, and chronology integrity remain mandatory.
- No nodes, cloud services, or distributed runtime topology are introduced.
