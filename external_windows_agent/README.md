# SBP External Windows Operator Agent V1

This package is the separate external Windows control layer. It is not the internal `sbp_operator_assistant` package and it has no SBP-LEX runtime, governance, execution, token, audit, SKG, DTN, Domain, Aurion, or pipeline authority.

## Implemented in this increment

- Local Windows installation outside the repository under `%LOCALAPPDATA%\SBP\ExternalWindowsAgentV1`.
- Action planning and persistent pending-action queue.
- Separate owner approval before applications, URLs, paths, commands, or internal-assistant requests execute.
- Process execution with argument arrays and `shell=False`.
- Blocklist for destructive or privilege-changing command patterns.
- Hash-chained JSONL audit trail.
- Read-only bridge to these internal SBP Operator Assistant commands only:
  - `status`
  - `list-docs`
  - `pending`
  - `prepare-workspace`

## Install on Windows

From the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\external_windows_agent\install.ps1
```

The default project root is:

```text
C:\Users\LeighMC\Documents\Codex\2026-07-11\SBP_LEX_DUAL_V6_DESKTOP_V1
```

## Start and inspect

```powershell
& "$env:LOCALAPPDATA\SBP\ExternalWindowsAgentV1\SBP-External-Agent.cmd" status
```

## Plan, approve, execute

```powershell
$agent = "$env:LOCALAPPDATA\SBP\ExternalWindowsAgentV1\SBP-External-Agent.cmd"
& $agent plan-open "C:\Users\LeighMC\Documents\Codex\2026-07-11\SBP_LEX_DUAL_V6_DESKTOP_V1"
& $agent pending
& $agent approve <REQUEST_ID>
& $agent execute <REQUEST_ID>
```

Read the internal project assistant without giving the external agent authority to change its records:

```powershell
& $agent plan-internal status
& $agent approve <REQUEST_ID>
& $agent execute <REQUEST_ID>
```

## Deferred

- AI model/provider connection.
- Browser-page interpretation and computer vision.
- Mouse and keyboard automation.
- Email and calendar connectors.
- Autonomous approval.
- Any SBP-LEX runtime-authority capability.
