# Pilot Package Install Guide Gap Register

Draft status: gaps that require final package details.

| Gap | Why it matters | Owner/action needed | Blocks final guide | Notes |
|---|---|---|---|---|
| Missing final package filename | Reviewers need to know the exact file to open. | Provide final filename after assembly. | YES | Final package not created yet. |
| Missing final package folder structure | Guides need exact folder names and screenshots. | Confirm final extracted folder structure. | YES | Current repo structure is known, final package structure is not. |
| Missing final hash/checksum | Reviewers need integrity verification. | Generate final package digest during final assembly. | YES | No package hash exists yet. |
| Missing final dependency list confirmation | Dependencies may change before final assembly. | Confirm `requirements.txt` at final assembly. | YES | Current file lists `pytest` and `cryptography>=49.0.0`. |
| Missing screenshots | Plain-English guide needs visual help. | Capture approved screenshots after final package exists. | NO | Placeholders exist in draft guide. |
| Missing final install command confirmation | Final package may use repo Python, bundled Python, or venv. | Confirm final command in assembly task. | YES | Current draft uses `python -m pip install -r requirements.txt`. |
| Missing final smoke-test command confirmation | Final guide needs exact basic command. | Confirm final smoke command. | YES | Current repo command is `python main.py`. |
| Missing final replay command confirmation | Final guide needs exact replay command. | Confirm final replay command. | YES | Current repo command is `python main.py replay`. |
| Missing platform-specific instructions | Non-Windows instructions may be needed. | Owner decides supported platforms. | NO | Current guide is Windows/PowerShell oriented. |
| Missing known-errors list from final package test | Final guide should reflect real final-package errors. | Add errors observed during final assembly validation. | YES | Draft includes current common examples only. |
| Missing final full-test command policy | Full pytest can be long and may need `--basetemp`. | Owner/reviewer confirms final command. | YES | Current optional command is `python -m pytest -q`. |
| Missing final support contact path | Operators need to know who to ask for help. | Owner supplies support contact or escalation route. | NO | Draft says stop and ask for help. |
| Missing final inclusion/redaction decisions | Source/test inclusion may need owner decision. | Approve raw, redacted, or summary-only content. | YES | Current register marks sensitive source as HUMAN_REVIEW. |
