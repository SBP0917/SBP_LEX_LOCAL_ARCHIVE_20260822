# Plain-English Pilot Operator Guide Draft

Draft status: beginner guide draft only.

The final pilot package has not been created yet. Some folder names, screenshots,
and final copy-and-paste commands must be confirmed later.

## What This Package Is

This package is planned as a local folder that lets someone review and test the
SBP-LEX Desktop V1 validation work on one computer.

Local means it runs on your computer.

Private means it is not a public website or public service.

Desktop V1 means this is a bounded desktop validation version.

## What This Package Is Not

This is not:

1. A production system.
2. A public release.
3. A cloud system.
4. A distributed network.
5. A node or quorum system.
6. A final canon document set.
7. A deployment installer.
8. A package that changes runtime authority.

## What You Need Before Starting

You will need:

1. The final pilot package folder, once it exists.
2. A Windows computer.
3. Python, or an approved Python/runtime folder.
4. The exact commands from the final guide.
5. Permission from the repository owner or reviewer lead.

Stop and ask for help if you do not know whether Python is installed.

## How To Unzip Or Open The Folder Later

Placeholder until the final package exists:

1. Find the final pilot package file.
2. Right-click it.
3. Choose the normal Windows option to extract or open it.
4. Put the extracted folder somewhere easy to find, such as Documents.
5. Do not rename files inside the folder unless told to.

Screenshot placeholder: final package file.

Screenshot placeholder: extracted folder.

## How To Recognise The Correct Folder

The correct folder should contain files or folders like:

1. `main.py`
2. `requirements.txt`
3. `reports`
4. `docs`
5. `fixtures`
6. `tests`

Stop and ask for help if you cannot see `main.py`.

## What Python Means

Python is the program that runs this project.

You do not need to understand Python code to follow this guide.

You only need to copy and paste approved commands.

## What A Terminal Or Command Window Means

A terminal, command window, or PowerShell is a text window where you type or
paste commands.

It may look plain and technical. That is normal.

You should only paste commands from the approved guide.

## How To Open A Terminal In The Project Folder

One common Windows method:

1. Open the project folder.
2. Click in the folder address bar at the top.
3. Type `powershell`.
4. Press Enter.

A blue or black command window may open.

Screenshot placeholder: folder address bar.

Screenshot placeholder: PowerShell window.

Stop and ask for help if the command window opens in the wrong folder.

## How To Copy And Paste A Command

1. Highlight the command in the guide.
2. Press Ctrl+C to copy it.
3. Click inside PowerShell.
4. Press Ctrl+V to paste it.
5. Press Enter.

Only copy one command at a time.

## Basic System Check

From the project folder, the current basic command is:

```powershell
python main.py
```

You may see text that looks like JSON. JSON is a structured text output with
curly brackets.

It worked if the command finishes and shows fields such as `decision`,
`execution_result`, or `convergence_matched`.

Stop and ask for help if you see a long red error.

## Replay Check

Replay means running the same controlled check again to see if the result still
matches.

The current replay command is:

```powershell
python main.py replay
```

It worked if the command finishes and says the replay matched.

## Running Tests Only If Instructed

Tests are automatic checks.

Do not run tests unless a technical reviewer tells you to.

If instructed, a common focused test command is:

```powershell
python -m pytest -q tests/test_phase19a_bounded_translator.py
```

It worked if it says tests passed.

Stop and ask for help if it says failed, error, or cannot find pytest.

## How To Find Reports

Reports are in the `reports` folder.

Important reports may include:

1. `PHASE19A_OWNER_CLOSURE_01_REPORT.md`
2. `PHASE19A_IMPLEMENTATION_01_REPORT.md`
3. `PHASE19A_IMPLEMENTATION_02_REPORT.md`
4. `PHASE19B_EVIDENCE_PACKAGE_01_REPORT.md`
5. `PHASE19B_OWNER_REVIEW_01_REPORT.md`
6. `PHASE19B_PILOT_ASSEMBLY_PREP_01_REPORT.md`

Files ending in `.md` are text documents.

## How To Know If It Worked

It probably worked if:

1. The command finished.
2. There was no long red error.
3. The output mentions success, pass, matched, or JSON fields.

It may not have worked if:

1. The command says Python was not found.
2. The command says pytest was not found.
3. The command says a module was not found.
4. The command says failed or error.

## Common Error Examples

`python is not recognized`

Meaning: Windows cannot find Python.

What to do: stop and ask for help.

`No module named pytest`

Meaning: the test tool is missing.

What to do: ask a technical reviewer before installing anything.

`No module named sbp_lex`

Meaning: you may be in the wrong folder.

What to do: check you opened PowerShell inside the project folder.

`Permission denied`

Meaning: Windows blocked access to a folder or file.

What to do: stop and ask for help.

## Do Not Touch

Do not delete or edit:

1. `main.py`
2. `sbp_lex`
3. `tests`
4. `fixtures`
5. `reports`
6. `docs`
7. `requirements.txt`

Do not use `baselines` as current evidence.

Do not change files because an error appeared.

## When To Stop And Ask For Help

Stop and ask for help if:

1. You see a long red error.
2. You cannot find `main.py`.
3. Python is not found.
4. You are asked to edit code.
5. You are asked to delete files.
6. You are asked to upload anything publicly.
7. You are asked to run a command not in the guide.
8. The folder does not match the screenshots.

## Simple Glossary

Python: the program that runs the project.

Terminal or PowerShell: the text window where commands are pasted.

Command: a line of text you paste and run.

Folder: a place on the computer that contains files.

Report: a text document explaining what was done.

Test: an automatic check.

Replay: running the same check again to see if it still matches.

Desktop V1: the local/private desktop validation version.

Runtime: the part that runs the controlled sample process.

Pilot package: the future review folder. It has not been created yet.

## Final Pilot Package Placeholder Notes

These details must be added later:

1. Final package filename.
2. Final folder name.
3. Final checksum or hash.
4. Final screenshots.
5. Final exact install command.
6. Final known error list.
