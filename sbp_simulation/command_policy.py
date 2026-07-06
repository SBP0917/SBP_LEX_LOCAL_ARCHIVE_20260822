from __future__ import annotations


ALLOWED_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("python", "main.py"),
    ("python", "main.py", "replay"),
    ("python", "-m", "sbp_pvpl.cli", "--runtime-root", ".", "--summary"),
    ("python", "-m", "sbp_oda.cli", "--health", "--runtime-root", "."),
    ("python", "-m", "sbp_oda.cli", "--diagnostics", "--runtime-root", "."),
)

BLOCKED_TOKENS = {
    "git clean",
    "git reset",
    "git checkout",
    "git commit",
    "git push",
    "delete",
    "remove",
    "rmdir",
    "rm ",
    "del ",
    "cloud",
    "blockchain",
    "ledger",
    "publish",
    "curl",
    "wget",
}


def normalise_command(command: list[str]) -> tuple[str, ...]:
    if command and command[0].lower().endswith("python.exe"):
        return ("python", *command[1:])
    return tuple(command)


def command_allowed(command: list[str] | None) -> tuple[bool, str]:
    if not command:
        return False, "missing_command"
    joined = " ".join(command).lower()
    if any(token in joined for token in BLOCKED_TOKENS):
        return False, "blocked_token"
    if any(ch in joined for ch in ("&", "|", ";", ">", "<")):
        return False, "shell_operator_blocked"
    if normalise_command(command) not in ALLOWED_COMMANDS:
        return False, "command_not_allowlisted"
    return True, "command_allowlisted"
