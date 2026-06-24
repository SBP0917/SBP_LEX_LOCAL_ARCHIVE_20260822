from __future__ import annotations

import argparse
import json
from typing import Sequence

from sbp_operator_assistant.file_organiser import register_document, list_documents
from sbp_operator_assistant.project_memory import (
    add_pending_task,
    get_project_status,
    list_pending_tasks,
    set_current_phase,
)
from sbp_operator_assistant.workspace_manager import prepare_workspace


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SBP Operator Assistant V1")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("status")

    add_doc = subparsers.add_parser("add-doc")
    add_doc.add_argument("path")

    subparsers.add_parser("list-docs")

    set_phase = subparsers.add_parser("set-phase")
    set_phase.add_argument("phase")

    pending = subparsers.add_parser("pending")
    pending.add_argument("task", nargs="?")
    pending.add_argument("--phase")

    prep = subparsers.add_parser("prepare-workspace")
    prep.add_argument("name")

    args = parser.parse_args(argv)
    if args.command == "status":
        _print(get_project_status())
    elif args.command == "add-doc":
        _print(register_document(args.path))
    elif args.command == "list-docs":
        _print({"documents": list_documents()})
    elif args.command == "set-phase":
        _print(set_current_phase(args.phase))
    elif args.command == "pending":
        if args.task:
            _print(add_pending_task(args.task, args.phase))
        else:
            _print({"pending_tasks": list_pending_tasks()})
    elif args.command == "prepare-workspace":
        _print(prepare_workspace(args.name))
    return 0


def _print(payload: object) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())

