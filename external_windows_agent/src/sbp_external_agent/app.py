from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence

from sbp_external_agent.core import AgentConfig, ExternalAgent, request_to_dict, requests_to_dict


def _print(payload: Any) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _config(path: str | None) -> AgentConfig:
    return AgentConfig.load(Path(path)) if path else AgentConfig.load()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SBP External Windows Operator Agent V1")
    parser.add_argument("--config", help="Path to agent configuration JSON")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("status")
    commands.add_parser("pending")

    open_path = commands.add_parser("plan-open")
    open_path.add_argument("path")

    open_url = commands.add_parser("plan-url")
    open_url.add_argument("url")

    run = commands.add_parser("plan-run")
    run.add_argument("executable")
    run.add_argument("arguments", nargs=argparse.REMAINDER)
    run.add_argument("--cwd")
    run.add_argument("--timeout-seconds", type=int, default=120)

    internal = commands.add_parser("plan-internal")
    internal.add_argument("internal_command")
    internal.add_argument("arguments", nargs=argparse.REMAINDER)

    approve = commands.add_parser("approve")
    approve.add_argument("request_id")

    execute = commands.add_parser("execute")
    execute.add_argument("request_id")

    audit = commands.add_parser("audit-tail")
    audit.add_argument("--limit", type=int, default=20)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    agent = ExternalAgent(_config(args.config))

    if args.command == "status":
        _print(agent.status())
    elif args.command == "pending":
        _print({"requests": requests_to_dict(agent.store.list_requests(status="PENDING_APPROVAL"))})
    elif args.command == "plan-open":
        _print(request_to_dict(agent.plan("open_path", {"path": args.path})))
    elif args.command == "plan-url":
        _print(request_to_dict(agent.plan("open_url", {"url": args.url})))
    elif args.command == "plan-run":
        _print(
            request_to_dict(
                agent.plan(
                    "run_process",
                    {
                        "executable": args.executable,
                        "arguments": args.arguments,
                        "cwd": args.cwd,
                        "timeout_seconds": args.timeout_seconds,
                    },
                )
            )
        )
    elif args.command == "plan-internal":
        _print(
            request_to_dict(
                agent.plan(
                    "internal_assistant",
                    {"command": args.internal_command, "arguments": args.arguments},
                )
            )
        )
    elif args.command == "approve":
        _print(request_to_dict(agent.approve(args.request_id)))
    elif args.command == "execute":
        _print(agent.execute(args.request_id))
    elif args.command == "audit-tail":
        _print({"records": agent.store.audit_tail(args.limit)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
