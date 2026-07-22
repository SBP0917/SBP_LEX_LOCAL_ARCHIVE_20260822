from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from sbp_external_agent.core import AgentConfig, ExternalAgent


def agent(tmp_path: Path) -> ExternalAgent:
    return ExternalAgent(AgentConfig(data_dir=tmp_path / "data", python_executable=sys.executable))


def test_status_is_read_only_and_declares_no_runtime_authority(tmp_path: Path) -> None:
    value = agent(tmp_path).status()
    assert value["runtime_authority"] == "NONE"
    assert value["internal_bridge"] == "READ_ONLY"
    assert value["audit_chain_valid"] is True


def test_planned_action_cannot_execute_without_approval(tmp_path: Path) -> None:
    current = agent(tmp_path)
    request = current.plan("run_process", {"executable": sys.executable, "arguments": ["-c", "print('ok')"]})
    with pytest.raises(PermissionError):
        current.execute(request.request_id)


def test_approved_process_executes_without_shell(tmp_path: Path) -> None:
    current = agent(tmp_path)
    request = current.plan("run_process", {"executable": sys.executable, "arguments": ["-c", "print('ok')"]})
    current.approve(request.request_id)
    result = current.execute(request.request_id)
    assert result["returncode"] == 0
    assert result["stdout"].strip() == "ok"


def test_dangerous_command_is_blocked_at_plan_time(tmp_path: Path) -> None:
    current = agent(tmp_path)
    with pytest.raises(PermissionError):
        current.plan("run_process", {"executable": "git", "arguments": ["reset", "--hard"]})


def test_internal_bridge_rejects_mutating_command(tmp_path: Path) -> None:
    current = agent(tmp_path)
    with pytest.raises(PermissionError):
        current.plan("internal_assistant", {"command": "set-phase", "arguments": ["X"]})


def test_audit_records_form_valid_hash_chain(tmp_path: Path) -> None:
    current = agent(tmp_path)
    request = current.plan("open_url", {"url": "https://example.com"})
    current.approve(request.request_id)
    assert current.store.verify_audit_chain() is True

    records = current.store.audit_tail()
    assert len(records) == 2
    assert records[1]["previous_hash"] == records[0]["record_hash"]


def test_requests_are_human_readable_json(tmp_path: Path) -> None:
    current = agent(tmp_path)
    current.plan("open_url", {"url": "https://example.com"})
    text = current.store.requests_path.read_text(encoding="utf-8")
    assert json.loads(text)
    assert "\n  " in text
