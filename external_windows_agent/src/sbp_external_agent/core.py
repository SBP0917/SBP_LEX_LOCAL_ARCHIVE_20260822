from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import tempfile
import webbrowser
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse
from uuid import uuid4


AGENT_NAME = "SBP External Windows Operator Agent V1"
READ_ONLY_INTERNAL_COMMANDS = {"status", "list-docs", "pending", "prepare-workspace"}
BLOCKED_EXECUTABLES = {
    "cmd.exe",
    "diskpart.exe",
    "format.com",
    "reg.exe",
    "shutdown.exe",
    "wmic.exe",
}
BLOCKED_ARGUMENT_FRAGMENTS = {
    "--force",
    "-encodedcommand",
    "remove-item",
    "del /s",
    "rmdir /s",
    "git push",
    "git commit",
    "git reset --hard",
    "git clean -fd",
    "taskkill /f",
    "net user",
    "sc delete",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class AgentConfig:
    data_dir: Path
    project_root: Path | None = None
    python_executable: str = "python"

    @classmethod
    def default(cls) -> "AgentConfig":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local"))
        return cls(data_dir=base / "SBP" / "ExternalWindowsAgentV1" / "data")

    @classmethod
    def load(cls, path: Path | None = None) -> "AgentConfig":
        config_path = path or Path(os.environ.get("SBP_EXTERNAL_AGENT_CONFIG", ""))
        if not str(config_path):
            return cls.default()
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        return cls(
            data_dir=Path(payload["data_dir"]).expanduser(),
            project_root=Path(payload["project_root"]).expanduser() if payload.get("project_root") else None,
            python_executable=str(payload.get("python_executable", "python")),
        )


@dataclass
class ActionRequest:
    request_id: str
    action_type: str
    parameters: dict[str, Any]
    risk: str
    approval_required: bool
    approved: bool
    status: str
    created_at: str
    approved_at: str | None = None
    executed_at: str | None = None


class ActionPolicy:
    """Fail-closed policy for external desktop actions."""

    def validate(self, action_type: str, parameters: dict[str, Any]) -> tuple[str, bool]:
        if action_type == "status":
            return "READ_ONLY", False
        if action_type == "open_path":
            path = Path(str(parameters.get("path", ""))).expanduser()
            if not str(path):
                raise ValueError("path is required")
            return "LOW", True
        if action_type == "open_url":
            parsed = urlparse(str(parameters.get("url", "")))
            if parsed.scheme not in {"https", "http"} or not parsed.netloc:
                raise ValueError("only valid http/https URLs are allowed")
            return "LOW", True
        if action_type == "run_process":
            executable = Path(str(parameters.get("executable", ""))).name.lower()
            arguments = [str(value) for value in parameters.get("arguments", [])]
            if not executable:
                raise ValueError("executable is required")
            if executable in BLOCKED_EXECUTABLES:
                raise PermissionError(f"blocked executable: {executable}")
            joined = " ".join([executable, *arguments]).lower()
            for fragment in BLOCKED_ARGUMENT_FRAGMENTS:
                if fragment in joined:
                    raise PermissionError(f"blocked command fragment: {fragment}")
            return "HIGH", True
        if action_type == "internal_assistant":
            command = str(parameters.get("command", ""))
            if command not in READ_ONLY_INTERNAL_COMMANDS:
                raise PermissionError("internal assistant bridge is read-only")
            return "READ_ONLY_BRIDGE", True
        raise PermissionError(f"unsupported action type: {action_type}")


class AgentStore:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        self.requests_path = self.config.data_dir / "requests.json"
        self.audit_path = self.config.data_dir / "audit.jsonl"

    def _read_requests(self) -> dict[str, dict[str, Any]]:
        if not self.requests_path.exists():
            return {}
        return json.loads(self.requests_path.read_text(encoding="utf-8"))

    def _write_requests(self, payload: dict[str, dict[str, Any]]) -> None:
        self.requests_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=self.requests_path.parent, delete=False
        ) as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            temp_name = handle.name
        os.replace(temp_name, self.requests_path)

    def save_request(self, request: ActionRequest) -> ActionRequest:
        payload = self._read_requests()
        payload[request.request_id] = asdict(request)
        self._write_requests(payload)
        return request

    def get_request(self, request_id: str) -> ActionRequest:
        payload = self._read_requests().get(request_id)
        if payload is None:
            raise KeyError(request_id)
        return ActionRequest(**payload)

    def list_requests(self, status: str | None = None) -> list[ActionRequest]:
        requests = [ActionRequest(**item) for item in self._read_requests().values()]
        if status:
            requests = [item for item in requests if item.status == status]
        return sorted(requests, key=lambda item: item.created_at)

    def append_audit(self, event: str, payload: dict[str, Any]) -> dict[str, Any]:
        previous_hash = "0" * 64
        if self.audit_path.exists():
            lines = [line for line in self.audit_path.read_text(encoding="utf-8").splitlines() if line]
            if lines:
                previous_hash = json.loads(lines[-1])["record_hash"]
        record = {
            "timestamp": utc_now(),
            "event": event,
            "payload": payload,
            "previous_hash": previous_hash,
        }
        record_hash = hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest()
        record["record_hash"] = record_hash
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(canonical_json(record) + "\n")
        return record

    def audit_tail(self, limit: int = 20) -> list[dict[str, Any]]:
        if not self.audit_path.exists():
            return []
        lines = [line for line in self.audit_path.read_text(encoding="utf-8").splitlines() if line]
        return [json.loads(line) for line in lines[-limit:]]

    def verify_audit_chain(self) -> bool:
        previous_hash = "0" * 64
        for record in self.audit_tail(limit=10_000):
            supplied_hash = record["record_hash"]
            body = {key: value for key, value in record.items() if key != "record_hash"}
            expected_hash = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
            if record["previous_hash"] != previous_hash or supplied_hash != expected_hash:
                return False
            previous_hash = supplied_hash
        return True


class ExternalAgent:
    def __init__(self, config: AgentConfig | None = None) -> None:
        self.config = config or AgentConfig.load()
        self.policy = ActionPolicy()
        self.store = AgentStore(self.config)

    def status(self) -> dict[str, Any]:
        return {
            "agent": AGENT_NAME,
            "version": "0.1.0",
            "platform": platform.platform(),
            "project_root": str(self.config.project_root) if self.config.project_root else None,
            "data_dir": str(self.config.data_dir),
            "pending_requests": len(self.store.list_requests(status="PENDING_APPROVAL")),
            "audit_chain_valid": self.store.verify_audit_chain(),
            "runtime_authority": "NONE",
            "internal_bridge": "READ_ONLY",
        }

    def plan(self, action_type: str, parameters: dict[str, Any]) -> ActionRequest:
        risk, approval_required = self.policy.validate(action_type, parameters)
        request = ActionRequest(
            request_id=uuid4().hex,
            action_type=action_type,
            parameters=parameters,
            risk=risk,
            approval_required=approval_required,
            approved=not approval_required,
            status="PENDING_APPROVAL" if approval_required else "READY",
            created_at=utc_now(),
        )
        self.store.save_request(request)
        self.store.append_audit("ACTION_PLANNED", asdict(request))
        return request

    def approve(self, request_id: str) -> ActionRequest:
        request = self.store.get_request(request_id)
        if request.status != "PENDING_APPROVAL":
            raise ValueError(f"request is not pending approval: {request.status}")
        request.approved = True
        request.approved_at = utc_now()
        request.status = "READY"
        self.store.save_request(request)
        self.store.append_audit("ACTION_APPROVED", {"request_id": request_id})
        return request

    def execute(self, request_id: str) -> dict[str, Any]:
        request = self.store.get_request(request_id)
        self.policy.validate(request.action_type, request.parameters)
        if request.approval_required and not request.approved:
            raise PermissionError("owner approval is required")
        if request.status != "READY":
            raise ValueError(f"request is not executable: {request.status}")
        result = self._execute_action(request)
        request.status = "EXECUTED"
        request.executed_at = utc_now()
        self.store.save_request(request)
        self.store.append_audit(
            "ACTION_EXECUTED",
            {"request_id": request.request_id, "action_type": request.action_type, "result": result},
        )
        return result

    def _execute_action(self, request: ActionRequest) -> dict[str, Any]:
        if request.action_type == "status":
            return self.status()
        if request.action_type == "open_path":
            path = Path(request.parameters["path"]).expanduser().resolve()
            if not path.exists():
                raise FileNotFoundError(path)
            if os.name == "nt":
                os.startfile(str(path))  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", str(path)])
            return {"opened": str(path)}
        if request.action_type == "open_url":
            opened = webbrowser.open(request.parameters["url"], new=2)
            return {"opened": bool(opened), "url": request.parameters["url"]}
        if request.action_type == "run_process":
            executable = str(request.parameters["executable"])
            arguments = [str(value) for value in request.parameters.get("arguments", [])]
            cwd = request.parameters.get("cwd")
            completed = subprocess.run(
                [executable, *arguments],
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=int(request.parameters.get("timeout_seconds", 120)),
                shell=False,
                check=False,
            )
            return {
                "returncode": completed.returncode,
                "stdout": completed.stdout[-20_000:],
                "stderr": completed.stderr[-20_000:],
            }
        if request.action_type == "internal_assistant":
            if self.config.project_root is None:
                raise RuntimeError("project_root is not configured")
            command = str(request.parameters["command"])
            arguments = [str(value) for value in request.parameters.get("arguments", [])]
            completed = subprocess.run(
                [
                    self.config.python_executable,
                    "-m",
                    "sbp_operator_assistant.app",
                    command,
                    *arguments,
                ],
                cwd=self.config.project_root,
                capture_output=True,
                text=True,
                timeout=60,
                shell=False,
                check=False,
            )
            return {
                "returncode": completed.returncode,
                "stdout": completed.stdout[-20_000:],
                "stderr": completed.stderr[-20_000:],
                "bridge": "READ_ONLY",
            }
        raise PermissionError(request.action_type)


def request_to_dict(request: ActionRequest) -> dict[str, Any]:
    return asdict(request)


def requests_to_dict(requests: Iterable[ActionRequest]) -> list[dict[str, Any]]:
    return [asdict(request) for request in requests]
