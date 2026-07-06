from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
import json


@dataclass(frozen=True)
class RemoteActionLogEntry:
    timestamp: str
    session_id: str
    deployment_id: str
    action_name: str
    result: str
    owner_visible: bool = True


def append_remote_action_log(log_path: str | Path, entry: RemoteActionLogEntry) -> None:
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(asdict(entry), sort_keys=True) + "\n")


def build_remote_log_entry(
    session_id: str,
    deployment_id: str,
    action_name: str,
    result: str,
) -> RemoteActionLogEntry:
    return RemoteActionLogEntry(
        timestamp=datetime.now(UTC).isoformat(),
        session_id=session_id,
        deployment_id=deployment_id,
        action_name=action_name,
        result=result,
    )
