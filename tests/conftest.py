from __future__ import annotations

import os
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TEST_STORE = REPOSITORY_ROOT / "runtime_artifacts" / "pytest_integrity_store.jsonl"
TEST_CHECKPOINT = TEST_STORE.with_suffix(TEST_STORE.suffix + ".checkpoint.json")


for artifact in (TEST_STORE, TEST_CHECKPOINT):
    artifact.unlink(missing_ok=True)

os.environ["SBP_LEX_INTEGRITY_STORE"] = "runtime_artifacts/pytest_integrity_store.jsonl"


def pytest_sessionfinish(session: object, exitstatus: int) -> None:
    for artifact in (TEST_STORE, TEST_CHECKPOINT):
        artifact.unlink(missing_ok=True)
