from __future__ import annotations

from pathlib import Path

from external_substrates.demo.build_demo_pre_context_package import build_demo_package
from external_substrates.shared.pre_context_package import validate_pre_context_package


def test_demo_package_builds_valid_signed_digest_bound_output(tmp_path: Path) -> None:
    output = tmp_path / "sample.json"
    package = build_demo_package(output)
    assert output.exists()
    assert validate_pre_context_package(package)
    assert package["digest"] and package["signature"]


def test_demo_has_no_execution_or_governance_authority() -> None:
    rendered = repr(build_demo_package())
    assert "execution_permission" not in rendered
    assert "governance_result" not in rendered


def test_demo_does_not_mutate_runtime_artifacts() -> None:
    runtime_file = Path("runtime_artifacts/integrity_store.jsonl")
    before = runtime_file.read_bytes() if runtime_file.exists() else None
    build_demo_package()
    after = runtime_file.read_bytes() if runtime_file.exists() else None
    assert after == before

