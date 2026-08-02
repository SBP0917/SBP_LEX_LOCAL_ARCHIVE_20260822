from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from sbp_lex.local_trust.git_provenance import (
    GENERATED_EVIDENCE_EXACT_PATHS,
    MAX_GENERATED_EVIDENCE_DESCENDANT_COMMITS,
    generated_evidence_lineage_is_bounded,
    generated_evidence_path_allowed,
)
from sbp_lex.local_trust.critical_paths import (
    CRITICAL_FILE_PATHS,
    TRUSTED_OUTPUT_PATHS,
)
from sbp_lex.local_trust.manifest import (
    build_local_trust_manifest,
    write_local_trust_manifest,
)
from sbp_lex.local_trust.manifest_validator import (
    LOCAL_TRUST_VALID,
    validate_local_trust_manifest,
)
from sbp_lex.local_trust.paths import resolve_local_trust_path
from sbp_lex.recovery.inventory import DEFAULT_ARTIFACT_SPECS
from sbp_lex.runtime.measured_startup import measure_runtime


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ("git", *arguments),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def _commit(root: Path, relative: str, value: str) -> str:
    _write(root / relative, value)
    _git(root, "add", "--", relative)
    _git(root, "commit", "-m", f"evidence: {relative}")
    return _git(root, "rev-parse", "HEAD")


@pytest.fixture
def repository(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.name", "SBP Evidence Test")
    _git(root, "config", "user.email", "evidence-test@sbp.invalid")
    _write(root / "README.md", "source\n")
    _git(root, "add", "README.md")
    _git(root, "commit", "-m", "source baseline")
    return root, _git(root, "rev-parse", "HEAD")


@pytest.mark.parametrize(
    "path",
    [
        "outputs/local_trust_root_manifest.json",
        "outputs/recovery_critical_inventory.json",
        "outputs/r3_operational_custody_assurance.json",
        "outputs/release_integrity_bundle/RELEASE_MANIFEST.json",
        "outputs/university_validation_dossier/DOSSIER_MANIFEST.json",
        "validation_package/PACKAGE_MANIFEST.json",
    ],
)
def test_generated_evidence_allowlist_accepts_bounded_paths(path: str) -> None:
    assert generated_evidence_path_allowed(path) is True


@pytest.mark.parametrize(
    "path",
    [
        "main.py",
        "outputs/release_integrity_bundle_evil/RELEASE_MANIFEST.json",
        "validation_package_evil/PACKAGE_MANIFEST.json",
        "../validation_package/PACKAGE_MANIFEST.json",
        "validation_package\\PACKAGE_MANIFEST.json",
    ],
)
def test_generated_evidence_allowlist_rejects_source_and_lookalikes(
    path: str,
) -> None:
    assert generated_evidence_path_allowed(path) is False


def test_current_commit_is_accepted(
    repository: tuple[Path, str],
) -> None:
    root, source_commit = repository
    assert generated_evidence_lineage_is_bounded(
        root,
        source_commit,
    ) is True


def test_linear_evidence_only_chain_is_accepted(
    repository: tuple[Path, str],
) -> None:
    root, source_commit = repository
    _commit(
        root,
        "outputs/local_trust_root_manifest.json",
        '{"generation":1}\n',
    )
    _commit(
        root,
        "outputs/release_integrity_bundle/RELEASE_MANIFEST.json",
        '{"generation":2}\n',
    )
    _commit(
        root,
        "validation_package/PACKAGE_MANIFEST.json",
        '{"generation":3}\n',
    )
    assert generated_evidence_lineage_is_bounded(
        root,
        source_commit,
    ) is True


def test_source_change_in_descendant_chain_is_rejected(
    repository: tuple[Path, str],
) -> None:
    root, source_commit = repository
    _commit(
        root,
        "outputs/local_evidence_chain.json",
        '{"generation":1}\n',
    )
    _commit(root, "main.py", "authority_change = True\n")
    assert generated_evidence_lineage_is_bounded(
        root,
        source_commit,
    ) is False


def test_merge_in_descendant_chain_is_rejected(
    repository: tuple[Path, str],
) -> None:
    root, source_commit = repository
    _git(root, "checkout", "-b", "evidence-a")
    _commit(
        root,
        "outputs/local_trust_root_manifest.json",
        '{"branch":"a"}\n',
    )
    _git(root, "checkout", "main")
    _commit(
        root,
        "outputs/local_evidence_chain.json",
        '{"branch":"main"}\n',
    )
    _git(root, "merge", "--no-ff", "evidence-a", "-m", "merge evidence")
    assert generated_evidence_lineage_is_bounded(
        root,
        source_commit,
    ) is False


def test_unbounded_evidence_commit_chain_is_rejected(
    repository: tuple[Path, str],
) -> None:
    root, source_commit = repository
    relative = "outputs/local_evidence_chain.json"
    for index in range(MAX_GENERATED_EVIDENCE_DESCENDANT_COMMITS + 1):
        _commit(root, relative, f'{{"generation":{index}}}\n')
    assert generated_evidence_lineage_is_bounded(
        root,
        source_commit,
    ) is False


def test_unknown_or_nonancestor_commit_is_rejected(
    repository: tuple[Path, str],
) -> None:
    root, _ = repository
    assert generated_evidence_lineage_is_bounded(
        root,
        "0" * 40,
    ) is False
    assert generated_evidence_lineage_is_bounded(
        root,
        "not-a-commit",
    ) is False


def test_manifest_remains_valid_after_its_bounded_recording_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(
        "SBP_LEX_LOCAL_TRUST_EVIDENCE_ROOT",
        raising=False,
    )
    clone = tmp_path / "clone"
    _git(
        tmp_path,
        "clone",
        "--no-local",
        "--quiet",
        str(REPOSITORY_ROOT),
        str(clone),
    )
    _git(clone, "config", "user.name", "SBP Evidence Test")
    _git(clone, "config", "user.email", "evidence-test@sbp.invalid")
    manifest = build_local_trust_manifest(clone)
    assert manifest["working_tree_clean"] is True
    output = "outputs/local_trust_root_manifest.json"
    write_local_trust_manifest(
        manifest,
        output,
        repository_root=clone,
    )
    _git(clone, "add", "--", output)
    _git(clone, "commit", "-m", "evidence: record local trust manifest")

    validation = validate_local_trust_manifest(
        manifest,
        repository_root=clone,
        current_validation=True,
        clean_required=True,
    )
    assert validation == {
        "local_trust_status": LOCAL_TRUST_VALID,
        "validation_failures": [],
    }


def test_all_exact_evidence_paths_are_portable() -> None:
    assert GENERATED_EVIDENCE_EXACT_PATHS
    assert all(
        generated_evidence_path_allowed(path)
        for path in GENERATED_EVIDENCE_EXACT_PATHS
    )


def test_generated_evidence_dependency_direction_is_acyclic() -> None:
    local_trust_inputs = (
        set(CRITICAL_FILE_PATHS)
        | set(TRUSTED_OUTPUT_PATHS)
    )
    recovery_outputs = {
        "outputs/recovery_critical_inventory.json",
        "outputs/r1_recovery_drill.json",
    }
    recovery_inputs = {
        spec.source_path for spec in DEFAULT_ARTIFACT_SPECS
    }
    local_trust_outputs = {
        "outputs/local_trust_root_manifest.json",
        "outputs/local_execution_environment_trust_envelope.json",
        "outputs/local_evidence_chain.json",
        "outputs/local_constitutional_gates.json",
        "outputs/local_toolchain_guard.json",
        "outputs/local_trust_25_year_capstone.json",
        "outputs/release_integrity_bundle/RELEASE_MANIFEST.json",
    }

    assert recovery_outputs.isdisjoint(local_trust_inputs)
    assert local_trust_outputs <= recovery_inputs
    assert (
        "outputs/phq_formal_architecture_assurance.json"
        in local_trust_inputs & recovery_inputs
    )


def test_formal_evidence_redirect_uses_staging_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv(
        "SBP_LEX_LOCAL_TRUST_EVIDENCE_ROOT",
        str(evidence_root),
    )
    assert resolve_local_trust_path(
        tmp_path / "repository",
        "outputs/phq_formal_architecture_assurance.json",
    ) == (
        evidence_root
        / "outputs/phq_formal_architecture_assurance.json"
    ).resolve()


def test_evidence_staging_path_does_not_change_runtime_identity() -> None:
    first_environment = dict(os.environ)
    second_environment = dict(os.environ)
    first_environment["SBP_LEX_LOCAL_TRUST_EVIDENCE_ROOT"] = (
        "/tmp/evidence-stage-a"
    )
    second_environment["SBP_LEX_LOCAL_TRUST_EVIDENCE_ROOT"] = (
        "/tmp/evidence-stage-b"
    )

    first = measure_runtime(
        REPOSITORY_ROOT,
        environ=first_environment,
    )
    second = measure_runtime(
        REPOSITORY_ROOT,
        environ=second_environment,
    )

    assert first["measurement_digest"] == second["measurement_digest"]
    assert first["category_digests"] == second["category_digests"]
