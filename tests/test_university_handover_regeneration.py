from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

import pytest

from sbp_lex.assurance import handover_regeneration as handover
from sbp_lex.local_trust.git_provenance import (
    generated_evidence_path_allowed,
)


def test_handover_generation_order_is_acyclic() -> None:
    labels = [
        item[0] for item in handover.LOCAL_TRUST_BUILD_COMMANDS
    ]

    assert labels.index("release_integrity") > labels.index(
        "local_trust_capstone",
    )
    assert labels.index("adversarial_harness") > labels.index(
        "release_integrity",
    )
    assert labels.index("university_dossier") > labels.index(
        "adversarial_harness",
    )


def test_required_stage_paths_are_evidence_only() -> None:
    assert handover.REQUIRED_STAGE_PATHS
    assert all(
        generated_evidence_path_allowed(path)
        for path in handover.REQUIRED_STAGE_PATHS
    )


def test_stage_root_must_be_absolute_and_outside_repository(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    with pytest.raises(
        handover.HandoverRegenerationError,
        match="stage_root_must_be_absolute",
    ):
        handover._safe_stage_root(
            repository,
            Path("relative-stage"),
            require_empty=True,
        )

    with pytest.raises(
        handover.HandoverRegenerationError,
        match="unsafe_stage_root",
    ):
        handover._safe_stage_root(
            repository,
            repository / "stage",
            require_empty=True,
        )


def test_nonportable_handover_environment_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "SBP_LEX_LOCAL_TRUST_EVIDENCE_ROOT",
        "/tmp/stale-evidence-root",
    )
    with pytest.raises(
        handover.HandoverRegenerationError,
        match="nonportable_handover_environment",
    ):
        handover._require_portable_handover_environment()


def test_archive_extraction_rejects_path_traversal(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "malicious.zip"
    with zipfile.ZipFile(archive, "w") as writer:
        writer.writestr("../outside.txt", "blocked")

    with pytest.raises(
        handover.HandoverRegenerationError,
        match="archive_path_invalid",
    ):
        handover._safe_extract(archive, tmp_path / "extract")


def test_legacy_marker_scan_fails_closed(tmp_path: Path) -> None:
    stage = tmp_path / "stage"
    output = stage / "outputs/example.json"
    package = stage / "validation_package/example.json"
    baseline = tmp_path / "approved_runtime_baselines.json"
    output.parent.mkdir(parents=True)
    package.parent.mkdir(parents=True)
    output.write_text('{"status":"current"}\n', encoding="utf-8")
    package.write_text(
        '{"signature_version":"PQC_01_PROVIDER_SIGNATURE_V1"}\n',
        encoding="utf-8",
    )
    baseline.write_text('{"status":"current"}\n', encoding="utf-8")

    with pytest.raises(
        handover.HandoverRegenerationError,
        match="legacy_assurance_evidence",
    ):
        handover._scan_legacy(stage, baseline)


def _minimal_external_package(tmp_path: Path) -> tuple[Path, Path, Path]:
    root = tmp_path / "repository"
    stage = tmp_path / "private-stage"
    outer = tmp_path / "external"
    root.mkdir()
    stage.mkdir()
    outer.mkdir()
    (outer / handover.EXTERNAL_EVIDENCE_DIRECTORY).mkdir()
    (outer / "VERIFICATION_LOGS").mkdir()
    (outer / "CONTROLLED_REVIEW_NOTICE.md").write_text(
        handover.CONTROLLED_REVIEW_LABEL + "\n",
        encoding="utf-8",
    )
    (outer / "EVALUATION_README.md").write_text(
        "Controlled evaluation.\n",
        encoding="utf-8",
    )
    (outer / "OWNER_ASSURANCE_RECORD.json").write_text(
        '{"status":"OWNER_SIDE_HANDOVER_ASSURANCE_PASSED"}\n',
        encoding="utf-8",
    )
    (outer / handover.EXTERNAL_PROPOSAL_NAME).write_bytes(
        b"%PDF-1.7\ncontrolled\n",
    )
    (outer / "SHA256SUMS.txt").write_text(
        "placeholder\n",
        encoding="utf-8",
    )
    return outer, root, stage


def test_external_package_rejects_source_material(
    tmp_path: Path,
) -> None:
    outer, root, stage = _minimal_external_package(tmp_path)
    source = (
        outer
        / handover.EXTERNAL_EVIDENCE_DIRECTORY
        / "verifier.py"
    )
    source.write_text("print('not releasable')\n", encoding="utf-8")

    with pytest.raises(
        handover.HandoverRegenerationError,
        match="external_source_material_rejected",
    ):
        handover._assert_external_package_boundary(
            outer,
            root=root,
            stage=stage,
        )


def test_external_package_rejects_repository_bundle(
    tmp_path: Path,
) -> None:
    outer, root, stage = _minimal_external_package(tmp_path)
    bundle = outer / "VERIFICATION_LOGS/history.bundle"
    bundle.write_bytes(b"repository history")

    with pytest.raises(
        handover.HandoverRegenerationError,
        match="external_source_material_rejected",
    ):
        handover._assert_external_package_boundary(
            outer,
            root=root,
            stage=stage,
        )


def test_external_log_redaction_preserves_result_and_removes_paths(
    tmp_path: Path,
) -> None:
    root = tmp_path / "canonical-repository"
    stage = tmp_path / "private-stage"
    raw = (
        f"root={root}\n"
        f"stage={stage}\n"
        "DOUBLE_TRIPLE_HANDOVER_ASSURANCE_PASS\n"
    )

    redacted = handover._redact_log_text(raw, root, stage)

    assert str(root) not in redacted
    assert str(stage) not in redacted
    assert "<CANONICAL_REPOSITORY>" in redacted
    assert "<PRIVATE_STAGING_ROOT>" in redacted
    assert "DOUBLE_TRIPLE_HANDOVER_ASSURANCE_PASS" in redacted


def test_external_log_rejects_signing_seed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("SBP_LEX_SIGNING_SECRET", "private-seed-value")

    with pytest.raises(
        handover.HandoverRegenerationError,
        match="private_signing_material",
    ):
        handover._redact_log_text(
            "private-seed-value",
            tmp_path / "repository",
            tmp_path / "stage",
        )


def test_external_readme_enforces_controlled_no_repository_release() -> None:
    text = handover._external_readme({
        "source_commit": "a" * 40,
        "evidence_commit": "b" * 40,
        "measured_baseline_identifier": "BASELINE_1",
        "trusted_signer_fingerprint": "c" * 64,
        "proposal_sha256": "d" * 64,
    })

    assert handover.CONTROLLED_REVIEW_LABEL in text
    assert "No repository" in text
    assert "Repository custody is not transferred" in text
    assert "does not claim Griffith University validation" in text


def test_proposal_requires_separately_reviewed_sha256(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    proposal = tmp_path / "controlled.pdf"
    raw = b"%PDF-1.7\n" + (b"x" * 2048)
    proposal.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()

    path, verified_digest = handover._validated_proposal_path(
        proposal,
        digest,
        root=root,
    )

    assert path == proposal
    assert verified_digest == digest
    with pytest.raises(
        handover.HandoverRegenerationError,
        match="proposal_sha256_mismatch",
    ):
        handover._validated_proposal_path(
            proposal,
            "0" * 64,
            root=root,
        )


def test_windows_finalizer_binds_all_helper_arguments_explicitly() -> None:
    script = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "finalize_university_handover.ps1"
    ).read_text(encoding="utf-8")
    helpers = (
        "Invoke-Git",
        "Get-GitText",
        "Invoke-HandoverPython",
    )

    for line in script.splitlines():
        stripped = line.strip()
        for helper in helpers:
            if (
                stripped.startswith(f"{helper} ")
                and not stripped.startswith(f"{helper} -Arguments ")
            ):
                raise AssertionError(
                    f"unsafe positional helper invocation: {stripped}",
                )
            assignment_marker = f"= {helper} "
            if (
                assignment_marker in stripped
                and f"= {helper} -Arguments " not in stripped
            ):
                raise AssertionError(
                    f"unsafe assigned helper invocation: {stripped}",
                )
