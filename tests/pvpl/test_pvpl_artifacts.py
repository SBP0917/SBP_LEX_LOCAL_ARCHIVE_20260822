from sbp_pvpl.artifact import inspect_proof_artifact


def test_artifact_inspection_hashes_existing_file(tmp_path) -> None:
    path = tmp_path / "proof.txt"
    path.write_text("proof", encoding="utf-8")

    artifact = inspect_proof_artifact("proof", path)

    assert artifact.exists is True
    assert artifact.sha256 != "MISSING"
    assert artifact.size_bytes == 5


def test_artifact_inspection_reports_missing_file(tmp_path) -> None:
    artifact = inspect_proof_artifact("missing", tmp_path / "missing.txt")

    assert artifact.exists is False
    assert artifact.sha256 == "MISSING"
