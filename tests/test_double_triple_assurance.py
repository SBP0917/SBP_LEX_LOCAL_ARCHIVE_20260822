from __future__ import annotations

import base64
import hashlib
import subprocess
from pathlib import Path

import pytest

from sbp_lex.assurance.double_triple import (
    COMPLETE_SUITE_TIMEOUT_SECONDS,
    DoubleTripleError,
    _run,
    evidence_command_plan,
    sanitized_subprocess_environment,
    scan_legacy_evidence,
    scan_python_safety,
    source_test_plan,
    validate_schema_documents,
    validate_trust_configuration,
)


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.linkage_assurance


def test_source_plan_is_one_complete_run_plus_three_fresh_linkage_runs():
    plan = source_test_plan("python")
    assert [label for label, _ in plan] == [
        "complete_suite",
        "linkage_assurance_1",
        "linkage_assurance_2",
        "linkage_assurance_3",
    ]
    assert sum("linkage_assurance" not in command for _, command in plan) == 1
    assert sum(command[-1] == "linkage_assurance" for _, command in plan) == 3
    assert COMPLETE_SUITE_TIMEOUT_SECONDS == 7200


def test_run_reports_timeout_distinctly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(("python", "-m", "pytest"), 7)

    monkeypatch.setattr(
        "sbp_lex.assurance.double_triple.subprocess.run", _timeout,
    )
    with pytest.raises(DoubleTripleError, match="command_timeout:fixture:7"):
        _run(tmp_path, "fixture", ("python", "-m", "pytest"), timeout=7)


def test_subprocess_environment_removes_injection_and_test_trust():
    environment = sanitized_subprocess_environment(
        {
            "PYTHONPATH": "attacker",
            "PYTHONOPTIMIZE": "2",
            "PYTEST_ADDOPTS": "--ignore=tests",
            "PYTEST_PLUGINS": "attacker",
            "SBP_LEX_SIGNING_SECRET": "production-secret",
            "SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY": "production-public",
            "SBP_LEX_EXPECTED_SIGNER_FINGERPRINT": "a" * 64,
            "SAFE_VALUE": "preserved",
        },
        for_tests=True,
    )
    assert "PYTHONPATH" not in environment
    assert "PYTHONOPTIMIZE" not in environment
    assert "PYTEST_ADDOPTS" not in environment
    assert "PYTEST_PLUGINS" not in environment
    assert "SBP_LEX_SIGNING_SECRET" not in environment
    assert "SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY" not in environment
    assert "SBP_LEX_EXPECTED_SIGNER_FINGERPRINT" not in environment
    assert environment["SAFE_VALUE"] == "preserved"
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"


def test_legacy_evidence_scan_is_bounded_and_reports_every_marker(tmp_path):
    (tmp_path / "outputs").mkdir()
    (tmp_path / "validation_package").mkdir()
    (tmp_path / "sbp_lex/runtime").mkdir(parents=True)
    (tmp_path / "outside.py").write_text(
        "PQC_01_PROVIDER_SIGNATURE_V1", encoding="utf-8",
    )
    (tmp_path / "outputs/one.json").write_text(
        "PQC_01_PROVIDER_SIGNATURE_V1", encoding="utf-8",
    )
    (tmp_path / "validation_package/two.json").write_text(
        "DETERMINISTIC_PLACEHOLDER", encoding="utf-8",
    )
    (tmp_path / "sbp_lex/runtime/approved_runtime_baselines.json").write_text(
        "PQC_01_PROVIDER_SIGNATURE_V2", encoding="utf-8",
    )

    findings = scan_legacy_evidence(tmp_path)

    assert {(item.path, item.reason) for item in findings} == {
        (
            "outputs/one.json",
            "PQC_01_PROVIDER_SIGNATURE_V1",
        ),
        (
            "validation_package/two.json",
            "DETERMINISTIC_PLACEHOLDER",
        ),
    }


def test_legacy_evidence_scan_rejects_symlinked_members(tmp_path):
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    try:
        (outputs / "link.json").symlink_to(target)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(DoubleTripleError, match="evidence_file_unsafe"):
        scan_legacy_evidence(tmp_path)


def test_static_scan_rejects_runtime_assert_dynamic_execution_and_shell(tmp_path):
    source = tmp_path / "unsafe.py"
    source.write_text(
        "import subprocess\n"
        "assert True\n"
        "eval('1')\n"
        "subprocess.run(['x'], shell=True)\n",
        encoding="utf-8",
    )
    findings = scan_python_safety((source,), root=tmp_path)
    reasons = {item.reason.split(":", 1)[0] for item in findings}
    assert reasons == {
        "runtime_assert",
        "dangerous_call",
        "shell_execution",
    }


def test_schema_scan_rejects_duplicate_json_keys(tmp_path):
    schema = tmp_path / "duplicate.schema.json"
    schema.write_text(
        '{"type":"object","type":"array"}\n', encoding="utf-8",
    )
    with pytest.raises(DoubleTripleError, match="duplicate_key"):
        validate_schema_documents(tmp_path, (schema,))


def test_trust_configuration_requires_out_of_band_fingerprint_match():
    public_key = b"test-public-key"
    encoded = base64.b64encode(public_key).decode("ascii")
    expected = hashlib.sha256(public_key).hexdigest()
    assert validate_trust_configuration({
        "SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY": encoded,
        "SBP_LEX_EXPECTED_SIGNER_FINGERPRINT": expected,
    }) == expected
    with pytest.raises(
        DoubleTripleError, match="trusted_signer_fingerprint_mismatch",
    ):
        validate_trust_configuration({
            "SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY": encoded,
            "SBP_LEX_EXPECTED_SIGNER_FINGERPRINT": "0" * 64,
        })


def test_evidence_plan_ends_with_repository_bound_r4_verification(tmp_path):
    fingerprint = "a" * 64
    plan = evidence_command_plan(tmp_path, fingerprint, "python")
    labels = [label for label, _, _ in plan]
    assert labels == [
        "measured_startup",
        "local_trust",
        "evidence_chain",
        "evidence_compare",
        "constitutional_gates",
        "toolchain_guard",
        "release_integrity",
        "capstone",
        "r2_offline",
        "r3_custody",
        "r4_repository_bound_package",
    ]
    final = plan[-1][1]
    assert "--repository-root" in final
    assert str(tmp_path) in final
    assert "--expected-signer-fingerprint" in final
    assert fingerprint in final


def test_all_launchers_use_explicit_exit_checks_and_clear_injection():
    launchers = (
        "scripts/run_tests.bat",
        "scripts/run_tests.sh",
        "scripts/run_desktop_runtime.bat",
        "scripts/run_desktop_runtime.sh",
        "scripts/run_double_triple_assurance.bat",
        "scripts/run_double_triple_assurance.sh",
    )
    for relative in launchers:
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert "assert " not in text
        assert "PYTHONOPTIMIZE" in text
        assert "PYTEST_ADDOPTS" in text
        assert "PYTEST_PLUGINS" in text
        assert "PYTEST_DISABLE_PLUGIN_AUTOLOAD" in text
        assert "raise SystemExit" in text
    for suffix in ("bat", "sh"):
        text = (
            ROOT / f"scripts/run_double_triple_assurance.{suffix}"
        ).read_text(encoding="utf-8")
        assert "sbp_lex.assurance.double_triple" in text
