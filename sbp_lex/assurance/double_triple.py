from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence


LEGACY_ASSURANCE_MARKERS = (
    b"PQC_01_PROVIDER_SIGNATURE_V1",
    b"DETERMINISTIC_PLACEHOLDER",
)
INJECTION_ENVIRONMENT_NAMES = (
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "PYTHONINSPECT",
    "PYTHONOPTIMIZE",
    "PYTHONCASEOK",
    "PYTHONUSERBASE",
    "PYTEST_ADDOPTS",
    "PYTEST_PLUGINS",
)
TEST_TRUST_ENVIRONMENT_NAMES = (
    "SBP_LEX_SIGNING_SECRET",
    "SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY",
    "SBP_LEX_EXPECTED_SIGNER_FINGERPRINT",
    "SBP_LEX_APPROVED_RUNTIME_BASELINE_PATH",
    "SBP_LEX_MEASURED_STARTUP_STATE_ROOT",
    "SBP_LEX_LOCAL_TRUST_EVIDENCE_ROOT",
)
EVIDENCE_SCAN_ROOTS = ("outputs", "validation_package")
EVIDENCE_SCAN_FILES = ("sbp_lex/runtime/approved_runtime_baselines.json",)
REQUIRED_HANDOVER_PATHS = (
    "outputs/local_trust_root_manifest.json",
    "outputs/local_evidence_chain.json",
    "outputs/r2_software_bill_of_materials.json",
    "outputs/r2_deterministic_build_manifest.json",
    "outputs/r2_offline_verification.json",
    "outputs/r3_operational_custody_assurance.json",
    "validation_package/PACKAGE_MANIFEST.json",
    "sbp_lex/runtime/approved_runtime_baselines.json",
)
EXPECTED_FINGERPRINT_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class DoubleTripleError(RuntimeError):
    pass


@dataclass(frozen=True)
class AssuranceFinding:
    path: str
    reason: str


def sanitized_subprocess_environment(
    source: Mapping[str, str] | None = None,
    *,
    for_tests: bool = False,
    pycache_prefix: str | None = None,
) -> dict[str, str]:
    environment = dict(os.environ if source is None else source)
    for name in INJECTION_ENVIRONMENT_NAMES:
        environment.pop(name, None)
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    if for_tests:
        for name in TEST_TRUST_ENVIRONMENT_NAMES:
            environment.pop(name, None)
    if pycache_prefix is not None:
        environment["PYTHONPYCACHEPREFIX"] = pycache_prefix
    return environment


def source_test_plan(
    python_executable: str = sys.executable,
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    return (
        (
            "complete_suite",
            (python_executable, "-m", "pytest", "-q"),
        ),
        *tuple(
            (
                f"linkage_assurance_{run_number}",
                (
                    python_executable,
                    "-m",
                    "pytest",
                    "-q",
                    "-m",
                    "linkage_assurance",
                ),
            )
            for run_number in range(1, 4)
        ),
    )


def evidence_command_plan(
    root: Path,
    expected_fingerprint: str,
    python_executable: str = sys.executable,
) -> tuple[tuple[str, tuple[str, ...], str], ...]:
    python = python_executable
    return (
        (
            "measured_startup",
            (python, "-m", "sbp_lex.runtime.measured_startup", "validate"),
            "MEASURED_STARTUP_APPROVED",
        ),
        (
            "local_trust",
            (
                python,
                "-m",
                "sbp_lex.local_trust.manifest",
                "validate",
                "--clean-required",
            ),
            "LOCAL_TRUST_VALID",
        ),
        (
            "evidence_chain",
            (
                python,
                "-m",
                "sbp_lex.local_trust.evidence_chain",
                "validate",
                "--clean-required",
            ),
            "EVIDENCE_CHAIN_VALID",
        ),
        (
            "evidence_compare",
            (
                python,
                "-m",
                "sbp_lex.local_trust.evidence_chain",
                "compare",
            ),
            "changed_evidence_items=0",
        ),
        (
            "constitutional_gates",
            (
                python,
                "-m",
                "sbp_lex.local_trust.constitutional_gates",
                "validate",
                "--clean-required",
            ),
            "CONSTITUTIONAL_GATES_PASS",
        ),
        (
            "toolchain_guard",
            (
                python,
                "-m",
                "sbp_lex.local_trust.toolchain_guard",
                "validate",
                "--clean-required",
            ),
            "TOOLCHAIN_GUARD_PASS",
        ),
        (
            "release_integrity",
            (
                python,
                "-m",
                "sbp_lex.local_trust.release_integrity",
                "validate",
                "--clean-required",
            ),
            "RELEASE_INTEGRITY_PASS",
        ),
        (
            "capstone",
            (
                python,
                "-m",
                "sbp_lex.local_trust.local_trust_capstone",
                "validate",
                "--clean-required",
            ),
            "LOCAL_TRUST_CAPSTONE_PASS",
        ),
        (
            "r2_offline",
            (
                python,
                "-m",
                "sbp_lex.supply_chain.offline_verify",
                "--root",
                str(root),
            ),
            "R2_SUPPLY_CHAIN_ASSURANCE_PASS",
        ),
        (
            "r3_custody",
            (
                python,
                "-m",
                "sbp_lex.custody.assurance",
                "validate",
            ),
            "R3_CUSTODY_ASSURANCE_PASS",
        ),
        (
            "r4_repository_bound_package",
            (
                python,
                "-m",
                "sbp_lex.ivvp.verifier",
                "validation_package",
                "--repository-root",
                str(root),
                "--expected-signer-fingerprint",
                expected_fingerprint,
            ),
            "R4_IVVP_VALID",
        ),
    )


def _git(
    root: Path,
    *arguments: str,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            ("git", *arguments),
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            env=sanitized_subprocess_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DoubleTripleError(f"git_unavailable:{arguments[0]}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise DoubleTripleError(
            f"git_command_failed:{arguments[0]}:{detail}"
        )
    return completed


def require_clean_repository(root: Path) -> None:
    status = _git(
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    ).stdout.strip()
    if status:
        raise DoubleTripleError(f"repository_not_clean:{status}")


def tracked_files(root: Path) -> tuple[Path, ...]:
    completed = _git(root, "ls-files", "-z")
    return tuple(
        root / relative
        for relative in completed.stdout.split("\0")
        if relative
    )


def _strict_json(path: Path) -> object:
    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate_key:{key}")
            value[key] = item
        return value

    def reject_constant(value: str) -> object:
        raise ValueError(f"non_finite_number:{value}")

    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise DoubleTripleError(
            f"schema_document_invalid:{path.as_posix()}:{exc}"
        ) from exc


def validate_schema_documents(
    root: Path,
    paths: Iterable[Path] | None = None,
) -> int:
    candidates = tuple(paths) if paths is not None else tuple(
        path
        for path in tracked_files(root)
        if path.name.endswith(".schema.json")
    )
    if not candidates:
        raise DoubleTripleError("schema_inventory_empty")
    for path in candidates:
        if path.is_symlink() or not path.is_file():
            raise DoubleTripleError(
                f"schema_document_unsafe:{path.as_posix()}"
            )
        value = _strict_json(path)
        if not isinstance(value, dict):
            raise DoubleTripleError(
                f"schema_document_not_object:{path.as_posix()}"
            )
    return len(candidates)


def _call_name(call: ast.Call) -> str:
    node: ast.AST = call.func
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def scan_python_safety(
    paths: Iterable[Path],
    *,
    root: Path,
) -> tuple[AssuranceFinding, ...]:
    findings: list[AssuranceFinding] = []
    for path in paths:
        relative = path.relative_to(root).as_posix()
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=relative)
        except (OSError, UnicodeError, SyntaxError) as exc:
            findings.append(
                AssuranceFinding(relative, f"python_parse_failed:{exc}")
            )
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                findings.append(
                    AssuranceFinding(
                        relative,
                        f"runtime_assert:{node.lineno}",
                    )
                )
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            if name in {
                "eval",
                "exec",
                "os.system",
                "pickle.load",
                "pickle.loads",
                "yaml.load",
            }:
                findings.append(
                    AssuranceFinding(
                        relative,
                        f"dangerous_call:{name}:{node.lineno}",
                    )
                )
            if name in {
                "subprocess.run",
                "subprocess.call",
                "subprocess.Popen",
                "subprocess.check_call",
                "subprocess.check_output",
            } and any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            ):
                findings.append(
                    AssuranceFinding(
                        relative,
                        f"shell_execution:{node.lineno}",
                    )
                )
    return tuple(findings)


def production_python_paths(root: Path) -> tuple[Path, ...]:
    return tuple(
        path
        for path in tracked_files(root)
        if path.suffix == ".py"
        and "tests" not in path.relative_to(root).parts
        and "fixtures" not in path.relative_to(root).parts
    )


def _bounded_files(root: Path) -> tuple[Path, ...]:
    files: list[Path] = []
    for relative in EVIDENCE_SCAN_ROOTS:
        boundary = root / relative
        if not boundary.exists():
            continue
        if boundary.is_symlink() or not boundary.is_dir():
            raise DoubleTripleError(
                f"evidence_boundary_unsafe:{relative}"
            )
        for directory, names, filenames in os.walk(
            boundary, followlinks=False,
        ):
            current = Path(directory)
            for name in tuple(names):
                child = current / name
                if child.is_symlink():
                    raise DoubleTripleError(
                        "evidence_symlink:"
                        f"{child.relative_to(root).as_posix()}"
                    )
            for name in filenames:
                child = current / name
                if child.is_symlink() or not child.is_file():
                    raise DoubleTripleError(
                        "evidence_file_unsafe:"
                        f"{child.relative_to(root).as_posix()}"
                    )
                files.append(child)
    for relative in EVIDENCE_SCAN_FILES:
        path = root / relative
        if path.exists():
            if path.is_symlink() or not path.is_file():
                raise DoubleTripleError(
                    f"evidence_file_unsafe:{relative}"
                )
            files.append(path)
    return tuple(files)


def scan_legacy_evidence(root: Path) -> tuple[AssuranceFinding, ...]:
    findings: list[AssuranceFinding] = []
    for path in _bounded_files(root):
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise DoubleTripleError(
                "evidence_read_failed:"
                f"{path.relative_to(root).as_posix()}"
            ) from exc
        for marker in LEGACY_ASSURANCE_MARKERS:
            if marker in raw:
                findings.append(
                    AssuranceFinding(
                        path.relative_to(root).as_posix(),
                        marker.decode("ascii"),
                    )
                )
    return tuple(findings)


def validate_trust_configuration(
    environment: Mapping[str, str] | None = None,
) -> str:
    source = os.environ if environment is None else environment
    encoded = source.get("SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY", "")
    expected = source.get("SBP_LEX_EXPECTED_SIGNER_FINGERPRINT", "")
    if not encoded:
        raise DoubleTripleError("trusted_public_key_missing")
    if EXPECTED_FINGERPRINT_PATTERN.fullmatch(expected) is None:
        raise DoubleTripleError("expected_signer_fingerprint_invalid")
    try:
        public_key = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise DoubleTripleError("trusted_public_key_invalid") from exc
    if not public_key:
        raise DoubleTripleError("trusted_public_key_invalid")
    actual = hashlib.sha256(public_key).hexdigest()
    if actual != expected:
        raise DoubleTripleError("trusted_signer_fingerprint_mismatch")
    return expected


def require_handover_surface(root: Path) -> None:
    missing = [
        relative
        for relative in REQUIRED_HANDOVER_PATHS
        if not (root / relative).is_file()
        or (root / relative).is_symlink()
    ]
    if missing:
        raise DoubleTripleError(
            "handover_evidence_missing:" + ",".join(missing)
        )


def _run(
    root: Path,
    label: str,
    command: Sequence[str],
    *,
    expected_output: str | None = None,
    for_tests: bool = False,
    timeout: int = 900,
    pycache_prefix: str | None = None,
) -> None:
    print(f"[RUN] {label}")
    try:
        completed = subprocess.run(
            tuple(command),
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            env=sanitized_subprocess_environment(
                for_tests=for_tests,
                pycache_prefix=pycache_prefix,
            ),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DoubleTripleError(f"command_unavailable:{label}") from exc
    if completed.stdout:
        print(completed.stdout, end="")
    if completed.stderr:
        print(completed.stderr, end="", file=sys.stderr)
    if completed.returncode != 0:
        raise DoubleTripleError(
            f"command_failed:{label}:exit_{completed.returncode}"
        )
    combined = completed.stdout + completed.stderr
    if expected_output is not None and expected_output not in combined:
        raise DoubleTripleError(
            f"expected_output_missing:{label}:{expected_output}"
        )
    print(f"[PASS] {label}")


def run_source_assurance(root: Path) -> None:
    require_clean_repository(root)
    _git(root, "diff", "--check")
    _git(root, "fsck", "--strict", "--no-reflogs", timeout=300)
    schema_count = validate_schema_documents(root)
    print(f"[PASS] strict_schema_documents={schema_count}")
    python_paths = production_python_paths(root)
    findings = scan_python_safety(python_paths, root=root)
    if findings:
        detail = ",".join(
            f"{item.path}:{item.reason}" for item in findings
        )
        raise DoubleTripleError(f"static_python_safety_failed:{detail}")
    print(f"[PASS] static_python_files={len(python_paths)}")
    _run(
        root,
        "dependency_integrity",
        (sys.executable, "-m", "pip", "check"),
        expected_output="No broken requirements found",
        for_tests=True,
        timeout=300,
    )
    with tempfile.TemporaryDirectory(
        prefix="sbp-lex-double-triple-pycache-",
    ) as pycache:
        compile_targets = tuple(
            name
            for name in (
                "main.py",
                "sbp_lex",
                "external_substrates",
                "sbp_operator_assistant",
                "scripts",
            )
            if (root / name).exists()
        )
        _run(
            root,
            "bytecode_compile",
            (
                sys.executable,
                "-m",
                "compileall",
                "-q",
                *compile_targets,
            ),
            for_tests=True,
            timeout=300,
            pycache_prefix=pycache,
        )
    for label, command in source_test_plan():
        require_clean_repository(root)
        _run(
            root,
            label,
            command,
            for_tests=True,
            timeout=1200 if label == "complete_suite" else 600,
        )
    require_clean_repository(root)
    print("[PASS] DOUBLE_TRIPLE_SOURCE_ASSURANCE_PASS")


def run_evidence_assurance(root: Path) -> None:
    require_clean_repository(root)
    require_handover_surface(root)
    legacy = scan_legacy_evidence(root)
    if legacy:
        detail = ",".join(
            f"{item.path}:{item.reason}" for item in legacy
        )
        raise DoubleTripleError(
            f"legacy_assurance_evidence:{detail}"
        )
    print("[PASS] legacy_assurance_markers=0")
    expected_fingerprint = validate_trust_configuration()
    print(
        "[PASS] trusted_signer_fingerprint="
        f"{expected_fingerprint}"
    )
    for label, command, expected in evidence_command_plan(
        root, expected_fingerprint,
    ):
        require_clean_repository(root)
        _run(
            root,
            label,
            command,
            expected_output=expected,
            timeout=600,
        )
    require_clean_repository(root)
    print("[PASS] DOUBLE_TRIPLE_HANDOVER_ASSURANCE_PASS")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run the fail-closed SBP-LEX Double Triple pre-handover "
            "assurance gate."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=("handover", "source", "evidence"),
        default="handover",
        help=(
            "handover runs source plus production evidence gates; "
            "source and evidence are diagnostic partial modes only"
        ),
    )
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[2]
    try:
        if args.mode in {"handover", "source"}:
            run_source_assurance(root)
        if args.mode in {"handover", "evidence"}:
            run_evidence_assurance(root)
    except DoubleTripleError as exc:
        print(f"[FAIL] DOUBLE_TRIPLE_ASSURANCE_FAILED:{exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
