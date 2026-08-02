from __future__ import annotations

import os
from pathlib import Path


LOCAL_TRUST_EVIDENCE_ROOT_ENVIRONMENT_NAME = "SBP_LEX_LOCAL_TRUST_EVIDENCE_ROOT"
_REDIRECTED_OUTPUT_NAMES = frozenset({
    "local_trust_root_manifest.json",
    "local_execution_environment_trust_envelope.json",
    "local_evidence_chain.json",
    "local_trust_regression_matrix.json",
    "local_constitutional_gates.json",
    "local_toolchain_guard.json",
    "local_trust_25_year_capstone.json",
    "adversarial_local_trust_negative_harness.json",
    "phq_formal_architecture_assurance.json",
})
_REDIRECTED_OUTPUT_DIRECTORIES = frozenset({
    "release_integrity_bundle",
    "university_validation_dossier",
    "local_trust_temp",
})


def _is_link_or_junction(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or (
        callable(is_junction) and is_junction()
    )


def _reject_link_components(path: Path, *, reason: str) -> None:
    cursor = path
    while cursor != cursor.parent:
        if _is_link_or_junction(cursor):
            raise ValueError(reason)
        cursor = cursor.parent


def resolve_local_trust_path(
    repository_root: Path,
    path: Path | str,
) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        _reject_link_components(
            candidate,
            reason="local_trust_absolute_path_symlink",
        )
        return candidate.resolve(strict=False)
    redirect_output = (
        len(candidate.parts) >= 2
        and candidate.parts[0] == "outputs"
        and (
            candidate.parts[1] in _REDIRECTED_OUTPUT_NAMES
            or candidate.parts[1] in _REDIRECTED_OUTPUT_DIRECTORIES
        )
    )
    if redirect_output:
        configured = os.environ.get(LOCAL_TRUST_EVIDENCE_ROOT_ENVIRONMENT_NAME)
        if configured:
            evidence_root = Path(configured)
            if not evidence_root.is_absolute():
                raise ValueError("local_trust_evidence_root_must_be_absolute")
            _reject_link_components(
                evidence_root,
                reason="local_trust_evidence_root_symlink",
            )
            resolved_root = evidence_root.resolve(strict=False)
            unresolved = resolved_root / candidate
            _reject_link_components(
                unresolved,
                reason="local_trust_evidence_path_symlink",
            )
            resolved = unresolved.resolve(strict=False)
            if not resolved.is_relative_to(resolved_root):
                raise ValueError("local_trust_evidence_path_escape")
            return resolved
    resolved_root = repository_root.resolve(strict=False)
    unresolved = resolved_root / candidate
    _reject_link_components(
        unresolved,
        reason="local_trust_repository_path_symlink",
    )
    resolved = unresolved.resolve(strict=False)
    if not resolved.is_relative_to(resolved_root):
        raise ValueError("local_trust_repository_path_escape")
    return resolved
