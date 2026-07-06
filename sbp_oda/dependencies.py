from __future__ import annotations

from importlib import metadata
from pathlib import Path


def parse_requirements(runtime_root: str | Path = ".") -> dict[str, object]:
    requirements_path = Path(runtime_root) / "requirements.txt"
    if not requirements_path.exists():
        return {"requirements_path": str(requirements_path), "exists": False, "requirements": [], "cryptography_requirement": None}
    lines = [
        line.strip()
        for line in requirements_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    crypto = next((line for line in lines if line.lower().startswith("cryptography")), None)
    return {
        "requirements_path": str(requirements_path),
        "exists": True,
        "requirements": lines,
        "cryptography_requirement": crypto,
    }


def inspect_dependency_and_pqc_provider(runtime_root: str | Path = ".") -> dict[str, object]:
    requirements = parse_requirements(runtime_root)
    try:
        cryptography_version = metadata.version("cryptography")
    except metadata.PackageNotFoundError:
        cryptography_version = None

    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: F401

        mldsa_import_available = True
    except Exception:
        mldsa_import_available = False

    if cryptography_version is None:
        provider_status = "PQC_PROVIDER_UNKNOWN"
    elif mldsa_import_available:
        provider_status = "PQC_PROVIDER_AVAILABLE"
    else:
        provider_status = "PQC_PROVIDER_UNAVAILABLE"

    return {
        "requirements": requirements,
        "cryptography_requirement": requirements.get("cryptography_requirement"),
        "cryptography_installed_version": cryptography_version,
        "mldsa_import_available": mldsa_import_available,
        "provider_status": provider_status,
        "certification_claimed": False,
        "post_quantum_compliance_claimed": False,
    }
