from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from external_substrates.demo.build_demo_pre_context_package import DEMO_DIR, build_demo_chain
from external_substrates.shared.bridge_manifest import build_bridge_manifest, validate_bridge_manifest
from external_substrates.shared.bridge_validator import (
    validate_bridge_package_chain,
    validate_dtn_package_for_bridge,
    validate_pre_context_package_for_bridge,
    validate_skg_package_for_bridge,
)
from external_substrates.shared.canonical_json import canonical_dumps

PACKAGE_FILES = (
    "sample_skg_package.json",
    "sample_dtn_package.json",
    "sample_pre_context_package.json",
)


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_or_build_demo_chain(package_dir: Path = DEMO_DIR) -> tuple[dict, dict, dict]:
    paths = [package_dir / name for name in PACKAGE_FILES]
    if not all(path.exists() for path in paths):
        return build_demo_chain(package_dir)
    return tuple(_read_json(path) for path in paths)  # type: ignore[return-value]


def validate_demo_bridge(
    *,
    package_dir: Path = DEMO_DIR,
    manifest_path: Path | None = None,
) -> tuple[str, dict[str, Any]]:
    skg_package, dtn_package, pre_context_package = load_or_build_demo_chain(package_dir)
    skg_valid, _ = validate_skg_package_for_bridge(skg_package)
    dtn_valid, _ = validate_dtn_package_for_bridge(dtn_package, skg_package)
    pre_valid, _ = validate_pre_context_package_for_bridge(pre_context_package)
    chain_valid, _ = validate_bridge_package_chain(skg_package, dtn_package, pre_context_package)
    manifest = build_bridge_manifest(skg_package, dtn_package, pre_context_package)
    manifest_valid, _ = validate_bridge_manifest(manifest)
    status = "BRIDGE_READY" if all((skg_valid, dtn_valid, pre_valid, chain_valid, manifest_valid)) else "BRIDGE_REJECTED"
    destination = manifest_path or package_dir / "sample_bridge_manifest.json"
    package_root = package_dir.resolve()
    destination = destination.resolve()
    if not destination.is_relative_to(package_root):
        raise ValueError("manifest_path_outside_package_dir")
    destination.write_text(canonical_dumps(manifest) + "\n", encoding="utf-8")
    return status, manifest


def main() -> None:
    status, _ = validate_demo_bridge()
    print(status)


if __name__ == "__main__":
    main()
