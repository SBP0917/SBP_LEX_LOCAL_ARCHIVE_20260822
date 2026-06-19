from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from external_substrates.dtn.signal_builder import build_dtn_signal_package
from external_substrates.shared.canonical_json import canonical_dumps
from external_substrates.shared.pre_context_package import build_pre_context_package, validate_pre_context_package
from external_substrates.shared.source_attestation import build_source_record
from external_substrates.skg.signal_builder import build_skg_signal_package

DEMO_DIR = Path(__file__).resolve().parent
DEMO_TIMESTAMP = "2026-06-19T00:00:00Z"
DEMO_NONCE = "phase-15-6a-read-only-demo-nonce"


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _prepare_sources(records: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [build_source_record(**dict(record)) for record in records]


def build_demo_chain(
    output_dir: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    skg_inputs = _read_json(DEMO_DIR / "sample_skg_inputs.json")
    dtn_inputs = _read_json(DEMO_DIR / "sample_dtn_inputs.json")
    skg_inputs["source_records"] = _prepare_sources(skg_inputs["source_records"])
    skg_inputs["timestamp"] = DEMO_TIMESTAMP
    skg_package = build_skg_signal_package(**skg_inputs)
    dtn_package = build_dtn_signal_package(
        request_fingerprint=skg_inputs["request_fingerprint"],
        skg_constraint_package=skg_package,
        context=dtn_inputs["context"],
        source_records=_prepare_sources(dtn_inputs["source_records"]),
        timestamp=DEMO_TIMESTAMP,
    )
    package = build_pre_context_package(
        skg_package=skg_package,
        dtn_package=dtn_package,
        nonce=DEMO_NONCE,
        timestamp=DEMO_TIMESTAMP,
    )
    if not validate_pre_context_package(package, skg_package=skg_package, dtn_package=dtn_package):
        raise RuntimeError("demo pre-context package failed validation")
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        outputs = {
            "sample_skg_package.json": skg_package,
            "sample_dtn_package.json": dtn_package,
            "sample_pre_context_package.json": package,
        }
        for name, value in outputs.items():
            (output_dir / name).write_text(canonical_dumps(value) + "\n", encoding="utf-8")
    return skg_package, dtn_package, package


def build_demo_package(output_path: Path | None = None) -> dict[str, Any]:
    skg_package, dtn_package, package = build_demo_chain()
    if output_path is not None:
        output_path.write_text(canonical_dumps(package) + "\n", encoding="utf-8")
    return package


def main() -> None:
    output = DEMO_DIR / "sample_pre_context_package.json"
    _, _, package = build_demo_chain(DEMO_DIR)
    print(canonical_dumps({"output": str(output), "digest": package["digest"], "valid": True}))


if __name__ == "__main__":
    main()
