from __future__ import annotations

from pathlib import Path

from sbp_pvpl.verifier import load_bundle, verify_local_proof_bundle


def write_proof_report(bundle_path: str | Path, output_path: str | Path, runtime_root: str | Path = ".") -> Path:
    bundle_file = Path(bundle_path)
    bundle = load_bundle(bundle_file)
    verification = verify_local_proof_bundle(bundle, runtime_root)
    manifest = bundle.get("proof_manifest", {})
    entries = manifest.get("evidence_entries", [])
    missing = [entry for entry in entries if entry.get("exists") is not True or entry.get("status") == "EVIDENCE_MISSING"]
    lines = [
        "# PVPL-02 Local Proof Report",
        "",
        f"Proof bundle path: `{bundle_file}`",
        "Manifest path: embedded in proof bundle",
        f"Evidence count: {len(entries)}",
        f"Present evidence count: {manifest.get('present_evidence_count')}",
        f"Missing evidence count: {manifest.get('missing_evidence_count')}",
        f"Digest verification result: `{verification['status']}`",
        f"Tamper verification result: `{verification['status']}`",
        "",
        "## Missing Evidence",
    ]
    if missing:
        lines.extend(f"- `{entry.get('evidence_id')}` at `{entry.get('path')}`" for entry in missing)
    else:
        lines.append("- None recorded.")
    lines.extend(
        [
            "",
            "## Boundary Statement",
            "PVPL is local/private, runtime-detached, publication-inactive, and non-authoritative.",
            "",
            "## Runtime Authority",
            "Runtime authority: NONE.",
            "",
            "## Reviewer Commands",
            "- `python -m sbp_pvpl.cli --verify-bundle --runtime-root . --bundle runtime_artifacts/pvpl_02/proof_bundle.json`",
            "- `python -m sbp_pvpl.cli --boundary-check --runtime-root .`",
            "",
            "## Limitations",
            "This report does not claim external publication, blockchain proof, certified proof, production proof, or external truth completeness.",
        ]
    )
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out
