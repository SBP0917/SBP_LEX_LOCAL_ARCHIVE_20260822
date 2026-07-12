from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from sbp_lex.local_trust.manifest import repository_root_from

from .assurance import DEFAULT_MANIFEST, DEFAULT_SBOM, DEFAULT_VERIFICATION, validate_bundle


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detached offline Desktop V1 artefact verifier")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--sbom", type=Path, default=DEFAULT_SBOM)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--verification", type=Path, default=DEFAULT_VERIFICATION)
    args = parser.parse_args(argv)
    root = args.root.resolve() if args.root else repository_root_from()
    result = validate_bundle(
        root,
        sbom_path=args.sbom,
        manifest_path=args.manifest,
        verification_path=args.verification,
    )
    print(result["status"])
    print("network_used=false")
    print(f"manifest_digest={result['manifest_digest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
