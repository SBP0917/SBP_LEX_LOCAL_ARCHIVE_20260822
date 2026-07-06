from __future__ import annotations

import argparse
import json

from sbp_oda.main import run_oda_health_check


def main() -> int:
    parser = argparse.ArgumentParser(description="SBP-LEX ODA-V1 support assistant")
    parser.add_argument("--runtime-root", default=".", help="Path to runtime repository root")
    parser.add_argument("--health", action="store_true", help="Run ODA health check")
    args = parser.parse_args()

    if args.health:
        print(json.dumps(run_oda_health_check(args.runtime_root), indent=2, sort_keys=True))
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
