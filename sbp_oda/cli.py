from __future__ import annotations

import argparse
import json

from sbp_oda.main import (
    run_oda_boundary_check,
    run_oda_diagnostics,
    run_oda_health_check,
    run_oda_maintenance_plan,
    run_oda_query,
    run_oda_support_bundle,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="SBP-LEX ODA-V1 support assistant")
    parser.add_argument("--runtime-root", default=".", help="Path to runtime repository root")
    parser.add_argument("--health", action="store_true", help="Run ODA health check")
    parser.add_argument("--diagnostics", action="store_true", help="Run evidence-grade ODA diagnostics")
    parser.add_argument("--support-bundle", action="store_true", help="Write ODA local support bundle")
    parser.add_argument("--out", default="runtime_artifacts/oda_02/support_bundle.json", help="Support bundle output path")
    parser.add_argument("--query", help="Run deterministic local ODA query")
    parser.add_argument("--boundary-check", action="store_true", help="Run static ODA boundary check")
    parser.add_argument("--maintenance-plan", help="Create a local maintenance work-package recommendation")
    args = parser.parse_args()

    if args.health:
        print(json.dumps(run_oda_health_check(args.runtime_root), indent=2, sort_keys=True))
        return 0
    if args.diagnostics:
        print(json.dumps(run_oda_diagnostics(args.runtime_root), indent=2, sort_keys=True))
        return 0
    if args.support_bundle:
        print(json.dumps(run_oda_support_bundle(args.runtime_root, args.out), indent=2, sort_keys=True))
        return 0
    if args.query:
        print(json.dumps(run_oda_query(args.query, args.runtime_root), indent=2, sort_keys=True))
        return 0
    if args.boundary_check:
        print(json.dumps(run_oda_boundary_check(args.runtime_root), indent=2, sort_keys=True))
        return 0
    if args.maintenance_plan:
        print(json.dumps(run_oda_maintenance_plan(args.maintenance_plan, args.runtime_root), indent=2, sort_keys=True))
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
