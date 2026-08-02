#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

if ! command -v git >/dev/null 2>&1; then
    echo "[FAIL] Git is required for pre-Python repository verification."
    exit 1
fi

STATUS=$(git -C "$ROOT_DIR" status --porcelain=v1 --untracked-files=all)
if [ -n "$STATUS" ]; then
    echo "[FAIL] Linkage assurance requires a clean tracked and untracked repository."
    echo "$STATUS"
    exit 1
fi

sh "$SCRIPT_DIR/run_tests.sh" -q -m linkage_assurance
echo "[PASS] Startup-to-terminal linkage assurance passed."
