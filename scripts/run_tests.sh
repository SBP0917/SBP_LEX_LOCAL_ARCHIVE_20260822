#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$ROOT_DIR"

if command -v python3 >/dev/null 2>&1; then
    PYTHON=${PYTHON:-python3}
elif command -v python >/dev/null 2>&1; then
    PYTHON=${PYTHON:-python}
else
    echo "[FAIL] Python 3.10 or newer was not found."
    exit 1
fi

if ! "$PYTHON" -c "import sys; assert sys.version_info >= (3, 10), 'Python 3.10 or newer is required'; import pytest; assert int(pytest.__version__.split('.')[0]) >= 8, 'pytest 8 or newer is required'"; then
    echo "[FAIL] pytest 8 or newer is required."
    echo "Run: $PYTHON -m pip install -r requirements.txt"
    exit 1
fi

echo "[INFO] Running: $PYTHON -m pytest $*"
if "$PYTHON" -m pytest "$@"; then
    echo "[PASS] Full test suite passed."
else
    echo "[FAIL] Test suite failed."
    exit 1
fi
