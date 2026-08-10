#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$ROOT_DIR"

# Remove interpreter and pytest injection surfaces before Python starts.
unset PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONINSPECT PYTHONOPTIMIZE
unset PYTHONCASEOK PYTHONUSERBASE PYTEST_ADDOPTS PYTEST_PLUGINS
export PYTHONNOUSERSITE=1
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1

if command -v python3 >/dev/null 2>&1; then
    PYTHON=${PYTHON:-python3}
elif command -v python >/dev/null 2>&1; then
    PYTHON=${PYTHON:-python}
else
    echo "[FAIL] Python 3.10 or newer was not found."
    exit 1
fi

if ! "$PYTHON" -c "import sys, pytest; raise SystemExit(0 if sys.version_info >= (3, 10) and int(pytest.__version__.split('.')[0]) >= 8 else 1)"; then
    echo "[FAIL] Required Python dependencies are unavailable."
    echo "Run: $PYTHON -m pip install -r requirements.txt"
    exit 1
fi
echo "[PASS] Python and required dependencies are available."

export SBP_LEX_API_SECURITY_MODE=local
export SBP_LEX_REQUIRE_API_TOKEN=0
SBP_LEX_PORT=${SBP_LEX_PORT:-8000}
export SBP_LEX_PORT
SBP_VIDEO_PORT=${SBP_VIDEO_PORT:-8765}
export SBP_VIDEO_PORT

echo "[INFO] Local/private mode: local"
echo "[INFO] Bind address: 127.0.0.1 only"

"$SCRIPT_DIR/run_tests.sh"

echo "[INFO] Dashboard URL: http://127.0.0.1:$SBP_LEX_PORT/dashboard"
echo "[INFO] Video Studio URL: http://127.0.0.1:$SBP_LEX_PORT/desktop/video-studio"
echo "[INFO] Runtime health URL: http://127.0.0.1:$SBP_LEX_PORT/health"
echo "[INFO] Starting the local runtime and smoke check..."

SMOKE_EXIT_ARG=
if [ "${SBP_LEX_EXIT_AFTER_CHECK:-0}" = "1" ]; then
    SMOKE_EXIT_ARG=--exit-after-check
fi

exec "$PYTHON" scripts/smoke_check.py \
    --launch \
    --host 127.0.0.1 \
    --port "$SBP_LEX_PORT" \
    --video-port "$SBP_VIDEO_PORT" \
    --expected-mode local \
    $SMOKE_EXIT_ARG
