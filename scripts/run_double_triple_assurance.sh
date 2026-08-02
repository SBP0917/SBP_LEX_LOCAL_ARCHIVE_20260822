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

if ! "$PYTHON" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)"; then
    echo "[FAIL] Python 3.10 or newer is required."
    exit 1
fi

exec "$PYTHON" -m sbp_lex.assurance.double_triple "$@"
