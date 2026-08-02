@echo off
setlocal EnableExtensions

cd /d "%~dp0\.."

rem Remove interpreter and pytest injection surfaces before Python starts.
set "PYTHONPATH="
set "PYTHONHOME="
set "PYTHONSTARTUP="
set "PYTHONINSPECT="
set "PYTHONOPTIMIZE="
set "PYTHONCASEOK="
set "PYTHONUSERBASE="
set "PYTEST_ADDOPTS="
set "PYTEST_PLUGINS="
set "PYTHONNOUSERSITE=1"
set "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1"

set "PYTHON_EXE=python"
set "PYTHON_ARGS="
"%PYTHON_EXE%" %PYTHON_ARGS% -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if not errorlevel 1 goto python_found

set "PYTHON_EXE=py"
set "PYTHON_ARGS=-3"
"%PYTHON_EXE%" %PYTHON_ARGS% -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if not errorlevel 1 goto python_found

for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
    if exist "%%~fD\python.exe" (
        "%%~fD\python.exe" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
        if not errorlevel 1 (
            set "PYTHON_EXE=%%~fD\python.exe"
            set "PYTHON_ARGS="
            goto python_found
        )
    )
)

echo [FAIL] Python 3.10 or newer was not found.
echo Install Python, then run this script again.
exit /b 1

:python_found

"%PYTHON_EXE%" %PYTHON_ARGS% -c "import pytest; raise SystemExit(0 if int(pytest.__version__.split('.')[0]) >= 8 else 1)"
if errorlevel 1 (
    echo [FAIL] Required Python dependencies are unavailable.
    echo Run: "%PYTHON_EXE%" %PYTHON_ARGS% -m pip install -r requirements.txt
    exit /b 1
)
echo [PASS] Python and required dependencies are available.

set "SBP_LEX_API_SECURITY_MODE=local"
set "SBP_LEX_REQUIRE_API_TOKEN=0"
if not defined SBP_LEX_PORT set "SBP_LEX_PORT=8000"

echo [INFO] Local/private mode: local
echo [INFO] Bind address: 127.0.0.1 only

call "%~dp0run_tests.bat"
if errorlevel 1 exit /b 1

echo [INFO] Dashboard URL: http://127.0.0.1:%SBP_LEX_PORT%/dashboard
echo [INFO] Runtime health URL: http://127.0.0.1:%SBP_LEX_PORT%/health
echo [INFO] Starting the local runtime and smoke check...

set "SMOKE_EXIT_ARG="
if "%SBP_LEX_EXIT_AFTER_CHECK%"=="1" set "SMOKE_EXIT_ARG=--exit-after-check"

"%PYTHON_EXE%" %PYTHON_ARGS% scripts\smoke_check.py --launch --host 127.0.0.1 --port %SBP_LEX_PORT% --expected-mode local %SMOKE_EXIT_ARG%
exit /b %errorlevel%
