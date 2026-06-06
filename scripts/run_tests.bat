@echo off
setlocal EnableExtensions

cd /d "%~dp0\.."

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
exit /b 1

:python_found

"%PYTHON_EXE%" %PYTHON_ARGS% -c "import pytest; assert int(pytest.__version__.split('.')[0]) >= 8, 'pytest 8 or newer is required'"
if errorlevel 1 (
    echo [FAIL] pytest 8 or newer is required.
    echo Run: "%PYTHON_EXE%" %PYTHON_ARGS% -m pip install -r requirements.txt
    exit /b 1
)

echo [INFO] Running: "%PYTHON_EXE%" %PYTHON_ARGS% -m pytest %*
"%PYTHON_EXE%" %PYTHON_ARGS% -m pytest %*
if errorlevel 1 (
    echo [FAIL] Test suite failed.
    exit /b 1
)

echo [PASS] Full test suite passed.
exit /b 0
