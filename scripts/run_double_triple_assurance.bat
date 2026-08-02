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
exit /b 1

:python_found

"%PYTHON_EXE%" %PYTHON_ARGS% -m sbp_lex.assurance.double_triple %*
if errorlevel 1 exit /b 1
exit /b 0
