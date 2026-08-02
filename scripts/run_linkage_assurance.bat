@echo off
setlocal EnableExtensions

pushd "%~dp0\.."
if errorlevel 1 (
    echo [FAIL] Repository root is unavailable.
    exit /b 1
)

git rev-parse --is-inside-work-tree >nul 2>&1
if errorlevel 1 (
    popd
    echo [FAIL] Git is required for pre-Python repository verification.
    exit /b 1
)

git status --porcelain=v1 --untracked-files=all >nul 2>&1
if errorlevel 1 (
    popd
    echo [FAIL] Git repository status could not be verified.
    exit /b 1
)

set "DIRTY_REPOSITORY="
for /f "usebackq delims=" %%L in (`git status --porcelain^=v1 --untracked-files^=all`) do set "DIRTY_REPOSITORY=1"
if defined DIRTY_REPOSITORY (
    git status --short --untracked-files=all
    popd
    echo [FAIL] Linkage assurance requires a clean tracked and untracked repository.
    exit /b 1
)
popd

call "%~dp0run_tests.bat" -q -m linkage_assurance
if errorlevel 1 (
    echo [FAIL] Startup-to-terminal linkage assurance failed.
    exit /b 1
)

echo [PASS] Startup-to-terminal linkage assurance passed.
exit /b 0
