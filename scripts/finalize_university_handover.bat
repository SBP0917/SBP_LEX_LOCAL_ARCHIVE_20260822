@echo off
setlocal EnableExtensions DisableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%finalize_university_handover.ps1" %*
set "RESULT=%ERRORLEVEL%"

if not "%RESULT%"=="0" (
    echo.
    echo [FAIL] University handover finalization stopped without a completion claim.
)
exit /b %RESULT%
