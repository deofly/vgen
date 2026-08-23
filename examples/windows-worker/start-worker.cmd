@echo off
setlocal
cd /d "%~dp0"

echo [vgen] Starting the one-click Worker setup...
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0enroll-worker.ps1"
set "VGEN_EXIT_CODE=%ERRORLEVEL%"

if not "%VGEN_EXIT_CODE%"=="0" (
  echo.
  echo [vgen] Setup stopped with exit code %VGEN_EXIT_CODE%.
  echo [vgen] Read the message above, then run start-worker.cmd again.
  pause
)

exit /b %VGEN_EXIT_CODE%
