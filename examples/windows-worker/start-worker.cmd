@echo off
setlocal
cd /d "%~dp0"

set "VGEN_WORKER_REENROLL_ARG="
if not "%~1"=="" (
  if /I not "%~1"=="-Reenroll" (
    echo [vgen] Only the reviewed -Reenroll recovery switch is accepted.
    exit /b 2
  )
  if not "%~2"=="" (
    echo [vgen] -Reenroll does not accept additional arguments.
    exit /b 2
  )
  set "VGEN_WORKER_REENROLL_ARG=-Reenroll"
)

echo [vgen] Starting the one-click Worker setup...
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0enroll-worker.ps1" %VGEN_WORKER_REENROLL_ARG%
set "VGEN_EXIT_CODE=%ERRORLEVEL%"

if not "%VGEN_EXIT_CODE%"=="0" (
  echo.
  echo [vgen] Setup stopped with exit code %VGEN_EXIT_CODE%.
  echo [vgen] Read the message above, then run start-worker.cmd again.
  pause
)

exit /b %VGEN_EXIT_CODE%
