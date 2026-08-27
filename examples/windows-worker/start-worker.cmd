@echo off
setlocal
cd /d "%~dp0"

set "VGEN_WORKER_SETUP_ARG="
if "%~1"=="" goto vgen_worker_arguments_checked
if /I "%~1"=="-Reenroll" set "VGEN_WORKER_SETUP_ARG=-Reenroll"
if /I "%~1"=="-Repair" set "VGEN_WORKER_SETUP_ARG=-Repair"
if not defined VGEN_WORKER_SETUP_ARG goto vgen_worker_invalid_switch
:vgen_worker_arguments_checked
if not "%~2"=="" goto vgen_worker_extra_arguments

if defined VGEN_WORKER_SETUP_ARG goto vgen_worker_setup
if not exist "%LOCALAPPDATA%\VGen\supervisor\supervise-worker.ps1" goto vgen_worker_setup
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%LOCALAPPDATA%\VGen\supervisor\supervise-worker.ps1" -Mode Start
if not errorlevel 1 goto vgen_worker_supervisor_started
echo [vgen] Persistent supervision needs repair; continuing with reviewed setup.
set "VGEN_WORKER_SETUP_ARG=-Repair"

:vgen_worker_setup
echo [vgen] Starting the one-click Worker setup...
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0enroll-worker.ps1" %VGEN_WORKER_SETUP_ARG%
set "VGEN_EXIT_CODE=%ERRORLEVEL%"

if not "%VGEN_EXIT_CODE%"=="0" (
  echo.
  echo [vgen] Setup stopped with exit code %VGEN_EXIT_CODE%.
  echo [vgen] Read the message above, then run start-worker.cmd again.
)

exit /b %VGEN_EXIT_CODE%

:vgen_worker_supervisor_started
exit /b 0

:vgen_worker_invalid_switch
echo [vgen] Only the reviewed -Repair and -Reenroll switches are accepted.
exit /b 2

:vgen_worker_extra_arguments
echo [vgen] The recovery switch does not accept additional arguments.
exit /b 2
