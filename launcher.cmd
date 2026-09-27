@echo off
rem One click: bring up the rewrite's server and the patched client.
rem Same entry point as `python -m uslocalserver.launcher`; extra args pass through
rem (e.g. `launcher.cmd --no-gui`).
setlocal
cd /d "%~dp0"
set "PYTHONPATH=%~dp0src"
set "PY=%~dp0.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"
"%PY%" -m uslocalserver.launcher %*
exit /b %errorlevel%
