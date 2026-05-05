@echo off
setlocal

set "ROOT_DIR=%~dp0.."

python -m venv "%ROOT_DIR%\.venv"
"%ROOT_DIR%\.venv\Scripts\python.exe" -m pip install --upgrade pip
"%ROOT_DIR%\.venv\Scripts\python.exe" -m pip install -r "%ROOT_DIR%\requirements.txt"

echo Environment ready.
pause
