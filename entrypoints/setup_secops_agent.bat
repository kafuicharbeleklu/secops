@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "ROOT_DIR=%%~fI"
set "APP_DIR=%ROOT_DIR%\templates\automation_project"
set "REQ_FILE=%APP_DIR%\requirements.txt"
set "VENV_DIR=%APP_DIR%\.venv"
set "VENV_PY=%VENV_DIR%\Scripts\python.exe"
set "BOOTSTRAP_MODE="

if not exist "%REQ_FILE%" (
    echo [ERROR] Fichier de dependances introuvable: "%REQ_FILE%"
    pause
    exit /b 1
)

where py >nul 2>&1
if not errorlevel 1 (
    set "BOOTSTRAP_MODE=py"
) else (
    where python >nul 2>&1
    if not errorlevel 1 (
        set "BOOTSTRAP_MODE=python"
    )
)

if not defined BOOTSTRAP_MODE (
    echo [ERROR] Aucun interpreteur Python trouve.
    pause
    exit /b 1
)

echo Preparation de l'environnement secops...
if "%BOOTSTRAP_MODE%"=="py" (
    call py -3 -m venv "%VENV_DIR%"
) else (
    call python -m venv "%VENV_DIR%"
)
if errorlevel 1 goto :fail

call "%VENV_PY%" -m pip install --upgrade pip
if errorlevel 1 goto :fail

call "%VENV_PY%" -m pip install -r "%REQ_FILE%"
if errorlevel 1 goto :fail

echo.
echo Environnement pret.
echo Lance ensuite: entrypoints\run_secops_agent.bat
pause
exit /b 0

:fail
echo.
echo [ERROR] La preparation de l'environnement a echoue.
pause
exit /b 1
