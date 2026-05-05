@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "ROOT_DIR=%%~fI"
set "APP_DIR=%ROOT_DIR%\templates\automation_project"
set "MAIN_PY=%APP_DIR%\main.py"
set "VENV_PY=%APP_DIR%\.venv\Scripts\python.exe"
set "PYTHON_MODE="

if not exist "%MAIN_PY%" (
    echo [ERROR] Entree introuvable: "%MAIN_PY%"
    pause
    exit /b 1
)

if exist "%VENV_PY%" (
    set "PYTHON_MODE=venv"
) else (
    where python >nul 2>&1
    if not errorlevel 1 (
        set "PYTHON_MODE=python"
    ) else (
        where py >nul 2>&1
        if not errorlevel 1 (
            set "PYTHON_MODE=py"
        )
    )
)

if not defined PYTHON_MODE (
    echo [ERROR] Aucun interpreteur Python trouve.
    echo Execute d'abord "templates\automation_project\scripts\setup_env.bat"
    pause
    exit /b 1
)

echo Lancement de l'agent secops...
if "%PYTHON_MODE%"=="venv" (
    call "%VENV_PY%" "%MAIN_PY%" %*
) else if "%PYTHON_MODE%"=="python" (
    call python "%MAIN_PY%" %*
) else (
    call py -3 "%MAIN_PY%" %*
)
set "EXIT_CODE=%ERRORLEVEL%"

if not "%EXIT_CODE%"=="0" (
    echo.
    echo [ERROR] Le lancement a echoue avec le code %EXIT_CODE%.
    echo Si les dependances manquent, execute "templates\automation_project\scripts\setup_env.bat".
)

pause
exit /b %EXIT_CODE%
