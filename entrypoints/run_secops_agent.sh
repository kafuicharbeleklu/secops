#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
APP_DIR="${ROOT_DIR}/templates/automation_project"
MAIN_PY="${APP_DIR}/main.py"
VENV_PY="${APP_DIR}/.venv/bin/python"

if [[ ! -f "${MAIN_PY}" ]]; then
    echo "[ERROR] Entree introuvable: ${MAIN_PY}" >&2
    exit 1
fi

if [[ -x "${VENV_PY}" ]]; then
    PYTHON_CMD=("${VENV_PY}")
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD=("python3")
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD=("python")
else
    echo "[ERROR] Aucun interpreteur Python trouve." >&2
    echo "Installe Python puis execute les dependances de templates/automation_project/requirements.txt." >&2
    exit 1
fi

echo "Lancement de l'agent secops..."
"${PYTHON_CMD[@]}" "${MAIN_PY}" "$@"
EXIT_CODE=$?

if [[ ${EXIT_CODE} -ne 0 ]]; then
    echo
    echo "[ERROR] Le lancement a echoue avec le code ${EXIT_CODE}." >&2
    echo "Si les dependances manquent, installe templates/automation_project/requirements.txt." >&2
fi

exit "${EXIT_CODE}"
