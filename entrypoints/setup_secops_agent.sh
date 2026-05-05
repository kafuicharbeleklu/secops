#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
APP_DIR="${ROOT_DIR}/templates/automation_project"
REQ_FILE="${APP_DIR}/requirements.txt"
VENV_DIR="${APP_DIR}/.venv"
VENV_PY="${VENV_DIR}/bin/python"

if [[ ! -f "${REQ_FILE}" ]]; then
    echo "[ERROR] Fichier de dependances introuvable: ${REQ_FILE}" >&2
    exit 1
fi

if command -v python3 >/dev/null 2>&1; then
    BOOTSTRAP_PYTHON="python3"
elif command -v python >/dev/null 2>&1; then
    BOOTSTRAP_PYTHON="python"
else
    echo "[ERROR] Aucun interpreteur Python trouve." >&2
    exit 1
fi

echo "Preparation de l'environnement secops..."
"${BOOTSTRAP_PYTHON}" -m venv "${VENV_DIR}"
"${VENV_PY}" -m pip install --upgrade pip
"${VENV_PY}" -m pip install -r "${REQ_FILE}"

echo
echo "Environnement pret."
echo "Lance ensuite: ${ROOT_DIR}/entrypoints/run_secops_agent.sh"
