#!/bin/bash
# 🛡️ SecOps Agent Setup & Repair Script

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "🔄 Initialisation de l'environnement SecOps dans : $PROJECT_ROOT"

# Supprime l'ancien venv s'il existe pour éviter les conflits de chemins
if [ -d ".venv" ]; then
    echo "🧹 Nettoyage de l'ancien environnement virtuel..."
    rm -rf .venv
fi

echo "📦 Création du nouvel environnement virtuel..."
python3 -m venv .venv

echo "🛠️ Installation des dépendances en mode éditable..."
source .venv/bin/activate
pip install --upgrade pip
pip install -e .

echo "✅ Configuration terminée !"
echo "🚀 Vous pouvez maintenant utiliser './secops --help' ou 'source .venv/bin/activate && secops'"
