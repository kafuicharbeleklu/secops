# Adaptation Checklist

Utilise cette checklist quand tu copies ce template dans un nouveau depot.

## En 5 minutes
1. Renomme le projet dans `app/branding.py` :
   - `PROJECT_NAME`
   - `PROJECT_SUBTITLE`
   - `PROMPT_BRAND`
   - `PROJECT_OWNER`
   - `PROJECT_SLUG`
2. Remplace les cibles et profils dans `app/catalog.py`.
3. Adapte les commandes et suggestions dans `app/project_shell.py`.
4. Branche les vraies actions dans `app/workflows.py`.
5. Ajuste `config/project.example.json` selon les options du projet.

## Avant premier commit
1. Lance `python main.py --list-targets`.
2. Lance `python main.py --check`.
3. Lance `python main.py --targets PRECHECK,INSTALL`.
4. Verifie que les artefacts vont bien dans `workspace/`.
5. Verifie que les fichiers runtime restent ignores par `.gitignore`.

## Si tu changes la charte graphique
1. Modifie `TERMINAL_PALETTE` dans `app/branding.py`.
2. Garde un contraste fort sur la toolbar et les badges.
3. Verifie le rendu dans Windows Terminal ou PowerShell.
