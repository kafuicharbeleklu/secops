# Terminal Shell Template

Ce dossier fournit un starter reutilisable pour les projets Python qui ont besoin d'une UX terminal guidee.

## Contenu
- `app/shell_template.py` : base generique pour le header, le prompt, la toolbar, les statuts, les suggestions et la boucle interactive.
- `templates/terminal_shell/starter_shell.py` : exemple minimal a copier puis adapter.

## Comment repartir vite
1. Copie `app/shell_template.py` dans ton nouveau projet.
2. Duplique `starter_shell.py` et renomme la classe.
3. Definis tes commandes, ton catalogue metier et tes statuts via `get_status_entries()`.
4. Branche ton moteur dans `dispatch_command()` et `run()`.

## Hooks principaux
- `get_keyword_catalog()` pour l'autocompletion de codes, modes ou entites.
- `get_context_actions()` pour les suggestions visibles sous le header.
- `get_next_action_hint()` pour le guidage contextuel.
- `build_state_payload()` et `apply_state_payload()` pour persister la session.
- `dispatch_command()` pour la logique metier.

## Lancer l'exemple
```powershell
python templates\terminal_shell\starter_shell.py
```
