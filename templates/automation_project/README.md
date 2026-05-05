# SECOPS Pentest Agent

Ce projet sert de base a un agent conversationnel oriente pentest pour labs autorises, avec UX terminal, memoire de cas, boucle agentique et raisonnement guide par Gemini.
Le shell conserve maintenant le fil de la conversation dans le terminal au lieu de rafraichir l'ecran a chaque requete.

## Structure
- `main.py` : point d'entree interactif et batch.
- `app/shell_template.py` : socle UX/TUI generique.
- `app/branding.py` : nom du projet, prompt et palette terminal.
- `app/settings.py` : defaults projet et plan recommande.
- `app/gemini_client.py` : client Gemini et gestion des erreurs de connexion API.
- `app/project_shell.py` : shell conversationnel, contexte memoire et UX.
- `app/catalog.py` : cibles et profils disponibles.
- `app/workflows.py` : handlers d'execution a remplacer par tes vraies actions.
- `config/project.example.json` : exemple de configuration projet.
- `docs/ADAPTATION_CHECKLIST.md` : checklist de prise en main.
- `docs/PROJECT_MAP.md` : carte rapide du template.
- `logs/` : journaux runtime.
- `workspace/` : artefacts generes.
- `scripts/run_app.bat` : lanceur Windows simple.
- `scripts/setup_env.bat` : creation rapide d'un environnement local.

## Capacites actuelles
1. Charger la memoire locale depuis `knowledge/`.
2. Interroger Gemini avec contexte de cas et repli local si l'API echoue.
3. Passer par une boucle `observation -> hypothese -> action -> observation`.
4. Utiliser des outils internes depuis le chat : memoire locale, lecture/ecriture `workspace/`, execution de commandes autorisees.
5. Identifier une cible mentionnee dans la conversation pour enrichir le contexte.

## Commandes utiles
- `python main.py`
- `texte libre` : poser une question directement a l'agent
- `/cases`
- `/case basic_penetration`
- `/help`
- `/quit`

## Exemple de flux
```text
/case basic_penetration
La cible 10.129.134.165 expose HTTP, SMB et SSH. Quelle hypothese tu privilegies ?
Si le web semble pauvre, quel pivot est le plus pertinent ?
Comment aborder RootMe sans sortir du perimetre du lab ?
```

## Variables d'environnement
- Le projet lit `.env` a la racine du repo.
- Variable recommandee pour Gemini : `GEMINI_API_KEY`
- Variable compatible : `GOOGLE_API_KEY`
- Variable optionnelle : `GEMINI_MODEL` (defaut : `gemini-2.5-flash`)
  - Gemini : `gemini-2.5-flash`
  - Gemma via Gemini API : `gemma-4-26b-a4b-it` ou `gemma-4-31b-it`
- Variable optionnelle : `SECOPS_COMMAND_MODE` avec `ask` (defaut), `session` ou `deny`

Pendant une session, `/model` affiche les profils disponibles. `/model gemma`
bascule temporairement sur `gemma-4-26b-a4b-it`, `/model gemma-31b` sur
`gemma-4-31b-it`, et `/model auto` active le routage automatique Gemma sans
modifier `.env`. Les modeles `gemma-*` utilisent le function calling natif
quand il est disponible.

## Tests
- `cd templates/automation_project`
- `.venv/bin/python -m unittest discover -s tests`

Le shell injecte explicitement la cle API dans `google-genai`. Si Gemini refuse l'acces API, le texte libre bascule sur une reponse locale issue de `knowledge/`.
Quand `SECOPS_COMMAND_MODE=ask`, l'agent peut proposer une commande depuis le chat et demande une validation interactive avant execution.

## Pour un nouveau projet
1. Copie le dossier `templates/automation_project/` dans un nouveau repo.
2. Renomme le projet via `app/branding.py`.
3. Passe la checklist `docs/ADAPTATION_CHECKLIST.md`.
