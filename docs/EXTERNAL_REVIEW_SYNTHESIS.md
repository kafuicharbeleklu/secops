# Synthese des rapports externes - logique metier SecOps CLI

Date: 2026-06-03

Rapports lus:

- `docs/external_reviews/rapport_de_synthese_secops.md`
- `docs/external_reviews/analyse_strategique_approche.md`
- `docs/external_reviews/revue_complete_agent_pentester.md`
- `docs/external_reviews/plan_implementation_consolide.md`

## Verdict

Les rapports externes valident notre choix central: `proposal-first`,
separation permission/intention, planner deterministe, parser deterministe et
controle HITL granulaire. Ils ne recommandent pas de remplacer l'architecture
par LangGraph, CrewAI ou un framework multi-agent.

Leur critique principale ne porte pas sur la strategie metier, mais sur la
fiabilite d'implementation:

- schemas et arguments d'outils;
- sorties d'outils adversariales;
- memoire longue;
- progress/cancel des traitements longs;
- gouvernance de l'experience store;
- observabilite structuree;
- refactoring de fichiers monolithiques.

## Attention sur la nomenclature

La "Phase 1/2/3" des rapports externes ne correspond pas directement a notre
roadmap `P22-P26`.

Pour eviter la confusion, on doit traiter leurs recommandations comme une source
de revue, puis les remapper dans notre plan interne:

- `P27`: permission prompt et command permission pertinents;
- `P28`: validation/coercion arguments et compatibilite provider/tool schema;
- `P29`: traitements longs, progress, cancel, sudo/TTY - termine;
- `P30`: gouvernance experience store et privacy - termine;
- `P30.5`: superviseur d'execution et UX traitements longs - termine;
- `P31`: playbooks prudents/state-aware - en cours;
- `P32`: refactoring/observabilite, si decide.

## Reconciliation avec l'etat actuel

| Sujet externe | Etat reel dans le code | Decision |
| --- | --- | --- |
| JSON Schema Gemini AFC | Deja corrige dans `ToolRegistry.get_tools_schema()`: `required` est au niveau objet et `default` n'est pas envoye. | Garder des tests de regression, mais ne pas reimplementer. |
| Sanitisation sorties outils | Deja presente via `core/output_sanitizer.py`, `memory.add_tool_result()` et safety rules dans `llm.py`. | A auditer/renforcer, mais pas a traiter comme absent. |
| Timeout approbation | Deja configurable dans `SecOpsAgent(approval_timeout=600.0)`. | Garder; verifier rendu UX si necessaire. |
| Logging exceptions integration resultats | Le parsing/integration logge maintenant avec `logger.warning(..., exc_info=True)`. | Reste a chercher d'autres `except Exception: pass` residuels. |
| Experience memory | Deja implementee P26 avec capture tool results, dedupe, skip refus utilisateur, ranking hint. Gouvernance ajoutee dans P30: audit, export, retention, purge, anonymisation cible et cache de lecture. | Etendre seulement via P31 avec playbooks prudents, pas par capture brute supplementaire. |
| `run_shell` dans experience | Toujours exclu de `_EXPERIENCE_TOOL_NAMES` par politique P30. | Ne pas ajouter brut: les sorties shell peuvent contenir secrets, flags, credentials, chemins locaux ou donnees privees sans rapport. |
| Validation/coercion arguments | Termine dans P28: `ToolRegistry.execute()` valide/coerce avant execution, applique les defaults cote execution, ignore les extra args avec warning et retourne un `ToolResult` clair en cas d'erreur. | Garder les tests de regression. |
| Detection sudo/TTY | Termine dans P29: `run_shell` publie un preflight `sudo -n true`, normalise les erreurs TTY/password et retourne une commande manuelle au lieu d'executer a l'aveugle. | Garder les tests de regression autour des commandes systeme et VPN. |
| Backoff exponentiel LLM | Encore ouvert: retry lineaire visible dans l'agent. | P28/P29 selon impact provider. |
| Progress events partout | Renforce dans P29 puis P30.5: les outils streamants gardent leur progress existant, la boucle agent emet un heartbeat `still running`, et les subprocess longs passent maintenant par un superviseur avec spool, idle timeout et max runtime. | Terminer les controles background/cancel et l'expansion directe des spool files. |
| `waf_detect` dangerous | Termine dans P27: l'outil est maintenant `dangerous=True` et documente dans l'inventaire README. | Garder le test de parite README/registre. |
| Hachage cibles ExperienceStore | Termine dans P30: export anonymise et anonymisation en place avec dry-run par defaut et backup avant rewrite. | Garder la migration explicite, jamais silencieuse. |
| Refactor `main.py` | Ouvert, mais `run_chat_loop` est importe dans les tests. | Refactor seulement avec wrapper compatible. |

## Priorite consolidee

### 1. P28 - Validation/coercion arguments + provider schema - termine

Raison:

- impact direct sur `Gemini API Error: 400 INVALID_ARGUMENT`;
- impact direct sur tool calls mal formes, arguments manquants ou mauvais types;
- evite des comportements comme `Nmap()` sans cible claire.

Travail realise:

- ajout d'une validation generique des arguments dans `ToolRegistry.execute()` ou
  juste avant l'execution;
- coercion des types simples (`str`, `int`, `float`, `bool`, `list`);
- rejet ou nettoyage des parametres inconnus avec warning;
- defaults appliques uniquement cote execution, pas dans le schema provider;
- tests ajoutes pour arguments manquants, types incorrects, extra params,
  schema Gemini propre.

### 2. P27 - Permission prompt contextuel - termine

Raison:

- c'est un irritant utilisateur recurrent;
- les rapports externes confirment que `command_prefix` peut etre trop large;
- AGY semble mieux calibrer les options selon le contexte.

Travail realise:

- differentiation exact command, contextual prefix, tool-level permission;
- masquage des options session/persistantes quand elles sont trop larges ou
  dangereuses;
- formulation plus claire pour commandes simples, sudo, nmap, apt, shell
  compose;
- tests des libelles et des scopes.

### 3. P29 - Long-running tools, progress, cancel, sudo/TTY - termine

Raison:

- corrige l'impression de terminal bloque;
- evite les echecs tardifs des commandes interactives;
- ameliore l'UX sans augmenter l'autonomie.

Travail realise:

- preflight sudo/TTY visible avant execution de commandes shell avec `sudo`;
- normalisation des erreurs TTY/password en guidance manuelle exploitable;
- heartbeat agent `still running` pour les outils silencieux;
- conservation des progress events existants dans nmap, dir_brute, nikto,
  sqlmap et run_shell;
- tests de regression sur le preflight sudo et le heartbeat outil silencieux.

### 4. P30 - Gouvernance ExperienceStore - termine

Raison:

- les rapports pointent le risque privacy;
- notre P26 capture maintenant des lecons automatiquement;
- il faut controler retention, purge, anonymisation et audit.

Travail realise:

- audit/review programmatique de l'ExperienceStore sans dumping complet des
  sorties;
- export JSONL avec anonymisation optionnelle des cibles;
- anonymisation en place avec dry-run par defaut et backup avant rewrite;
- retention/purge par age, nombre, outcome ou outil, egalement dry-run par
  defaut;
- cache de lecture par signature fichier, invalide apres append/rewrite;
- politique explicite: `run_shell` reste exclu de l'experience automatique.

### 5. P31/P32 - Intelligence/refactoring

Raison:

- utile, mais moins urgent que fiabilite et permission;
- risque de gros refactor si lance trop tot.

Travail attendu:

- memoire 3 niveaux deterministe d'abord, resume LLM optionnel ensuite;
- observabilite structuree;
- refactor `main.py` avec compatibilite `secops_agent.main.run_chat_loop`;
- refactor parsers quand la logique metier est stable.

## Decisions recommandees sur les 4 questions externes

1. Priorite de suite: oui pour la fiabilite, mais sous notre `P28`, pas sous une
   nouvelle nomenclature "Phase 2".
2. Compaction memoire: commencer par extraction deterministe de patterns; ajouter
   resume LLM seulement en couche optionnelle.
3. Hachage retroactif: disponible sous P30 via dry-run + backup + migration
   explicite, mais ne pas l'executer silencieusement.
4. Refactor `main.py`: ne pas deplacer librement `run_chat_loop`; garder un
   wrapper compatible dans `secops_agent.main`.

## Prochaine action conseillee

`P30.5` est termine: ctrl+o/artifact lit les fichiers de spool via metadata
superviseur, `Esc`/Ctrl-C stoppe les process groups supervises actifs, les
executions foreground longues/echouees/interrompues restent reviewables via
`/tasks`, le prompt sudo PTY securise est fait pour `run_shell` interactif, et
`/cancel` marque puis annule les handles de taches existants. `P31.1` a
`P31.5` sont termines: les echecs techniques comme Nmap `Host seems down`,
wordlist DirBrute manquante, outil local absent, sortie vide, timeout supervise,
source exposee, fichier sensible expose, directory listing et action deja
echouee dans la session sont transformes en propositions correctives, revues
bornees, ou suppressions deterministes sans execution automatique.
L'installation d'un outil manquant passe par `run_shell`, reste visible, et
requiert l'approbation utilisateur/sudo. Le premier palier `P32` est lance:
observabilite JSONL optionnelle via `SECOPS_TRACE_FILE`, backoff LLM sur erreurs
temporaires de stream, redaction des champs sensibles de trace, et extraction
compatible de la selection de surface interactive slash hors de `main.py`.
Prochaine etape: continuer `P32` en extrayant davantage de helpers purs de
`main.py` seulement quand les imports publics comme `run_chat_loop` restent
stables et testes.

Definition de fin P28, maintenant couverte:

- un appel avec parametres inconnus n'atteint pas la fonction outil sans warning
  ou nettoyage;
- un type simple incorrect est coerced quand c'est raisonnable;
- un argument requis manquant produit un `ToolResult(success=False, error=...)`
  clair;
- les schemas provider restent JSON Schema compatibles;
- les tests de non-regression tool-chaining, permissions, replay labs et
  experience memory passent.
