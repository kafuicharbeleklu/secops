# Rapport de passation - logique metier SecOps CLI

Date: 2026-06-03

Ce document transmet l'etat actuel de la logique metier SecOps CLI a un autre
agent charge de donner une opinion independante. Il ne s'agit pas d'un rapport
TUI general ni d'un plan marketing. Le focus est l'orchestration pentest:
classification de requete, permission, proposition d'actions, execution
controlee, session, relecture de labs et memoire d'experience.

## Objectif Produit

SecOps CLI doit etre un agent pentester utilisable dans plusieurs contextes:
CTF en ligne, labs TryHackMe/HackTheBox/RootMe/PortSwigger, infra virtuelle
privee, et audits autorises. La logique metier vise a garder la meme demarche
technique quelle que soit l'etiquette d'environnement:

- comprendre l'objectif technique;
- respecter le scope et l'autorisation;
- executer seulement ce que l'utilisateur demande ou selectionne;
- proposer les prochaines etapes au lieu d'enchainer silencieusement;
- conserver les resultats utiles pour mieux classer les futures suggestions.

## Principe Actuel

La regle centrale est "proposal-first":

- Une permission d'outil indique seulement qu'une action est autorisee.
- Une permission ne signifie pas que l'utilisateur veut executer tous les
  suivis possibles.
- Les actions suggerees par le planner sont candidates; elles ne s'executent
  pas seules par defaut.
- Les etapes sensibles restent derriere les flux de permission existants.
- Les labels comme CTF, TryHackMe, private VM ou authorized org sont des
  metadonnees de contexte, pas des modes qui changent la strategie technique.

## Modules Clefs

### Classification de requete

Fichier: `secops_agent/core/request_context.py`

Responsabilite:

- classifier `technical_goal`, `user_intent`, `risk`, `scope_status`,
  `target`, `environment_hint`;
- distinguer une question focalisee d'une demande d'orchestration;
- signaler `focused_answer_turn` via `should_suppress_followups`.

Decision importante:

- "Quels ports sont ouverts ?" et "fais un scan de ports" ne sont pas traites
  pareil.
- "TryHackMe", "HackTheBox", "RootMe" ou "machine virtuelle" ne doivent pas a
  eux seuls activer ou desactiver les suivis.

### Orchestration agent

Fichier: `secops_agent/core/agent.py`

Responsabilite:

- appeler le LLM;
- normaliser les tool calls;
- appliquer scope guard et permission engine;
- executer les outils;
- parser les resultats;
- emettre des `SuggestedActionsEvent`;
- enregistrer des lecons d'experience apres les resultats d'outils.

Points structurants:

- `allow_automatic_planner_execution` est `False` par defaut.
- `max_chained_actions_per_turn` existe, mais le comportement attendu reste
  proposal-first sauf opt-in explicite.
- `continue`, `1`, `1 2`, `tous/all` selectionnent les suggestions deja
  proposees, puis repassent par le flux normal: permission, scope, progress,
  result, parsing.
- Les refus utilisateur ne doivent pas devenir des lecons techniques.

### Planner deterministe

Fichier: `secops_agent/core/planner.py`

Responsabilite:

- produire des `NextAction` a partir de `MissionContext`;
- classer les actions;
- dedupliquer;
- attacher risque, pre-requis, methode et evidence;
- appliquer les lecons d'experience comme signaux de ranking.

Decision importante:

- Le planner propose, il n'execute pas.
- Les actions d'exploitation sont bornees:
  - upload/panel -> `upload_surface_validation`, action manuelle, high risk;
  - SQLi/XSS/cmd injection -> `generate_payload`, dangerous, approval required;
  - SUID -> `suid_privilege_escalation_review`, action manuelle;
  - high/critical known vuln -> `exploit_feasibility_review`, action manuelle.

### Permission

Fichiers:

- `secops_agent/core/permissions.py`
- `secops_agent/ui/tool_display.py`

Responsabilite:

- distinguer tool permission, command permission, command prefix/exact;
- gerer once/session/persistent;
- bloquer les commandes/system paths dangereux;
- afficher la demande de permission.

Point a revoir par l'autre agent:

- Le prompt de permission est fonctionnel, mais la pertinence UX des options
  reste une zone ouverte. L'utilisateur a signale que les options "Yes",
  "always allow in this conversation", "persist to settings.json" peuvent etre
  moins coherentes que dans AGY selon le contexte.

### Memoire structuree et parsing

Fichiers:

- `secops_agent/core/result_parser.py`
- `secops_agent/core/structured_memory.py`
- `secops_agent/core/mission.py`

Responsabilite:

- transformer les sorties nmap, dir brute, headers, nikto, run_shell, etc. en
  hosts, services, findings, evidence;
- garder `MissionContext` coherent;
- alimenter le planner et le contexte LLM.

Cas important:

- `run_shell` peut parser des sorties SUID et produire des findings
  `suid_binary`, tout en ignorant les binaires SUID courants.

### Experience memory

Fichier: `secops_agent/core/experience.py`

Responsabilite:

- modeliser `CaseLesson`;
- stocker les lecons en JSONL local;
- dedupliquer;
- ignorer les refus utilisateur;
- enregistrer les echecs techniques utiles, par exemple wordlist absente,
  timeout, host down, invalid tool output;
- retrouver les lecons similaires depuis services, endpoints, findings,
  arguments, evidence et failures;
- influencer le ranking du planner sans creer de findings ni declencher
  d'execution.

Limite volontaire:

- Ce n'est pas une confirmation de vulnerabilite.
- Ce n'est pas un mode autonome.
- Ce n'est pas encore une base de playbooks editee/revue par l'utilisateur.

### Sessions

Fichier: `secops_agent/main.py`

Responsabilite:

- autosave a la fermeture;
- `/save`, `/load`, `/resume`;
- restauration du modele, runtime, mission, artifacts;
- apres `/load` ou `/resume`, l'autosave continue sur la session active.

Decision importante:

- Chaque lancement peut creer une nouvelle session, mais une session reprise
  doit etre sauvegardee dans son fichier actif, pas dans un autosave sans lien.

## Comportements Attendus

### Question focalisee

Exemple:

`Scan la machine, combien de ports sont ouverts ?`

Attendu:

- faire uniquement le scan necessaire;
- repondre au nombre de ports et aux faits utiles;
- ne pas enchainer automatiquement headers, tech detect, dir brute, nikto.

### Demande d'enumeration

Exemple:

`Fais une reconnaissance sur 10.10.10.5`

Attendu:

- executer les outils explicitement demandes ou proposes puis selectionnes;
- afficher les suggestions suivantes;
- attendre l'utilisateur pour continuer.

### Selection de suggestion

Exemples:

- `continue`
- `1`
- `1 2`
- `tous`

Attendu:

- executer uniquement les suggestions selectionnees;
- garder scope, permission, progress, result, parsing et suggestions;
- ne pas utiliser la permission comme intention implicite.

### Exploitation controlee

Exemple:

`Find a form to upload and get a reverse shell`

Attendu:

- identifier les surfaces et pre-requis;
- proposer une action bornee;
- ne pas generer ou executer de shell sans etape explicite;
- demander permission pour tout outil ou payload sensible.

### Environnement

Exemples:

- TryHackMe
- HackTheBox
- RootMe
- VM privee sur hyperviseur
- audit interne autorise

Attendu:

- l'environnement enrichit le contexte;
- la decision technique depend de l'objectif, du risque, du scope et de
  l'intention;
- pas de mode CTF rigide qui fausse les scans sur une infra virtuelle privee.

## Etat de Validation

Derniere validation connue apres P26:

- `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests`
  -> 326 tests OK
- `PYTHONDONTWRITEBYTECODE=1 python3 -m compileall secops_agent tests -q`
  -> OK

Tests importants a inspecter:

- `tests/test_request_context.py`
- `tests/test_tool_chaining.py`
- `tests/test_planner.py`
- `tests/test_lab_replay_harness.py`
- `tests/test_experience_memory.py`
- `tests/test_runtime_persistence.py`
- `tests/test_agent_permissions.py`
- `tests/test_local_lab_setup.py`

## Points Forts Actuels

- La distinction permission/intention est explicite.
- Les follow-ups sont suppressibles par intention utilisateur, pas par label CTF.
- Les actions d'exploitation sont proposal-first et evidence-backed.
- Les replays multi-plateformes couvrent RootMe-like, HackTheBox-like,
  TryHackMe-like, PortSwigger-like et generic CTF sans cible live.
- La session reprise conserve model/runtime/mission/artifacts.
- La memoire d'experience influence le ranking mais ne bypass pas le scope ou
  les permissions.

## Risques et Questions Pour Revue Independante

### 1. Prompt de permission

Question:

- Les options actuelles sont-elles suffisamment proches d'AGY et suffisamment
  pertinentes selon le contexte ?

Points a regarder:

- `secops_agent/ui/tool_display.py`
- `secops_agent/core/permissions.py`

Hypothese actuelle:

- `Yes` = autorisation ponctuelle.
- `always allow in this conversation` = regle session.
- `persist to settings.json` = regle persistante.

Risque:

- Pour certaines commandes, proposer une regle prefixe ou persistante peut etre
  trop large ou peu pertinente.

### 2. Compatibilite LLM/tool schemas

Question:

- Pourquoi certains prompts GoBuster/DirBrute ont produit des erreurs de type
  AFC/Gemini INVALID_ARGUMENT dans les tests manuels precedents ?

Points a regarder:

- `secops_agent/core/llm.py`
- `secops_agent/core/tools.py`
- schemas des outils web/recon;
- melange eventuel entre function calling, declarations et providers.

Risque:

- Le TUI et la logique metier peuvent etre corrects, mais un provider peut
  refuser le schema et casser l'orchestration.

### 3. Long-running tools et progress

Question:

- Les outils longs exposent-ils assez de progress events pour eviter l'impression
  de terminal bloque ?

Points a regarder:

- `report_progress` dans `secops_agent/core/tools.py`;
- implementations `nmap_scan`, `dir_brute`, `nikto_scan`, `run_shell`;
- rendu `ToolStartEvent`, `ToolProgressEvent`, `ToolResultEvent`.

Risque:

- Si un outil ne publie aucun progress event, l'agent peut sembler bloque meme si
  l'execution est en cours.

### 4. Sudo et commandes interactives

Question:

- Faut-il detecter plus tot les commandes qui exigent un TTY ou un mot de passe
  sudo ?

Risque:

- Une commande comme `sudo apt update` peut etre autorisee puis echouer avec
  "a terminal is required to authenticate".

### 5. Memoire d'experience et gouvernance

Question:

- La capture automatique des lecons doit-elle etre configurable, purgeable ou
  visible dans une future interface ?

Etat actuel:

- Stockage JSONL local.
- Arguments sanitizes.
- Refus utilisateur ignores.
- Les IP/domaines peuvent rester dans les fingerprints de cas.

Risque:

- Pour un usage pro, retention, privacy et export/import doivent etre decides.

### 6. Granularite des suggestions

Question:

- `continue`, `1 2`, `tous` sont-ils acceptables pour un agent pentester ?

Etat actuel:

- Ces entrees selectionnent uniquement les suggestions deja affichees.
- Chaque outil repasse par permission/scope.

Risque:

- `tous` peut etre trop large si la liste contient des actions medium/high risk,
  meme si les permissions restent actives.

### 7. Experience vs playbooks

Question:

- Faut-il transformer les lecons en vrais playbooks revus, ou garder seulement un
  signal de ranking ?

Etat actuel:

- Experience = ranking hint et raison courte.
- Pas de playbook executif.

Risque:

- Une experience utile peut rester sous-exploitee, mais un playbook trop fort
  pourrait pousser l'agent vers l'autonomie.

## Contraintes A Ne Pas Casser

- Ne pas revenir a un mode "CTF only".
- Ne pas executer automatiquement payload/shell/privilege escalation.
- Ne pas affaiblir permission engine ou scope guard.
- Ne pas ajouter de commandes slash ou raccourcis sans demande explicite.
- Ne pas changer logo/login.
- Ne pas transformer la memoire d'experience en preuve de vulnerabilite.
- Ne pas confondre "autorise" avec "demande par l'utilisateur".

## Recommandation de Revue Pour L'Autre Agent

Ordre conseille:

1. Lire `docs/AGENT_BUSINESS_LOGIC_REVIEW_PLAN.md`.
2. Lire `docs/PENTEST_AGENT_CAPABILITY_PLAN.md`, surtout P22.5 a P26.
3. Auditer `request_context.py`, `agent.py`, `planner.py`, `permissions.py`,
   `tool_display.py`, `experience.py`.
4. Executer les tests clefs:
   - `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests/test_request_context.py`
   - `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests/test_tool_chaining.py`
   - `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests/test_experience_memory.py`
   - `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests/test_lab_replay_harness.py`
5. Donner une opinion sur:
   - separation permission/intention;
   - traitement multi-environnement;
   - pertinence des options de permission;
   - limites des suggestions multi-selection;
   - gouvernance de la memoire d'experience;
   - risques de provider/tool schema.

## Suite Possible

Prochaines phases candidates:

- P27: revoir et simplifier le prompt de permission selon le contexte exact.
- P28: corriger la compatibilite provider/tool schema et les erreurs AFC.
- P29: renforcer progress/cancel/output streaming pour outils longs.
- P30: ajouter gouvernance de la memoire d'experience: retention, purge,
  review, export.
- P31: passer de "experience ranking" a "playbook suggestions" sans execution
  autonome.
- P32: detecter les commandes sudo/interactives avant execution et proposer des
  alternatives executables par l'utilisateur.
