# SecOps v2 Plan Executif

Date: 2026-06-05

Ce document resume les artefacts longs:

- `docs/SECOPS_V2_NIGHT_RESEARCH_IMPROVEMENT_PLAN.md`
- `docs/SECOPS_V2_DEEP_RESEARCH_AND_CODE_AUDIT_2026-06-05.md`
- `docs/SECOPS_V2_NEXT_SPRINT_QUEUE_2026-06-05.md`
- `docs/SECOPS_V2_RESEARCH_SOURCE_INDEX_2026-06-05.md`
- `docs/SECOPS_V2_TOOL_RISK_INVENTORY_2026-06-05.md`

## Decision Principale

Ne pas ajouter de nouvelles commandes, raccourcis ou chaines autonomes pour le
prochain sprint.

La priorite est de rendre l'agent plus fiable, plus previsible et plus sur
dans ses comportements actuels:

1. execution locale;
2. permissions;
3. sudo/VPN;
4. resume et `ctrl+o`;
5. commandes longues;
6. contexte d'engagement;
7. reporting/RoE;
8. experience/playbooks;
9. adapters lourds;
10. fiabilite provider;
11. retention et redaction;
12. frontieres prompt/donnees outil.

Recentrage actuel:

- MCP, skills, artifacts, plugins et nouvelles commandes ne sont pas la
  priorite produit pour le moment.
- La priorite immediate est l'intelligence operationnelle:
  - comprendre l'intention technique de la requete;
  - choisir un ensemble minimal d'outils pertinents;
  - proposer les prochaines actions au lieu de les enchainer en silence;
  - apprendre des echecs et reussites avec des portes de compatibilite;
  - expliquer pourquoi une lecon s'applique ou ne s'applique pas.
- Les surfaces d'extension restent en pause apres la tranche securite deja
  implementee, sauf risque direct pour le runtime.

## Ce Qui A Change Dans La Comprehension

### Permissions

Le probleme n'est plus seulement "les options de permission sont mauvaises".
Le code actuel a deja progresse:

- les commandes composees dangereuses ne proposent plus de persistance;
- `nmap target` peut utiliser un prefixe controle;
- les extensions de commande avec `&&`, `|`, backticks, ou `$()` ne sont pas
  couvertes par un prefixe autorise;
- `uname -a` reste une autorisation exacte.

Le travail restant:

- ajouter une classe de risque lisible;
- ajouter une analyse shell commune pour permission, sudo, sandbox et scope;
- aligner outil, commande, sudo, sandbox et VPN;
- appliquer la politique fichier avant lecture;
- afficher une permission pertinente, pas seulement une chaine shell.

### `ctrl+o` Et Resume

Le bug n'est pas seulement visuel.

Le systeme reconstruit un transcript depuis les messages, mais ne persiste pas
encore un journal exact de rendu. `ctrl+o` a plusieurs sources d'etat et peut
garder une ancre trop vieille ou mal placee.

Le travail restant:

- separer session reprise et session courante;
- nettoyer les ancres sur `/resume`, `/load`, `--session`, `/clear`;
- borner le replay visible;
- calculer les lignes entre un outil et le prompt final;
- ajouter un journal de rendu prive ou un modele equivalent;
- garder l'export public redige, separe du replay exact local.

### VPN Et Sudo

Le VPN marche maintenant dans certains cas, mais le modele d'execution reste a
durcir.

Le travail restant:

- garder un PID/config/log/status pour les VPN lances par SecOps;
- distinguer les etats: starting, pending-handshake, connected, failed,
  stale, disconnected;
- deconnecter uniquement le VPN lance par SecOps par defaut;
- ne pas tuer tous les processus OpenVPN sauf action explicite;
- ne pas afficher un prompt sudo si le sandbox va bloquer sudo;
- remplacer `nohup ... & echo $!` par un chemin supervise ou possede.

### Commandes Longues

Le superviseur existe et il est solide, mais il n'est pas encore utilise partout.

Le travail restant:

- declarer le budget runtime dans le contrat outil;
- aligner le timeout du registre avec le timeout interne;
- classer les helpers `_run_cmd`;
- garder un statut visible: running, success, failed, cancelled, timed out;
- conserver spool/log pour revue.

### Experience Et Apprentissage

L'agent a deja une memoire d'experience locale.

Le risque restant:

- le rapprochement par tokens peut melanger des cas qui se ressemblent en mots
  mais pas techniquement.

Le travail restant:

- ajouter des portes de compatibilite:
  - service;
  - port/protocole;
  - endpoint;
  - mode d'echec;
  - classe de risque;
  - plateforme comme metadata faible seulement.

### Reporting Et RoE

Le reporting ne doit pas devenir une reformulation libre du modele.

Le travail restant:

- stocker les regles d'engagement comme donnees mission:
  - autorisation;
  - scope;
  - hors scope;
  - techniques autorisees/interdites;
  - fenetres horaires;
  - sensibilite des donnees;
  - conditions d'arret;
  - exigences de reporting.
- lier chaque affirmation de rapport a une preuve:
  - evenement outil;
  - evidence structuree;
  - fait explicitement fourni par l'utilisateur.
- ajouter un niveau de support:
  - observed;
  - inferred;
  - reference;
  - unsupported.
- calculer la severite executive uniquement depuis les findings confirmes ou
  observes.

### Adapters Lourds

Burp/ZAP, Metasploit, Impacket, NetExec et BloodHound sont utiles, mais ne
doivent pas devenir des shells deguises.

Le travail restant:

- creer un `AdapterSpec` obligatoire pour chaque outil;
- definir un contrat adapter avant ajout:
  - exigences binaire/API;
  - version/provenance;
  - type d'action;
  - credentiels requis;
  - extraction du scope;
  - timeout;
  - parser de sortie;
  - preuves produites;
  - detection/installation;
  - classe de risque.
- separer observation passive, scan actif, mutation de requete, spray,
  upload/download, execution distante et exploit/payload.
- traiter les erreurs outils comme des objets:
  - dependency missing;
  - timeout;
  - auth required;
  - scope blocked;
  - rate-limit blocked.
- proposer une installation adaptee a l'OS, pas seulement `apt`.

### Fiabilite Provider

Les erreurs 500/400, warnings AFC, repetitions et latences longues doivent etre
traitees comme une couche produit, pas comme une fatalite du modele.

Le travail restant:

- reessayer proprement les erreurs `500 INTERNAL`;
- garder les erreurs `400 INVALID_ARGUMENT` tool-schema comme non retriables;
- dedupliquer ou signaler les paragraphes repetes;
- repondre localement aux questions deterministes quand possible:
  - heure;
  - OS;
  - IP;
  - statut VPN.
- maintenir une matrice de compatibilite provider par modele.

### Frontieres Prompt Et Donnees Outil

Le risque n'est pas seulement que le modele se trompe. Le code peut aussi
promouvoir du texte non fiable vers le prochain prompt systeme.

Le travail restant:

- traiter le contexte extension comme donnees de confiance inferieure;
- ne jamais laisser une skill, un hook, un MCP ou une sortie outil redefinir
  les regles systeme;
- neutraliser les marqueurs de frontiere presents dans les sorties outil;
- assainir les valeurs issues des parsers avant mission/structured memory;
- envoyer au provider des resumes parses compacts et des references
  d'artefacts, pas toute la sortie brute quand un parser existe;
- appliquer la compaction/trimming sur le chemin LLM principal;
- reduire les doublons en supprimant le narratif pre-outil quand le meme tour
  execute aussi des outils;
- supprimer les variantes de bloc `Mission State` dans les reponses locales
  courtes.

### Retention Et Redaction

SecOps stocke plus que du texte de chat: sessions, exports, spools, logs VPN,
logs applicatifs, traces, historique TUI et memoire d'experience.

Le travail restant:

- centraliser `SECOPS_HOME`;
- creer les dossiers en `0700` et fichiers en `0600`;
- valider les noms de sessions/exports comme slugs stricts;
- rediger par defaut:
  - tokens;
  - cookies;
  - mots de passe;
  - cles privees;
  - flags;
  - cibles internes si configure;
  - chemins sensibles.
- separer deux formats:
  - reprise exacte privee locale;
  - export public redige.
- ajouter une retention configurable:
  - sessions;
  - spools;
  - logs VPN;
  - traces;
  - experience memory.

## Ordre De Travail Recommande

### Phase 1 - P43 Execution Locale Et Permissions

Objectif:

- securiser le noyau d'execution avant de toucher au TUI ou aux capacites.

Taches:

1. ajouter les classes de risque internes;
2. corriger `ssl_audit`;
3. corriger sudo/backticks/substitutions;
4. appliquer la politique fichier;
5. aligner permission, sandbox, sudo et VPN;
6. introduire `ShellCommandAnalysis` pour supprimer les parsers divergents.

### Phase 2 - P44 Gouvernance Extensions

Objectif:

- traiter skills, hooks et MCP comme surfaces de confiance.
- bloquer l'execution silencieuse de hooks/MCP configures avant d'ajouter de
  nouvelles capacites.

Taches:

1. provenance et hash des skills;
2. `ExtensionTrustStore`;
3. hooks shell gates ou desactives par defaut;
4. approbation demarrage MCP par serveur et hash de schema;
5. politique d'environnement MCP allowlist;

Statut actuel:

- tranche skills/hooks/MCP implementee et validee;
- les configs d'extension non approuvees restent visibles mais inactives;
- le baseline de tests est passe a 462 tests OK.
6. commandes hook string en high-risk exact-only;
7. contraintes de schema MCP preservees;
8. audit durable extension/hook/MCP;
9. separation outputs MCP / outils internes privilegies;
10. contexte extension comme donnees non prioritaires;
11. neutralisation des marqueurs prompt/frontiere dans extensions et outputs.

### Phase 3 - P45 Resume Et `ctrl+o`

Objectif:

- supprimer les doublons, mauvais placements et replays incomplets.

Taches:

1. separer `resumed_from` et `current_session_name`;
2. journal de transcript prive;
3. stable row IDs;
4. payloads collapsed/expanded;
5. nettoyer les ancres;
6. borner le transcript;
7. calculer le tail apres outil;
8. ajouter tests PTY reels;
9. fallback "replay approximatif" pour anciennes sessions sans journal.

### Phase 4 - P46 VPN Ownership

Objectif:

- gerer le VPN comme un service local possede par SecOps.

Taches:

1. PID/config/log/status;
2. snapshot TUN avant connexion;
3. disconnect owned-only;
4. etats VPN precis;
5. cleanup sur annulation/timeout;
6. kill-all explicite et high-risk.

### Phase 5 - P47 Commandes Longues

Objectif:

- obtenir un suivi proche des bons agents CLI: progression, logs, annulation,
  timeout clair.

Taches:

1. contrat runtime par outil;
2. adoption superviseur;
3. `_run_cmd` reserve aux lectures courtes;
4. statut par etat d'execution, pas par permission;
5. progression pendant les periodes silencieuses;
6. timeout registre aligne au timeout outil;
7. erreurs structurees exploitables par le planner.

### Phase 6 - P48 Contexte D'Engagement

Objectif:

- eviter la confusion CTF/lab/VM/audit.

Decision:

- ne pas faire un mode CTF separe.
- conserver une logique technique commune.
- stocker l'environnement comme metadata.

Taches:

1. `EngagementContext`;
2. scope/RoE/stop conditions;
3. champs de reporting;
4. replays local/VPN/CTF/private VM/sudo.

### Phase 7 - P49/P50/P51 Maturite Capacites

Objectif:

- ajouter de la capacite sans autonomie cachee.

Taches:

1. playbooks revus;
2. `AdapterSpec` obligatoire;
3. adapters JSON-first;
4. NVD/EPSS/KEV comme priorisation seulement;
5. evidence board interne;
6. task tree durable;
7. conformance tests pour outils lourds.

### Phase 8 - P54 Fiabilite Provider

Objectif:

- eviter qu'une question simple echoue a cause d'une instabilite modele quand
  une reponse locale fiable existe.

Taches:

1. retries `500 INTERNAL`;
2. deduplication sorties;
3. `ToolSchemaSelector` par objectif technique;
4. chemins locaux deterministes;
5. AFC desactive pour l'orchestration manuelle;
6. matrice compatibilite provider;
7. resumes compacts apres outils;
8. trimming provider sur le chemin principal;
9. suppression des doublons pre-outil/post-outil.

Statut actuel:

- premiere tranche de routing implementee;
- les questions locales temps, OS, IP et hostname peuvent eviter le provider;
- les schemas outils envoyes au provider sont limites par objectif technique;
- les prompts port scan, web directory et exploit-step ont des tests de
  reduction de schema.

### Phase 9 - P55 Retention Et Redaction

Objectif:

- conserver la capacite de reprise exacte sans exposer inutilement secrets,
  flags, cibles ou logs bruts.

Taches:

1. `SECOPS_HOME`;
2. helpers `ensure_private_dir`, `write_private_text`,
   `append_private_jsonl`;
3. permissions `0700`/`0600`;
4. slugs stricts sessions/exports;
5. `RedactionPolicy`;
6. retention et purge dry-run;
7. export redige par defaut.

### Phase 10 - P56 Apprentissage Revu

Objectif:

- permettre a l'agent d'apprendre des echecs et succes sans memoriser des
  flags, secrets ou solutions CTF comme verites reutilisables.

Taches:

1. statut de revue des lecons;
2. provenance et expiration;
3. exclusion flags/secrets/credentials;
4. lecons non revues en explication seulement;
5. portes de compatibilite technique;
6. evaluation par replays synthetiques et cas negatifs.

Statut actuel:

- premiere tranche P56 implementee;
- les lecons capturees automatiquement restent non revues par defaut;
- seules les lecons revues et compatibles peuvent modifier le ranking;
- les flags, secrets et reponses exactes de challenge sont rediges dans les
  textes de lecon;
- les tests couvrent les cas negatifs endpoint/service incompatibles.
- P56/B ajoute une API locale `review_lesson` sans nouvelle commande
  utilisateur;
- les suggestions peuvent afficher `Lesson`, `Match` et `Missing` pour
  expliquer pourquoi une lecon influence ou n'influence pas l'action.
- P56/C ajoute un scoring de replays synthetiques pour verifier stop point,
  evidence, tool count, scope et absence de contamination CTF;
- les replays couvrent CTF/lab, VM privee et client autorise;
- une lecon endpoint-specifique ne peut plus influencer une action avant
  evidence d'un endpoint comparable.
- P56/D ajoute un journal local de signaux pour les suggestions:
  `suggested`, `selected`, `ignored`, `succeeded`, `failed`;
- P56/D ajoute une gate de promotion: lecon revue, replays passes et signal
  de succes correspondant avant reutilisation plus forte.
- P56/E agrege les signaux repetes pour distinguer tactiques utiles, bruit,
  actions ignorees et echecs repetes;
- P56/E expose ces metriques via l'audit interne de l'ExperienceStore;
- P56/E applique une influence faible dans le planner: boost limite,
  retrogradation limitee ou explication seulement.
- P56/F definit une representation de playbook technique controle;
- P56/F autorise la creation d'un playbook uniquement depuis une lecon revue,
  replays passes, preuves disponibles et signaux de succes suffisants;
- P56/F garde les playbooks en proposition-only avec contraintes explicites:
  scope, permission, evidence et stop point restent obligatoires.
- P56/G raccorde les playbooks controles au planner comme suggestions
  seulement;
- P56/G exige une evidence technique courante avant suggestion: famille de
  service compatible et indices endpoint compatibles quand ils existent;
- P56/G garde les playbooks derriere les filtres normaux de registry et scope;
- P56/G empeche un playbook proposal-only d'entrer dans le chainage automatique
  meme quand l'execution automatique du planner est activee.
- P56/H ajoute un audit interne du planner via `learning_audit()`;
- P56/H journalise les decisions lecon/playbook comme appliquees, rejetees ou
  explanation-only;
- P56/H trace service match, endpoint match, scope, registry, statut
  proposal-only, raisons, evidence manquante et delta de priorite;
- P56/H reste interne: pas de nouvelle commande, pas d'artifact, pas de surface
  MCP ou raccourci utilisateur.
- P56/I ajoute un chemin unique `LessonMatchDecision` pour compatibilite,
  score, effet et statut d'audit des lecons;
- P56/I fait consommer cette meme decision par `retrieve_similar_lessons()`,
  `lesson_is_compatible()`, `lesson_influence_detail()`, le ranking du planner
  et l'audit interne;
- P56/I retire du planner la logique dupliquee de service, endpoint et famille
  d'action pour les lecons;
- P56/I ajoute des tests de non-divergence pour service mismatch, lecon non
  revue, outil local bloque et outil absent de la registry.
- P56/J ajoute les gates de compatibilite risque/acces avant influence d'une
  lecon revue sur le ranking;
- P56/J conserve la classe de risque interne dans les `ToolResult` pour que les
  lecons generees gardent cette information;
- P56/J bloque les lecons d'exploitation, test authentifie, privilege
  escalation ou post-exploitation quand la mission n'a pas l'acces requis;
- P56/J etend l'audit interne avec `risk_match`, `access_match`,
  `required_access` et `current_access`;
- P56/J ajoute des tests pour mismatch de risque, shell manquant, shell present
  et persistance des metadata de risque.
- P56/K applique les metadata risque/acces aux playbooks controles;
- P56/K stocke classe de risque et acces requis sur les etapes de playbook
  promues;
- P56/K rejette une suggestion de playbook quand la mission n'a pas l'evidence
  d'acces compatible;
- P56/K inclut etat risque/acces dans les entrees d'audit interne des
  playbooks;
- P56/K enrichit les signaux de suggestion avec statut et raisons d'audit pour
  apprendre des decisions appliquees/rejetees;
- P56/K conserve les playbooks en proposition-only et verifie qu'ils ne
  peuvent pas entrer dans le chainage automatique.

## Prochain Ticket A Implementer

Commencer par P56/L:

- rendre l'apprentissage par signaux contextuel;
- inclure service, endpoint, risque et acces dans la correspondance des familles
  de signaux;
- empecher une reussite repetee sur un outil de booster des cibles ou phases
  non comparables;
- garder les raisons d'audit rejetees comme contexte negatif, pas comme
  retrogradation permanente et generique;
- garder ce travail interne: pas de nouvelle commande utilisateur, pas
  d'artifact, pas de MCP.

## Baseline De Verification

Dernieres validations observees:

```text
compileall: OK
tests complets: 515 OK
controle docs non-URL > 100 caracteres: OK
git status: indisponible dans ce checkout, pas un depot git
```
