# Architecture — Agent de pentesting autonome

> Document vivant. Décrit l'architecture *cible* de l'agent : modèle de
> planification, mémoire (court ET long terme), intégration des outils, boucle
> de raisonnement, et politique d'autonomie. Le TUI/TUX vise l'alignement avec
> Antigravity CLI (agy) ; le comportement agentique vise Claude Code / Codex CLI
> appliqués à la sécurité offensive.
>
> Statut : définition validée (autonomie = *semi-autonome par risque*, adaptatif).
> Reste à consolider le code existant vers cette cible (voir §8).

---

## 1. Principe directeur

L'agent est un **analyste senior augmenté** : il comprend ce qu'il fait,
s'adapte aux résultats, capitalise sur l'expérience passée, et documente ses
conclusions. Il n'est pas un wrapper LLM naïf.

Le patron architectural est nommé explicitement :

> **Blackboard (état de mission) + Case-Based Reasoning (mémoire long terme) +
> LLM-executor**, piloté par une boucle *plan → act → observe → reflect*.

**Règle d'or — séparation des pouvoirs (invariant testé) :**

| Couche | Pouvoir | Ne fait *jamais* |
|---|---|---|
| Planner | **propose** des actions candidates | exécuter un outil |
| LLM | **raisonne**, arbitre, justifie | court-circuiter le gate de sûreté |
| Sûreté | **autorise** (permission/scope/sudo) | proposer une action |
| Orchestration | **exécute** l'action autorisée | décider seule du périmètre |
| Mémoire long terme | **annote et priorise** | autoriser une exécution |

Aucune couche ne court-circuite la suivante. Le seul chemin vers l'exécution
d'un outil passe par le gate de sûreté.

---

## 2. Couches

```
┌──────────────────────────────────────────────────────────────┐
│ UI / TUX  — aligné agy (views/, renderer, input, statusline)  │
├──────────────────────────────────────────────────────────────┤
│ ORCHESTRATION — boucle agentique (plan/act/observe/reflect)   │
│                 + request_context (classification)            │
│                 + AutonomyPolicy (quand faire une pause)      │
├──────────────────────────────────────────────────────────────┤
│ COGNITION                                                     │
│   • Planner déterministe → NextAction[] (candidats)           │
│   • LLM (raisonnement libre + appel d'outils)                 │
│   • Ranking par expérience (CBR)                              │
├──────────────────────────────────────────────────────────────┤
│ MÉMOIRE / ÉTAT                                                │
│   court terme : ConversationMemory (fenêtre)  ─┐              │
│                 MissionContext (blackboard)    ├─ StructuredMemory → contexte LLM
│                 KnowledgeBase (faits extraits) ┘              │
│   long terme  : ExperienceStore (CaseLesson) — inter-missions │
├──────────────────────────────────────────────────────────────┤
│ OUTILS — registry, catégories, risk class, result_parser      │
├──────────────────────────────────────────────────────────────┤
│ SÛRETÉ — permissions, scope_guard, sudo, sandbox, preflight   │  (gate transversal)
└──────────────────────────────────────────────────────────────┘
```

### Correspondance avec le code existant

| Couche / brique | Fichier(s) |
|---|---|
| Boucle agentique | `core/agent.py` (`SecOpsAgent.stream_response`) — à scinder en `MissionLoop` |
| Classification de requête | `core/request_context.py` |
| Planner déterministe | `core/planner.py` (`MissionPlanner.plan` → `NextAction`) |
| LLM | `core/llm.py` |
| Ranking expérience (CBR) | `core/experience.py` (`evaluate_lesson_match`, `retrieve_similar_lessons`) |
| Blackboard de mission | `core/mission.py` (`MissionContext`, `PentestPhase`, `Finding`…) |
| Mémoire conversationnelle | `core/memory.py` (`ConversationMemory`) |
| Faits extraits | `core/structured_memory.py` (`KnowledgeBase`, `StructuredMemory`) |
| Mémoire long terme | `core/experience.py` (`ExperienceStore`, `CaseLesson`, `SuggestionSignal`) |
| Registry d'outils | `core/tools.py` (`ToolRegistry`, `@tool`, `ToolRiskClass`) |
| Parsing des sorties | `core/result_parser.py` — à scinder par famille d'outils |
| Sûreté | `core/permissions.py`, `scope_guard.py`, `sudo.py`, `sandbox.py`, `preflight.py` |

---

## 3. Boucle de raisonnement (plan → act → observe → reflect)

La boucle doit être **explicite** (un objet `MissionLoop`), et non plus noyée
dans une méthode `stream_response` de ~800 lignes. Elle peut enchaîner
*plusieurs* étapes ACT vers l'objectif de mission, dans la limite fixée par
l'`AutonomyPolicy` (§7) et un budget borné.

```
            ┌───────────────────────────────────────────────┐
            │              MISSION GOAL + SCOPE             │
            └───────────────────────┬───────────────────────┘
                                    ▼
  ┌──────────┐  briefing   ┌─────────────┐
  │ LONG-TERM│────────────▶│   PLAN      │  Planner.plan(mission) → NextAction[]
  │ MEMORY   │  (lessons)  │ (priorise)  │  rerank CBR + arbitrage LLM
  └────▲─────┘             └──────┬──────┘
       │ lesson                   ▼ action choisie
       │ + signal           ┌─────────────┐  gate Sûreté (permission/scope/sudo)
  ┌────┴─────┐  observe     │    ACT      │─────────────────────────────────▶ tool exec
  │ REFLECT  │◀─────────────│ (exécute)   │   ↳ AutonomyPolicy décide : pause ou continue
  │ (succès? │   parse      └──────┬──────┘
  │ FP? next)│                     ▼
  └────┬─────┘            ┌─────────────────┐
       │                  │    OBSERVE      │  result_parser → KnowledgeBase + MissionContext
       └─────────────────▶│ (met à jour     │  transition de phase ?
       update blackboard  │  l'état)        │
                          └─────────────────┘
              ↻ jusqu'à : objectif atteint │ budget épuisé │ pause requise (AutonomyPolicy)
```

**Étapes :**

- **PLAN** — `MissionPlanner.plan(mission)` génère des `NextAction` candidates
  *uniquement* à partir du blackboard courant (in-scope, phase courante).
  Reranking CBR par `CaseLesson`. Le LLM tranche entre candidats ex-aequo et
  peut proposer une action hors-catalogue — qui repasse par le même gate.
- **ACT** — passage **obligatoire** par le gate de sûreté. C'est ici que
  l'`AutonomyPolicy` décide : exécuter directement, ou demander une approbation
  (prompt agy, `ctrl+k` pour valider vite).
- **OBSERVE** — `result_parser` transforme la sortie d'outil en faits
  structurés (`KnowledgeBase` + mise à jour `MissionContext`), détecte une
  éventuelle transition de phase.
- **REFLECT** — écrit une `CaseLesson` / `SuggestionSignal`
  (efficace / inefficace / faux positif) qui nourrit la mémoire long terme
  **et** influence le rerank du tour suivant.

Conditions d'arrêt de la boucle : objectif atteint, budget épuisé (tours /
tokens / temps), ou pause exigée par l'`AutonomyPolicy`.

---

## 4. Modèle de planification (hybride)

Choix assumé : **planificateur déterministe + LLM arbitre**, pas « LLM pur ».

- **Générateur déterministe** (`NextAction`) : reproductible, auditable,
  testable, et structurellement sûr — il ne *peut* proposer que des actions
  dans le périmètre et la phase courants.
- **LLM en arbitre/explorateur** : choisit parmi les candidats, justifie le
  choix, peut proposer une action hors-catalogue → repasse par le gate.
- **Reranking CBR** : `evaluate_lesson_match` ajuste les priorités selon le
  vécu (compatibilité service / endpoint / risk / access).

**À formaliser :** un objet `Plan` de première classe (liste ordonnée de
`NextAction` + justification + budget), **persisté dans `MissionContext`**
plutôt que recalculé et jeté à chaque tour. Bénéfice : le plan devient
**inspectable dans le TUI** via `/plan` — très « agy ».

Lien phase ↔ outils : chaque `NextAction` est liée à une `ToolCategory` /
`ToolRiskClass` ; le planner ne propose pas d'exploitation en phase recon.

---

## 5. Mémoire — deux horizons séparés

### 5.1 Court terme (intra-mission)

Trois registres complémentaires, unifiés par `StructuredMemory` puis compactés
en contexte système injecté au LLM :

| Registre | Rôle | Source de vérité pour |
|---|---|---|
| `ConversationMemory` | fenêtre glissante de messages bruts | la récence du dialogue |
| `MissionContext` (**blackboard**) | vérités structurées de la mission | hosts, services, findings, phase, scope, trace |
| `KnowledgeBase` | faits extraits des sorties d'outils | données techniques observées |

> Le **blackboard** (`MissionContext`) est l'état canonique de la mission — pas
> la conversation. La conversation peut être tronquée ; le blackboard, non.

### 5.2 Long terme (inter-missions)

`ExperienceStore` persisté sur disque. Capitalise *sans ré-entraînement du
modèle* :

- `CaseLesson` : technique efficace/inefficace, faux positif validé, pattern
  récurrent — typé par service / endpoint / risk / access.
- `SuggestionSignal` : statistiques d'efficacité des suggestions passées.

**Flux « briefing de mission » (à câbler explicitement) :** au démarrage d'une
mission, `retrieve_similar_lessons(mission)` produit un encart injecté **une
fois** en tête de contexte *et* affiché dans le TUI :

> « D'après N missions passées sur des cibles similaires : priorise X,
> méfie-toi du faux positif Y. »

C'est la réalisation directe de « consultable en début de mission pour orienter
les priorités ». Aujourd'hui les leçons rerankent à chaque tour ; il manque
cette étape de briefing en amont.

**Invariant :** la mémoire long terme *annote et priorise*, elle **n'autorise
jamais** une exécution (cf. docstring `experience.py` — garder l'invariant
testé).

---

## 6. Intégration des outils

Ossature conservée (`registry` + `@tool` + `ToolRiskClass` + `result_parser`),
avec trois consolidations :

1. **Contrat de sortie unifié** : chaque outil renvoie un `ToolResult` dont le
   parsing vers le blackboard est *garanti*. Scinder `result_parser.py`
   (monolithe) en **un parser par famille** (nmap, ffuf, sqlmap, nuclei…),
   co-localisé avec l'outil. Un outil sans parser ⇒ ses résultats ne nourrissent
   pas la mémoire ⇒ angle mort de l'étape OBSERVE.
2. **Tout outil = action planifiable** : `NextAction` peut référencer n'importe
   quel outil du registry par capacité. Lier `ToolCategory` / `ToolRiskClass` à
   la phase de mission.
3. **Chemin d'exécution unique** : aucun `subprocess` hors `tools/` ; tout passe
   par le gate de sûreté.

---

## 7. Politique d'autonomie (`AutonomyPolicy`)

**Défaut : semi-autonome par risque.** Déclencheur de pause = `ToolRiskClass`.

| Risque de l'outil | Comportement par défaut |
|---|---|
| Bas (recon, énumération non-destructive) | exécution autonome, en chaîne |
| Élevé (exploitation, écriture, destructif, sudo) | **pause → approbation** (prompt agy, `ctrl+k`) |

Pourquoi ce défaut : (1) réutilise la taxonomie `ToolRiskClass` déjà en place ;
(2) seul défaut *sûr pour n'importe quelle cible* (aucun dégât irréversible sans
humain dans la boucle) ; (3) fidèle à la philosophie `request-review` d'agy
(pause avant ce qui affecte le système) ; (4) ratio vitesse/contrôle d'un
analyste senior.

**Adaptatif selon l'environnement** (via l'`EnvironmentHint` déjà calculé par
`request_context`) :

```
EnvironmentHint = CTF / LAB        →  escalade auto vers « autonome supervisé »
                                       (checkpoint seulement aux transitions de
                                        phase et actions destructrices)
EnvironmentHint = CLIENT / inconnu →  reste « semi-autonome par risque » (sûr)
```

`AutonomyPolicy` est un **objet de première classe** dans la couche
Orchestration. Le flag historique `allow_automatic_planner_execution` en est
l'embryon et doit être absorbé. Override manuel toujours disponible
(`/auto`, `/permissions`) — comme agy. Le TUX (prompt d'approbation,
statusline, `ctrl+k`) reste identique à agy quel que soit le niveau.

---

## 8. Écart vers la cible & plan de consolidation

L'architecture ci-dessus est à ~80 % présente en composants. Il manque surtout
de l'**explicitation** et de la **découpe**. Ordre recommandé :

| # | Chantier | Pourquoi d'abord |
|---|---|---|
| 0 | **`git init` + commit initial** | 32k lignes sans historique ; aucun refactor sûr sans filet |
| 1 | Outillage qualité (ruff, pytest, CI) ; MAJ `AGENTS.md` (33 tests existent) | rend les refactors suivants vérifiables |
| 2 | Extraire `AutonomyPolicy` (absorbe `allow_automatic_planner_execution`) | décision d'archi centrale (§7) |
| 3 | Extraire `MissionLoop` de `stream_response` (boucle explicite §3) | lisibilité + testabilité du cœur |
| 4 | Câbler le **briefing de mission** (`retrieve_similar_lessons` en amont) §5.2 | réalise l'exigence mémoire long terme |
| 5 | Objet `Plan` persistant + `/plan` dans le TUI (§4) | plan inspectable, très agy |
| 6 | Scinder `result_parser.py` par famille d'outils (§6) | supprime les angles morts d'OBSERVE |
| 7 | Découpe UI `renderer.py` → `ui/views/` (cf. revue TUX) | aligne les surfaces sur le modèle agy |

> Principe : **0 et 1 avant tout refactor** ; ensuite, un chantier à la fois,
> tests verts entre chaque.

### Décisions de parité TUI actées

- **Glyphe des lignes outil** : toujours `●` (plein) ; l'état est encodé par la
  **couleur** (jaune pending/running, vert succès, rouge erreur) + un **spinner**
  pendant l'exécution. Vérifié sur le transcript officiel agy (codelab). Pas
  d'état `○` vide.
- **Politique d'approbation R11** (`_approval_options`) : **divergence sécurité
  volontaire**. agy offre « Always Allow / Persist » pour tout et sécurise via
  une liste `alwaysDeny` ; pour un agent offensif, « Persist to settings.json »
  n'est offert que pour les ressources à faible risque. Plus strict qu'agy, par
  conception.
- **Suggestions argumentées** (`_render_suggested_actions`) : une ligne `Lesson:`
  concise par suggestion (le *pourquoi*), internals `Match:`/`Missing:` masqués.

### TODO lié à la boucle (chantier 2 — AutonomyPolicy)

- `test_exploit_request_sends_no_function_tools_by_default` est marqué
  `@unittest.expectedFailure`. Aujourd'hui l'agent envoie les schémas d'outils
  d'exploitation par défaut ; l'`AutonomyPolicy` doit retenir ces schémas tant
  que l'utilisateur n'a pas approuvé un plan (gating de `ToolSchemaSelector` par
  risque/approbation). Retirer le décorateur quand le test passe.
