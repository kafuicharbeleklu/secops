# Étude UX & recherche comparative — Modernisation TUI/TUX

Date : 2026-09-01
Périmètre : recherche en ligne (conventions 2026 des CLI/TUI agentiques) + lecture du code
d'interface réel, aboutissant à des propositions **sourcées et vérifiées pour leur
faisabilité**. Aucune modification du code applicatif (`secops_agent/`, `core/`). Un seul
prototype jetable a été écrit et exécuté : `scratch/ux_research_probe.py`.

Suite de `docs/UX_AUDIT_2026-08-27.md` : les constats `P1-xx`/`P2-xx`/`P3-xx` ne sont pas
rediagnostiqués — ils sont **référencés** et cette passe cherche *comment* les combler, en
s'appuyant sur ce que font aujourd'hui Claude Code, Codex CLI, Antigravity CLI et le
paysage TUI plus large.

---

## Résumé exécutif

**23 propositions**, réparties ainsi :

| Dimension | Propositions | IDs |
|---|---:|---|
| 1 — Animations & retours transitoires | 5 | `ANIM-01…05` |
| 2 — Format des réponses | 6 | `FMT-01…06` |
| 3 — Traitement (interaction/erreurs/processus) | 7 | `PROC-01…07` |
| 4 — Au-delà (chrome, accessibilité, onboarding) | 5 | `X-01…05` |

### Verdict architectural (question tranchée en premier)

**Conserver le couple actuel `prompt_toolkit` (saisie + touches) + `rich` (rendu). Ne PAS
migrer vers Textual.** SecOps Agent est *déjà* ce hybride : `rich` est importé dans 12
fichiers de `ui/` (renderer, tool_display, animations, overlay, theme, panels…),
`prompt_toolkit` dans seulement 3 (saisie, complétion, key-bindings). Les **23** propositions
sont réalisables sur cette pile : **20** avec des primitives `rich` déjà installées
(`Progress`, `Table`, `Syntax`, `Live`, `Console` markup/liens — v15.0.0), **3** avec le
`bottom_toolbar` / les key-bindings / l'`Application` plein écran de `prompt_toolkit`. Aucune
n'exige Textual. Détail et déclencheurs de réévaluation en **§ Verdict architectural**.

### Les 5 premières à traiter (justification en fin de document)

`FMT-01` (couleur par sévérité du badge R0–R8) · `FMT-06` (statusline persistante, `P1-01`) ·
`PROC-01` (vrai mode plan lecture seule, `P2-01`) · `ANIM-01` (barres de progression
déterminées pour les scans) · `PROC-03` (confirmation renforcée pour R6/R8).

---

## Verdict architectural — `prompt_toolkit` vs bibliothèque additionnelle vs migration

**Contexte réel.** La pile n'est pas « `prompt_toolkit` seul ». C'est un partage de
responsabilités déjà en place :

- **`prompt_toolkit`** : la ligne de saisie, la complétion slash (`SlashCommandCompleter`),
  le `bottom_toolbar` (statusline courte + modèle), les raccourcis. → `ui/input_handler.py`.
- **`rich`** : tout le transcript. `Console.print`, `Markdown(code_theme="ansi_dark")`,
  `Live` (streaming throttlé ~20 fps, `vertical_overflow="crop"`), `Status` (spinners
  `agy_dots`), `Padding`, panneaux. → `ui/renderer.py` (4218 lignes), `ui/tool_display.py`,
  `ui/animations.py`.

C'est **exactement** le découpage que les agents de référence n'évitent qu'en écrivant un
moteur de rendu sur mesure : Claude Code utilise un réconciliateur type React/Ink en
JavaScript ([ch13-terminal-ui](https://github.com/mikeoptimax/claude-code-architecture/blob/main/book/ch13-terminal-ui.md),
consulté 2026-09-01), Codex CLI a été réécrit en Rust sur **Ratatui + crossterm + tokio**
en rendu *immediate-mode* ([codex-rs architecture](https://codex.danielvaughan.com/2026/03/28/codex-rs-rust-rewrite-architecture/),
consulté 2026-09-01). Aucun des deux n'utilise Textual.

**Trois options évaluées :**

1. **Rester sur `prompt_toolkit` + `rich` (RETENU).** `rich` 15.0.0 fournit déjà `Progress`
   (barres déterminées), `Syntax` (coloration), `Table` (responsive), les liens OSC 8 via
   markup `[link=…]`, et `Live`/`Status` pour l'animation. 20 des 23 propositions tombent
   ici. Effort par proposition, risque local, rien ne casse.
   *Validé* : `scratch/ux_research_probe.py` exécute barre de progression déterminée, badges
   colorés par sévérité, séquence OSC 9;4 et rendu `NO_COLOR` sans erreur sur la pile
   installée.

2. **Ajouter une bibliothèque ponctuelle.** Inutile : aucune proposition ne demande une
   dépendance nouvelle. `rich.progress`, `rich.syntax`, `rich.table` couvrent tout ce qui,
   ailleurs, justifierait « ajouter Rich ». (Note : Textual *est* construit sur Rich — le
   moteur de rendu est donc déjà présent.)

3. **Migrer vers Textual (REJETÉ pour l'instant).** Textual remplace le modèle applicatif
   par une boucle d'événements asynchrone, un layout CSS et **sa propre gestion des
   entrées** — il entrerait en collision frontale avec la couche `prompt_toolkit` existante
   et imposerait de réécrire le transcript `rich` (renderer de 4218 lignes). Ce que Textual
   débloque (souris, layout CSS, widgets « vivants » multi-panneaux façon k9s) n'est pas ce
   dont un **agent à transcript déroulant** a besoin — c'est le modèle de Claude Code et de
   Codex, pas celui de k9s/lazygit.
   Réf. paysage : [Charm v2](https://charm.land/blog/v2/) (Bubble Tea/Lip Gloss v2 : rendu
   optimisé, compositing avancé, API déclarative) et [awesome-ratatui](https://github.com/ratatui/awesome-ratatui),
   consultés 2026-09-01 — utiles comme inspiration, pas comme cible de portage (écosystèmes
   Go/Rust).

**Déclencheurs de réévaluation (« reconsidérer Textual si… »).** Si un objectif produit
futur exige un **tableau de bord plein écran multi-panneaux persistant** (p. ex. un « mission
board » live à côté du transcript, une vue findings drill-down façon k9s), alors `rich`+`pt`
montrent leurs limites (pas de layout retenu multi-région sans réimplémenter un moteur) et
Textual devient le bon choix. Tant que la surface reste un transcript + overlays, non.

**Nuance de faisabilité importante (impacte `FMT-06`).** Le `bottom_toolbar` de
`prompt_toolkit` n'est visible **que pendant la saisie**. Pendant un outil long (rendu par
le côté `rich`), il n'existe plus : la ligne d'état persistante doit donc être portée *aussi*
par le footer du `Status` `rich` (le paramètre `status_right` de `ThinkingSpinner`/
`ToolExecutionSpinner` existe déjà pour ça). Toute proposition « visible en permanence »
doit couvrir les deux surfaces — c'est noté au cas par cas.

---

## Dimension 1 — Animations & retours visuels transitoires

État actuel : `ui/animations.py` — `ThinkingSpinner`/`ToolExecutionSpinner` sur `rich.Status`
avec spinner `agy_dots`, timer elapsed rafraîchi chaque seconde, `WAIT_TIPS` en rotation
(4 s) et footer `esc to cancel`. Streaming : `rich.Live` throttlé ~20 fps
(`renderer.py:3876+`). `ToolProgressEvent(phase, detail, percent)` est déjà émis et consommé
(`renderer.py:4069`, `_update_tool_feedback`), mais **`percent` n'est pas rendu** en barre.

### ANIM-01 — Barres de progression *déterminées* pour les scans longs
- **Audit lié :** — (complète `P3-01`, observabilité).
- **Composant :** `ui/animations.py` (`ToolExecutionSpinner`) ; `renderer.py:4069`
  (`ToolProgressEvent`) ; `_update_tool_feedback`.
- **Proposé :** quand un `ToolProgressEvent.percent` est disponible (nmap ports scannés,
  gobuster/ffuf requêtes, listes de mots), afficher une **barre `rich.Progress` déterminée**
  au lieu du seul spinner + elapsed. Repli sur spinner indéterminé si `percent is None`.

  ```
  ⠹ Nmap 10.0.0.5 (1000 ports)  ━━━━━━━━━━━╺━━━━━━━━  58%  0:00:12
      ⎿ phase: syn-scan · 580/1000 ports
  ```
- **Référence(s) :** Claude Code expose des composants `ProgressBar`/`Spinner`
  ([dev.to/minnzen — toolkit tiré du source](https://dev.to/minnzen/i-studied-claude-codes-leaked-source-and-built-a-terminal-ui-toolkit-from-it-4poh)) ;
  demande explicite d'un indicateur de progression pendant l'exécution d'outil
  ([claude-code#60320](https://github.com/anthropics/claude-code/issues/60320)) ;
  Codex affiche « blended token usage » et un affichage riche par session
  ([codex release notes](https://www.havoptic.com/tools/openai-codex)). Consultés 2026-09-01.
- **Faisabilité :** **directe** — `rich.progress.Progress(BarColumn, TimeElapsedColumn…)`
  déjà présent ; le flux `percent` existe déjà côté agent. Coexistence `Progress`/`Live`
  validée par le prototype.
- **Effort :** M. **Prototype :** `scratch/ux_research_probe.py` (ANIM-03 dans le script).

### ANIM-02 — Progression au niveau du terminal hôte (OSC 9;4), persistante sur tout le tour
- **Audit lié :** —
- **Composant :** `ui/renderer.py` (boucle d'événements streaming), `ui/animations.py`.
- **Proposé :** émettre la séquence **OSC 9;4** (barre de progression dans la barre des
  tâches / l'onglet du terminal : WezTerm, Windows Terminal, ConEmu…) au début du tour,
  la maintenir pendant *toute* la séquence d'outils, l'effacer à la fin. Donne un signal
  « ça travaille » même quand le terminal n'a pas le focus.
- **Référence(s) :** Claude Code a corrigé le *flickering* de l'indicateur OSC 9;4 pour
  qu'il « reste visible sur tout le tour » ([changelog](https://code.claude.com/docs/en/changelog),
  entrée sur OSC 9;4, consulté 2026-09-01). Gestion des barres de progression terminal
  demandée de longue date ([claude-code#2686](https://github.com/anthropics/claude-code/issues/2686)).
- **Faisabilité :** **directe** — simple `sys.stdout.write` d'une séquence ANSI, gardée par
  `is_terminal`. Aucune interaction avec `prompt_toolkit`. Séquence validée par le prototype.
- **Effort :** S. **Prototype :** `scratch/ux_research_probe.py` (ANIM-04 dans le script).

### ANIM-03 — Le spinner « chauffe » avec la durée (ambre après ~10 s)
- **Audit lié :** —
- **Composant :** `ui/animations.py` — `ThinkingSpinner._status_message`, `spinner_style`.
- **Proposé :** faire évoluer la **couleur** du spinner selon `elapsed` : accent → ambre
  (~10 s) → ambre soutenu (~30 s). Signale « toujours en cours » sur les tours lents (le
  modèle *flash* par défaut génère des `429`/`500` : les tours longs existent).
- **Référence(s) :** Claude Code — « the spinner now warms to amber after 10 seconds to
  signal Claude is still working during long thinking periods »
  ([recherche UI Claude Code](https://code.claude.com/docs/en/changelog), consulté 2026-09-01).
- **Faisabilité :** **directe** — `Status.update(...)` accepte déjà un style ; le timer 1 s
  existe (`_update_timer`). Palette dispo dans `theme.py` (`accent`, `warning`).
- **Effort :** S. **Prototype :** —

### ANIM-04 — Libellés de phase *sémantiques* plutôt que « Thinking… » + tips génériques
- **Audit lié :** —
- **Composant :** `ui/animations.py` — `WAIT_TIPS`, `format_wait_message`,
  `extract_thought_summary` (déjà présent mais sous-exploité) ; `_running_label_for_elapsed`.
- **Proposé :** remplacer le texte statique par un libellé qui reflète la **phase réelle**
  (`planning`, `recon`, `analyzing nmap output`, `deciding next step`) — `MissionContext`
  expose déjà la phase, et `ToolProgressEvent.phase` la porte pendant l'outil. Garder la
  rotation de tips comme repli quand aucune phase n'est connue.
- **Référence(s) :** Claude Code — indicateur inline « still thinking / thinking more /
  almost done thinking » remplaçant la ligne de tip séparée, et rotation de verbes + elapsed
  ([changelog / architecture ch13](https://github.com/mikeoptimax/claude-code-architecture/blob/main/book/ch13-terminal-ui.md),
  consulté 2026-09-01).
- **Faisabilité :** **directe** — le câblage phase→libellé est du texte ; `extract_thought_summary`
  existe déjà. Attention à ne PAS exposer le contenu brut du *thinking* (respecter la
  frontière ASI01 : résumé de phase, pas fuite de raisonnement sensible).
- **Effort :** M. **Prototype :** —

### ANIM-05 — Mode « mouvement réduit » (SSH, terminal lent, accessibilité)
- **Audit lié :** — (croise `X-02`).
- **Composant :** `ui/animations.py` (spinner `none` **déjà défini** mais non câblé),
  factory de `Console`.
- **Proposé :** un interrupteur (`SECOPS_REDUCED_MOTION=1`, `NO_COLOR`, ou terminal non-TTY
  déjà détecté via `is_terminal`) qui : bascule sur le spinner `none` (texte live sans
  glyphe rotatif), réduit la fréquence de rafraîchissement du `Live`, et coupe les
  transitions. Améliore l'usage sur liens SSH/mosh lents — cas explicitement soigné par les
  agents de référence (voir corrections « slow SSH/mosh links » du changelog Claude Code).
- **Référence(s) :** [clig.dev](https://clig.dev/) (respecter l'environnement, dégrader
  proprement) ; norme [NO_COLOR](https://no-color.org/) ; corrections Claude Code liées aux
  liens lents (changelog, consulté 2026-09-01).
- **Faisabilité :** **directe** — le spinner `none` et la détection `is_terminal` existent
  déjà ; il manque le câblage à une préférence unique.
- **Effort :** S. **Prototype :** `scratch/ux_research_probe.py` (X-02, `console_factory`).

---

## Dimension 2 — Format des réponses

État actuel : Markdown via `rich.Markdown(code_theme="ansi_dark")` (titres/listes/tableaux/
code colorés — bon). Résultats d'outils : lignes `● Tool(arg) (ctrl+o to expand)` +
`⎿ résumé` (`ui/tool_display.py`), badge de risque **déjà présent** (`_tool_risk_badge`
→ `R0`…`R8`) mais rendu en gris plat `text_dim`. Un seul thème (sombre) ; `NO_COLOR` non
honoré ; `renderer.py:348 force_terminal=False`.

### FMT-01 — Couleur **par sévérité** du badge R0–R8 (déjà rendu, mais gris plat)
- **Audit lié :** **`P1-02`** (la classe de risque doit être immédiatement distinguable).
- **Composant :** `ui/tool_display.py` — `_tool_risk_badge` (l.197), `ToolCallBox.render`
  (l.660, badge imprimé en `COLORS['text_dim']`).
- **Proposé :** mapper le tier → couleur pour qu'un `R8` (action distante créditée) ne
  ressemble pas à un `R0` (calcul local). Ne rien ajouter — **colorer** l'existant.

  ```
  ● Whois(example.com)         R2      (gris/cyan — observation)
  ● Nmap(10.0.0.5)             R3      (jaune — énumération active)
  ● GeneratePayload(win/x64)   R6      (rouge — exploit)
  ● <mcp>DeployKey(prod)       R8      (rouge gras — distant/identité)
  ```
- **Référence(s) :** principe de moindre surprise / « la couleur est un signal »
  ([clig.dev](https://clig.dev/), consulté 2026-09-01) ; Antigravity encode l'**état** d'un
  outil par la couleur du `●` (déjà suivi dans `_tool_status_color`) — même logique appliquée
  à la **sévérité**. Palette dispo (`theme.py`).
- **Faisabilité :** **directe** — 9 entrées de dictionnaire tier→couleur. **Validé** par le
  prototype (R0 gris → R8 rouge gras ; correctement neutralisé sous `NO_COLOR`).
- **Effort :** S. **Prototype :** `scratch/ux_research_probe.py` (FMT-02 dans le script).

### FMT-02 — Cartes de résultat *structurées* : résumé tabulaire repliable, pas un dump brut
- **Audit lié :** **`P3-01`** (13 outils sans parser structuré).
- **Composant :** `ui/tool_display.py` (`ToolResultBox`), `core/result_parsers/*`,
  `renderer.py` (expansion `ctrl+o`).
- **Proposé :** pour les sorties structurables (ports nmap, répertoires gobuster, findings),
  rendre un **`rich.Table` de résumé** (p. ex. Port/État/Service) en vue collapsée, le détail
  brut restant derrière `ctrl+o`. Applique le principe « artefact revu, pas transcript brut »
  du repère Antigravity déjà cité dans l'audit précédent.

  ```
  ⎿ Nmap 10.0.0.5 — 3 ports ouverts / 1000
     ┌───────┬────────┬─────────────┐
     │ Port  │ État   │ Service     │
     ├───────┼────────┼─────────────┤
     │ 22    │ open   │ ssh         │
     │ 80    │ open   │ http        │
     │ 443   │ open   │ https       │
     └───────┴────────┴─────────────┘
     (ctrl+o : sortie nmap brute)
  ```
- **Référence(s) :** Codex a ajouté des « responsive Markdown tables » et un affichage par
  session data-driven ([codex release notes](https://www.havoptic.com/tools/openai-codex)) ;
  lazygit/k9s : synthèse scannable + drill-down
  ([9 TUI apps](https://medium.com/the-software-journal/9-tui-apps-so-good-i-stopped-opening-my-browser-a4c622e438c0)).
  Consultés 2026-09-01.
- **Faisabilité :** **directe** côté rendu (`rich.Table`) ; dépend de `P3-01` pour disposer
  des données parsées (le résumé tabulaire est le *débouché* naturel de ces parseurs).
- **Effort :** M. **Prototype :** —

### FMT-03 — Tableaux Markdown responsives + défilement horizontal du contenu large
- **Audit lié :** —
- **Composant :** `renderer.py` (rendu `Markdown`/`Table`), `overlay.view_logs_overlay`.
- **Proposé :** aux largeurs étroites, éviter le débordement/tronquage des tableaux : soit
  compactage responsive (masquer colonnes secondaires), soit renvoi du bloc large vers le
  **pager existant** (`view_logs_overlay`, avec recherche) pour un défilement horizontal.
- **Référence(s) :** Codex — « responsive Markdown tables »
  ([release notes](https://www.havoptic.com/tools/openai-codex)) ; Claude Code a corrigé un
  crash de tableau/barre de progression en terminal très étroit
  ([changelog 2.1.229](https://code.claude.com/docs/en/changelog)). Consultés 2026-09-01.
- **Faisabilité :** **directe** — `rich.Table` connaît la largeur de `Console` ; le pager
  existe déjà (réutilisation).
- **Effort :** M. **Prototype :** —

### FMT-04 — Blocs de preuve à coloration syntaxique (`rich.Syntax`) pour code/JSON/HTTP
- **Audit lié :** —
- **Composant :** `ui/tool_display.py` (`ToolResultBox`), parseurs web/exploit.
- **Proposé :** rendre les payloads (requêtes/réponses HTTP, extraits JSON, snippets de
  code, diffs déjà partiellement gérés pour `write_file`) via `rich.Syntax` avec langage
  détecté, plutôt qu'en texte brut. Améliore la lisibilité des preuves d'un finding.
- **Référence(s) :** « modern TUI apps have syntax highlighting »
  ([essential CLI/TUI tools](https://itnext.io/essential-cli-tui-tools-for-developers-7e78f0cd27db)) ;
  Glamour/Charm pour le rendu Markdown/code soigné ([Charm](https://charm.land/blog/v2/)).
  Consultés 2026-09-01.
- **Faisabilité :** **directe** — `rich.Syntax` déjà installé.
- **Effort :** S/M. **Prototype :** —

### FMT-05 — Thème clair/sombre + adaptation au fond du terminal + `/theme`
- **Audit lié :** —
- **Composant :** `ui/theme.py` (**une seule** palette sombre `COLORS`, aucune variante
  claire, `/theme` inexistant), `renderer.py:348`.
- **Proposé :** extraire la palette en thèmes nommés (sombre/clair/haut-contraste), une
  commande `/theme`, et une détection du fond (COLORFGBG / requête OSC 11) avec repli sûr.
  Les couleurs « austères » actuelles supposent un fond sombre ; sur terminal clair, les gris
  `text_muted`/`text_dim` deviennent illisibles.
- **Référence(s) :** Claude Code a un `/theme` et respecte la couleur de bordure d'un thème
  custom ([changelog 2.1.246 `/rename`/`promptBorder`](https://code.claude.com/docs/en/changelog)) ;
  [clig.dev](https://clig.dev/) (ne pas présumer du fond). Consultés 2026-09-01.
- **Faisabilité :** **directe** — `theme.py` est déjà « source unique de vérité » ; il s'agit
  de la paramétrer. (Croise `X-02`.)
- **Effort :** M. **Prototype :** —

### FMT-06 — Statusline persistante (contexte opérationnel toujours lisible)
- **Audit lié :** **`P1-01`** (la statusline riche existe mais reste en overlay).
- **Composant :** `ui/input_handler.py` — `_build_statusline` (l.1083), `_get_toolbar`
  (l.1129), `bottom_toolbar` ; charge utile `_statusline_payload` (`main.py:444-457`) ;
  footer `status_right` du `Status` (`animations.py`).
- **Proposé :** rendre en continu modèle · phase · permission · autonomie · ~tokens
  (idéalement coût) · sandbox — **sur les deux surfaces** : le `bottom_toolbar` pendant la
  saisie *et* le footer `status_right` du spinner pendant un outil (voir la nuance de
  faisabilité du verdict architectural). Les données sont déjà toutes calculées ;
  aujourd'hui seules « aide courte + modèle » survivent au rendu courant.

  ```
  gemini-2.5-flash · recon · perm:request-review · auto:copilot · ~12.3k tok · sandbox
  ```
- **Référence(s) :** Claude Code — footer d'items alignés à droite (goal/état/agent en
  fond) et lignes de coût/usage dans la statusline
  ([changelog 2.1.234 / 2.1.251](https://code.claude.com/docs/en/changelog)) ; Codex —
  « blended token usage », « permissions/approval mode », « effective workspace roots » dans
  le TUI ([release notes](https://www.havoptic.com/tools/openai-codex)). Consultés 2026-09-01.
- **Faisabilité :** **directe pour la saisie** (`bottom_toolbar`, données déjà là) ;
  **nécessite le footer `rich`** pour la phase « outil en cours » (le `bottom_toolbar` n'est
  pas rendu à ce moment) — le champ `status_right` existe déjà.
- **Effort :** S (saisie) → M (couverture des deux surfaces). **Prototype :** —

---

## Dimension 3 — Traitement (interaction, erreurs, processus longs)

État actuel : interruption `esc`/`Ctrl-C` déjà solide (`_EscInterruptMonitor`,
`renderer.py:610+`, `main.py:1933 SIGINT`). Approbation : `request_approval`
(`tool_display.py:868`) — flèches + entrée, **première option « Allow once » présélectionnée
même pour un outil destructeur**. Pager avec recherche : `overlay.view_logs_overlay` (l.502)
— mais réservé aux logs. Reprise de session : `resolve_resume_target` existe
(`cli/sessions.py:162`, `main.py:1636`) mais peu exposée. Commande inconnue : simple
`Unknown command: {cmd}` (`main.py:1642`).

### PROC-01 — Vrai mode plan *lecture seule* (session sans exécution)
- **Audit lié :** **`P2-01`** (Élevée).
- **Composant :** `core/autonomy.py` (`AutonomyLevel.COPILOT` défini, non exposé),
  `main.py:1711+` (modes CLI), `/plan` (affiche un plan, ne verrouille pas la session).
- **Proposé :** un mode permission `plan` qui **garantit zéro appel d'outil mutating** :
  le modèle planifie, cite des preuves du contexte, mais aucune exécution n'est possible
  (pas même « approuvable »). Distinct de `strict` (qui autorise après approbation).
- **Référence(s) :** Claude Code — `--permission-mode plan` est un mode de permission à part
  entière ([CLI usage](https://docs.anthropic.com/en/docs/claude-code/cli-usage), déjà cité
  `P2-01`, consulté 2026-09-01) ; Antigravity expose aussi un mode `plan` et un mode
  `strict`/lecture seule ([neurals — permission modes](https://neurals.ca/tech/gemini/antigravity/permission-modes/),
  [aibuilderclub](https://www.aibuilderclub.com/blog/antigravity-cli-guide)), consultés
  2026-09-01. (NB : les sources tierces divergent sur la taxonomie exacte des modes agy —
  voir `PROC-02`.)
- **Faisabilité :** **directe côté politique** — `COPILOT` existe ; c'est du câblage
  `AutonomyPolicy` (ne pas exposer de schéma d'outil mutating) + une entrée CLI/`Shift+Tab`.
  À traiter dans `core/` (hors périmètre de cette passe) : proposition, pas implémentation.
- **Effort :** M. **Prototype :** —

### PROC-02 — Cyclage `Shift+Tab` des modes de permission + indicateur de mode toujours visible
- **Audit lié :** complète `P1-01`/`P2-01`.
- **Composant :** key-bindings `prompt_toolkit` (`input_handler.py`), statusline (`FMT-06`),
  modes de `main.py:1711`.
- **Proposé :** cycler `request-review → proceed-in-sandbox → always-proceed → strict/plan`
  via `Shift+Tab`, avec le mode courant affiché en permanence (couleur distincte par
  posture, cf. `FMT-01`). Rend l'autonomie « opt-in et visible », jamais un défaut caché.
- **Référence(s) :** Antigravity — « Press Shift+Tab … to cycle default, accept-edits,
  plan » ([aibuilderclub](https://www.aibuilderclub.com/blog/antigravity-cli-guide)) ;
  Claude Code — indicateur de mode de permission, corrigé pour rester visible
  ([changelog 2.1.246](https://code.claude.com/docs/en/changelog)). Consultés 2026-09-01.
- **Faisabilité :** **directe** — key-binding `prompt_toolkit` + affichage ; la mécanique de
  modes existe déjà en CLI.
- **Effort :** M. **Prototype :** —

### PROC-03 — Confirmation renforcée pour les approbations R6/R8 (destructif/distant)
- **Audit lié :** complète `P1-02`.
- **Composant :** `ui/tool_display.py` — `_approval_options`/`_approval_lines`/
  `request_approval` (l.516-620, 868+), `selected = 0` présélectionne « Allow once ».
- **Proposé :** pour un `risk_class ≥ R6`, **ne pas présélectionner « Allow once »** :
  présélectionner « No », et/ou exiger une confirmation explicite (« type to confirm » :
  saisir le nom de l'outil, ou la cible). Réduit l'approbation par réflexe d'une action
  irréversible. Aligné avec la divergence sécurité déjà assumée dans `_approval_options`
  (pas d'« always allow » pour les outils sensibles).

  ```
  Permission — GeneratePayload(windows/x64/meterpreter)   R6 exploit assistance
  Cette action est offensive et irréversible.
  Tapez le nom de l'outil pour confirmer :  ______________
  > (par défaut : No)
  ```
- **Référence(s) :** [clig.dev](https://clig.dev/) — confirmer avant l'irréversible, défaut
  sûr ; motif « type-to-confirm » standard (suppressions GitHub/`kubectl`-style). Codex
  expose un « approval mode » distinct par niveau de risque
  ([release notes](https://www.havoptic.com/tools/openai-codex)). Consultés 2026-09-01.
- **Faisabilité :** **directe** — la boucle `run_tui`/`read_key` existe ; ajouter une branche
  de saisie et changer le `selected` par défaut selon le tier.
- **Effort :** S/M. **Prototype :** —

### PROC-04 — Sémantique d'annulation : double `Ctrl-C` pour quitter + annulation mi-outil explicite
- **Audit lié :** —
- **Composant :** `main.py:1933` (SIGINT), `renderer.py:610+` (`interrupt`),
  `ui/animations.py` (footer `esc to cancel`).
- **Proposé :** conserver `esc`/`Ctrl-C` = interrompre la génération/l'outil (déjà bien), et
  ajouter l'affordance « appuyez à nouveau sur Ctrl-C pour quitter » + un message clair
  quand un outil est réellement annulé en cours (vs. simplement la génération).
- **Référence(s) :** Claude Code — hint « Press Ctrl-C again to exit » et gestion fine de
  l'interruption ([changelog 2.1.246](https://code.claude.com/docs/en/changelog),
  « permission mode indicator … behind the Ctrl-C hint »). Consulté 2026-09-01.
- **Faisabilité :** **directe** — le handler SIGINT et le moniteur d'interruption existent ;
  ajouter un état « premier Ctrl-C » + le texte.
- **Effort :** S. **Prototype :** —

### PROC-05 — Pagination/scroll des sorties volumineuses (réutiliser le pager existant)
- **Audit lié :** —
- **Composant :** `overlay.view_logs_overlay` (l.502, **pager avec recherche déjà là**),
  `renderer.py` (expansion `ctrl+o` actuellement inline), `/artifact`.
- **Proposé :** router les grosses sorties d'outil et la vue `/artifact` vers
  `view_logs_overlay` (défilement + recherche) au lieu d'un flux inline qui inonde le
  transcript. Étend un composant déjà écrit plutôt que d'en créer un.
- **Référence(s) :** k9s — navigation en pile drill-down, `?` pour l'aide ; lazygit —
  panneaux persistants et défilement
  ([9 TUI apps](https://medium.com/the-software-journal/9-tui-apps-so-good-i-stopped-opening-my-browser-a4c622e438c0),
  [awesome-ratatui](https://github.com/ratatui/awesome-ratatui)). Consultés 2026-09-01.
- **Faisabilité :** **directe** — le pager existe (`view_logs_overlay`) ; c'est un
  branchement de surface.
- **Effort :** M. **Prototype :** —

### PROC-06 — Récupération d'erreur de commande : « vouliez-vous dire… » + exemple
- **Audit lié :** **`P2-02`** (Faible).
- **Composant :** `main.py:1642` (`Unknown command: {cmd}`), `ui/commands.py`
  (`CommandSpec` : descriptions + usages **déjà présents**), complétion.
- **Proposé :** sur commande inconnue, proposer la plus proche (distance de Levenshtein sur
  les `CommandSpec`), afficher son usage et un exemple exécutable ; enrichir la complétion
  avec la syntaxe complète, pas seulement la description.
- **Référence(s) :** [clig.dev](https://clig.dev/) — une CLI doit être découvrable et guider
  l'erreur vers la correction (déjà cité `P2-02`, consulté 2026-09-01) ; Claude Code — menu
  slash amélioré (caractères correspondants en gras, sélection lisible)
  ([changelog 2.1.227](https://code.claude.com/docs/en/changelog)).
- **Faisabilité :** **directe** — les specs de commandes portent déjà usage/description.
- **Effort :** S. **Prototype :** —

### PROC-07 — Découvrabilité de la reprise de session (`/resume` + hint au démarrage)
- **Audit lié :** —
- **Composant :** `cli/sessions.py:162` (`resolve_resume_target`, **existe**),
  `main.py:1636`, bannière de démarrage.
- **Proposé :** exposer un sélecteur `/resume` (liste des sessions récentes, titres) et un
  hint de démarrage « `--continue` pour reprendre la dernière session ». La mécanique est là,
  la surface manque.
- **Référence(s) :** Claude Code — `/resume`/`--continue`, titres de session courts et
  lisibles ([changelog 2.1.234 / 2.1.229](https://code.claude.com/docs/en/changelog)) ;
  Codex — dashboard d'agents (chercher/ouvrir/reprendre des tâches)
  ([release notes](https://www.havoptic.com/tools/openai-codex)). Consultés 2026-09-01.
- **Faisabilité :** **directe** — réutilise `resolve_resume_target` + un overlay de choix
  (`overlay.choose_overlay` existe).
- **Effort :** S/M. **Prototype :** —

---

## Dimension 4 — Au-delà (chrome, accessibilité, onboarding)

### X-01 — Overlay d'aide contextuel `?` (carte des raccourcis du contexte courant)
- **Audit lié :** complète `P2-02`.
- **Composant :** overlays (`ui/overlay.py`), toolbar (« ? for shortcuts » déjà affiché),
  `ui/commands.py`.
- **Proposé :** un overlay `?` listant les raccourcis **actifs dans le contexte courant**
  (saisie / streaming / approbation / pager), façon k9s/lazygit — au lieu d'un simple renvoi
  vers `/help`.
- **Référence(s) :** k9s/lazygit — « press `?` for the current panel's key list »,
  hints de bas de page contextuels
  ([9 TUI apps](https://medium.com/the-software-journal/9-tui-apps-so-good-i-stopped-opening-my-browser-a4c622e438c0),
  [Terminal Renaissance](https://dev.to/hyperb1iss/the-terminal-renaissance-designing-beautiful-tuis-in-the-age-of-ai-24do)).
  Consultés 2026-09-01.
- **Faisabilité :** **directe** — le système d'overlay existe (`render_overlay`,
  `choose_overlay`).
- **Effort :** S/M. **Prototype :** —

### X-02 — Honorer `NO_COLOR`/`CLICOLOR` + garde-fous d'accessibilité
- **Audit lié :** — (socle de `ANIM-05`, `FMT-05`).
- **Composant :** factory de `Console` (`renderer.py:348 force_terminal=False`), `theme.py`.
- **Proposé :** respecter `NO_COLOR`/`CLICOLOR`/`CLICOLOR_FORCE` (norme), exposer
  `SECOPS_REDUCED_MOTION`, et garantir un rendu lisible sans couleur (le sens ne doit pas
  reposer *uniquement* sur la couleur — cf. glyphes `●`/`⎿` déjà présents).
- **Référence(s) :** [NO_COLOR](https://no-color.org/) (norme) ; [clig.dev](https://clig.dev/)
  (accessibilité, ne pas coder le sens uniquement par la couleur). Consultés 2026-09-01.
- **Faisabilité :** **directe** — `rich.Console(no_color=…)` ; **validé** par le prototype
  (badges neutralisés sous `NO_COLOR=1`).
- **Effort :** S. **Prototype :** `scratch/ux_research_probe.py` (`console_factory`).

### X-03 — Liens hypertextes OSC 8 (chemins, URLs, refs CVE cliquables)
- **Audit lié :** —
- **Composant :** `renderer.py`, `tool_display.py` (rendu des refs).
- **Proposé :** rendre chemins de fichiers, URLs cibles et identifiants CVE en **liens OSC 8**
  cliquables (via markup `rich` `[link=…]…[/link]`), avec repli texte sur terminaux sans
  support. Utile pour ouvrir un rapport, une preuve, une fiche CVE.
- **Référence(s) :** Claude Code expose un composant `HyperlinkText`
  ([dev.to/minnzen](https://dev.to/minnzen/i-studied-claude-codes-leaked-source-and-built-a-terminal-ui-toolkit-from-it-4poh)) ;
  support natif des liens dans `rich`. Consultés 2026-09-01.
- **Faisabilité :** **directe** — markup de liens `rich` déjà disponible ; garder sous
  `is_terminal`.
- **Effort :** S. **Prototype :** —

### X-04 — Onboarding au premier lancement (posture de permission + confiance de l'espace + thème)
- **Audit lié :** croise `P1-01`/`P2-01`.
- **Composant :** `main.py` (démarrage), `.env`/préférences, `theme.py`.
- **Proposé :** au tout premier lancement, un assistant court : (1) **confiance de l'espace
  de travail** (ce dossier est-il autorisé comme cible/contexte ?), (2) **posture de
  permission par défaut** (request-review recommandé), (3) **thème** (sombre/clair/auto). La
  confiance de workspace est particulièrement pertinente pour un agent offensif (garde-fou
  ASI05/ASI09). *Note de recherche :* les sources tierces divergent sur l'existence d'un
  assistant complet côté Antigravity — certaines décrivent un simple login + `/config`
  ([aibuilderclub](https://www.aibuilderclub.com/blog/antigravity-cli-guide)), d'autres des
  modes riches ([neurals](https://neurals.ca/tech/gemini/antigravity/permission-modes/)) ;
  la proposition retient le **motif** (trust + posture au premier run), pas une copie.
- **Référence(s) :** Antigravity — login + confiance du workspace au premier run, `/config`
  (sources ci-dessus, consultées 2026-09-01) ; Claude Code — offre unique « Try the new
  renderer » gérée au démarrage sans perdre le mode de permission
  ([changelog 2.1.234](https://code.claude.com/docs/en/changelog)).
- **Faisabilité :** **directe** — overlays de choix existants (`choose_overlay`) + une clé de
  préférence « onboarding vu ».
- **Effort :** M. **Prototype :** —

### X-05 — Exposer le générateur de rapport de pentest en `/report`
- **Audit lié :** **`P2-03`** (Moyenne).
- **Composant :** `core/reporting.py` (`PentestReportGenerator.generate_markdown`,
  **implémenté mais non appelé**), `ui/commands.py`, `/export` (aujourd'hui : conversation).
- **Proposé :** une commande `/report` qui produit le rapport structuré (findings +
  artefacts déjà collectés par `_track_agent_artifacts`) — la phase « post-exécution /
  rapport » des méthodologies, actuellement inaccessible depuis le TUI.
- **Référence(s) :** NIST SP 800-115 — planification/exécution/**post-exécution (rapport)**
  ([NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final), déjà cité `P2-03`,
  consulté 2026-09-01).
- **Faisabilité :** **directe** — le générateur existe ; il manque la commande et le câblage
  d'artefacts (les artefacts sont déjà suivis).
- **Effort :** S/M. **Prototype :** —

---

## Priorisation — 8 propositions à traiter en premier

| # | ID | Pourquoi en premier | Effort |
|---|---|---|---|
| 1 | **FMT-01** | Sécurité + effort minimal : le badge R0–R8 est **déjà rendu**, il suffit de le colorer par sévérité. Rend `P1-02` intelligible à l'instant critique. Validé par prototype. | S |
| 2 | **FMT-06** | Rend permission/phase/autonomie/usage **visibles en permanence** (`P1-01`) — données déjà calculées ; le manque est de rendu. Socle de confiance. | S→M |
| 3 | **PROC-01** | Seul vrai levier « analyser sans exécuter » (`P2-01`, Élevée) — impact légal/éthique/ASI09 direct pour un agent offensif. | M |
| 4 | **ANIM-01** | Les scans sont l'usage central ; `ToolProgressEvent.percent` existe déjà mais n'est pas montré. Grosse amélioration perçue pour peu de code. Validé par prototype. | M |
| 5 | **PROC-03** | Empêche l'approbation par réflexe d'une action R6/R8 irréversible — complète `FMT-01` côté interaction. | S/M |
| 6 | **PROC-02** | Autonomie « opt-in et visible » : cyclage `Shift+Tab` + indicateur de mode. Rend `PROC-01` accessible et l'état lisible. | M |
| 7 | **X-02** | Socle d'accessibilité (`NO_COLOR`/mouvement réduit) qui débloque `ANIM-05` et `FMT-05` ; validé par prototype. | S |
| 8 | **PROC-05** | Réutilise le pager `view_logs_overlay` déjà écrit pour dompter les grosses sorties de scan — faible risque, gain immédiat. | M |

Fil conducteur : **rendre visible et sûr ce qui existe déjà** (badge, statusline, phase,
pager, générateur de rapport, mode COPILOT) avant d'ajouter des capacités — cohérent avec le
constat de l'audit (« des contrôles solides, mais leur *visibilité* est le point faible »).

---

## Annexe — `git status --short` (auto-vérification)

Les seuls ajouts de cette passe sont le présent rapport et le prototype jetable ; tout le
reste (fichiers `M`/`??`) préexistait à cette session (état documenté dans l'annexe de
`docs/UX_AUDIT_2026-08-27.md`). La sortie exacte est insérée ci-dessous au moment de la
finalisation :

```console
 M CLAUDE.md
 M README.md
 M docs/ARCHITECTURE.md
 M scratch/tui_smoke.py
 M secops_agent/cli/permissions.py
 M secops_agent/core/agent.py
 M secops_agent/core/llm.py
 M secops_agent/core/mcp.py
 M secops_agent/core/mission.py
 M secops_agent/core/permissions.py
 M secops_agent/core/request_context.py
 M secops_agent/core/result_parser.py
 M secops_agent/core/tools.py
 M secops_agent/main.py
 M secops_agent/tools/forensics.py
 M secops_agent/tools/recon.py
 M secops_agent/ui/commands.py
 M secops_agent/ui/input_handler.py
 M secops_agent/ui/permissions_menu.py
 M secops_agent/ui/renderer.py
 M secops_agent/ui/runtime.py
 M secops_agent/ui/tool_display.py
 M secops_agent/ui/views/panels.py
 M tests/test_agent_evaluation_harness.py
 M tests/test_agent_permissions.py
 M tests/test_cli_surfaces.py
 M tests/test_core.py
 M tests/test_experience_memory.py
 M tests/test_mcp_trust.py
 M tests/test_mission_phase.py
 M tests/test_model_behavior.py
 M tests/test_request_context.py
 M tests/test_request_routing.py
 M tests/test_result_parsers.py
 M tests/test_runtime_persistence.py
 M tests/test_scope_guardrails.py
 M tests/test_structured_capabilities.py
 M tests/test_tool_chaining.py
 M tests/test_tui_polish.py
?? docs/TUI_TUX_REASONING_AUDIT_2026-07-10.md
?? docs/UX_AUDIT_2026-07-09.md
?? docs/UX_AUDIT_2026-08-27.md
?? docs/UX_RESEARCH_PROPOSAL_2026-09-01.md
?? scratch/ux_research_probe.py
?? secops_agent/core/result_parsers/local.py
?? secops_agent/core/result_parsers/observation.py
?? shell.php
?? tests/test_finding_artifacts.py
?? tests/test_mission_plan.py
?? tests/test_plan_preview.py
?? tests/test_plan_render.py
?? tests/test_scan_cache_reuse.py
```

**Delta de cette passe** : seuls `docs/UX_RESEARCH_PROPOSAL_2026-09-01.md` et `scratch/ux_research_probe.py` (isolé, jetable) sont nouveaux ; les entrées `M` et les autres `??` préexistaient à cette session.
