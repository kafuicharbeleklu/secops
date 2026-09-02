# GAP_ANALYSIS.md — Écarts entre la référence et le rendu actuel

**Base de comparaison :** `docs/DESIGN_SPEC.md` (référence Claude Code, tokens
nommés). **Sujet :** le rendu actuel dans `secops_agent/ui/`.

**Citations re-vérifiées le 2026-09-02 contre `HEAD` (`a36164f`).** Les commits
`2ca340b` (couche de layout responsive) et `a36164f` (re-wrap du cadre de prompt),
postérieurs au livrable P0 (`6883f9c`), ont touché **tous** les fichiers cités
(`renderer.py` +47, `theme.py` +69, `tool_display.py` +12, `animations.py` +36,
`views/common.py` −25) ; chaque `fichier:ligne` ci-dessous a été re-localisé et
re-confirmé ligne par ligne dans l'arbre courant. **Aucun écart n'a été résolu par
ces commits** — seuls les numéros de ligne ont bougé — et un écart supplémentaire
que l'audit initial avait manqué a été ajouté (**G12**).

**Méthode.** Chaque écart cite (a) le token de la spec, (b) la valeur de référence,
(c) la valeur actuelle observée dans le code avec `fichier:ligne`, (d) l'impact sur
la lisibilité. Aucun jugement subjectif : un écart n'est retenu que si la valeur
actuelle diffère d'une valeur/glyphe/condition de la référence.

**Classement d'impact (sur la lisibilité) :**
- **P1 — structurel** : change la charpente perçue (glyphe de tête, indentation,
  alignement) ou rend un contenu illisible. Corrige en priorité.
- **P2 — hiérarchie** : brouille la hiérarchie visuelle (couleur d'emphase, contraste,
  rythme) sans casser la charpente.
- **P3 — cosmétique** : divergence de détail (format d'une méta, glyphe secondaire)
  au faible coût de lisibilité.

**Note de cadrage.** La charpente actuelle suit historiquement l'*Antigravity CLI*
(`agy`) — cf. `CLAUDE.md`. Les écarts ci-dessous mesurent la distance à la référence
**Claude Code** demandée en P0 ; certains sont des choix `agy` assumés, signalés comme
tels. Ils restent listés car la référence normative est désormais `DESIGN_SPEC.md`.

---

## Synthèse

| # | Token | Réf. | Actuel | Impact |
|---|-------|------|--------|--------|
| G1 | `glyph.turn_bullet` | `⏺` U+23FA | `⏺` U+23FA — ✅ **résolu** | ~~P1~~ |
| G2 | `indent.narrative` / `glyph.turn_bullet` sur la prose | prose sous une puce `⏺`, col 2 | prose sous puce `⏺`, col 2 — ✅ **résolu** | ~~P1~~ |
| G3 | `glyph.thinking` | `✻` U+273B | `▸` U+25B8 | P3 |
| G4 | `line.tool_call.name_style` | `bold` + `color.text` | `bold` + `accent_bright` | P2 |
| G5 | `fold.meta_separator` cohérence | ` · ` partout | mélange ` · ` et 2ᵉ ligne méta autonome | P3 |
| G6 | `md.list.bullet` | `•` U+2022 | rendu Rich par défaut (`•`), puce colorée `accent` | conforme |
| G7 | Badge de risque `R0–R8` | absent de la réf. | présent sur chaque ligne d'appel | P2 |
| G8 | `line.tool_call.arg_form` couleur args | `color.text_muted` | `[dim]` (atténuation Rich, pas le rôle muted) | P3 |
| G9 | `color.state_map` (repos) | `accent` | `accent` ✔ | conforme |
| G10 | `md.code.block` cadre | sans bordure, indenté col 2 | conforme (Padding left=2, pas de panel) | conforme |
| G11 | `md.table.style` | filets `text_dim` + en-tête `bold` | non implémenté (rendu Rich par défaut) | P3 |
| G12 | `md.code.inline` | `accent` bright, **non-gras** | `bold accent_bright` (gras appliqué) | P3 |

Écarts ouverts : **G3, G4, G5, G7, G8, G11, G12**. Les deux écarts P1 — **G1**
et **G2** — sont **résolus** le 2026-09-02 (voir les notes de résolution dans le
détail ci-dessous). (G6, G9, G10 vérifiés conformes, listés pour traçabilité.)

---

## Détail des écarts

### G1 — Glyphe de puce : `●` au lieu de `⏺` (P1) — ✅ résolu 2026-09-02

> **Résolu.** `●` (U+25CF) → `⏺` (U+23FA) aux sept sites de rendu
> (`tool_display.py:360/803/826`, `renderer.py:315/322/326/3704`) ; commentaires
> et exemples de docstring alignés dans les trois fichiers de charpente. Le mapping
> état→couleur §4.2 est intact. Les trois `●` non-puce-de-tour (dot VPN `theme.py`,
> swatch `overlay.py`, statut d'artefact `input_handler.py`) sont volontairement
> **inchangés**. Régression gardée par `test_tool_call_row_uses_record_bullet`.

- **Token :** `glyph.turn_bullet` — réf. `⏺` (U+23FA).
- **Actuel :** `●` (U+25CF), codé en dur. **0** occurrence de `⏺` dans `secops_agent/ui/`.
  - `secops_agent/ui/tool_display.py:355` — `def _tool_status_marker(...)` ;
    `:360` — `return "●"` (retour inconditionnel ; l'état est porté par la couleur).
  - `secops_agent/ui/tool_display.py:769` — `indicator_marker = _tool_status_marker(...)`
    consommé au rendu `:783` (via la variable, pas de littéral).
  - `secops_agent/ui/tool_display.py:803` — `●` littéral (ligne de permission) ;
    `:826` — `●` littéral (ligne running/indicateur).
  - `secops_agent/ui/renderer.py:315,322,326,3704` — `●` littéraux
    (`:311` est le commentaire décrivant la règle `agy`, pas un rendu).
- **Impact P1 :** c'est le glyphe le plus fréquent de la charpente ; un `●` plein
  standard au lieu du `⏺` de Claude Code change l'identité visuelle de **chaque**
  ligne d'action. Choix `agy` assumé (commentaire `tool_display.py:357`), mais
  divergent de la réf. **Correctif :** remplacer `●`→`⏺` aux **sept** sites
  glyphe-littéral : `tool_display.py:360` (retour canonique, qui pilote aussi le
  rendu `:783`), `:803`, `:826` ; `renderer.py:315, :322, :326, :3704`. Le mapping
  état→couleur §4.2 est déjà correct et n'est pas touché.

### G2 — La prose de l'assistant n'a pas de puce de tête (P1) — ✅ résolu 2026-09-02

> **Résolu.** `_agent_markdown()` (`renderer.py`) accepte désormais `bullet=bool` :
> quand il est armé, la prose est montée dans un `Table.grid` à deux colonnes dont
> la gouttière porte une **unique** puce `⏺` (`color.accent`) montée en tête, col 0,
> la première ligne physique seulement — le reste (et chaque ligne de continuation)
> reste col 2 (`line.hang_alignment`). Il est armé pour le tour **committé/rejoué**
> (`_flush_live_text`, chemin de replay) et **jamais** pour la queue de streaming
> (dont la 1ʳᵉ ligne visible n'est plus le début du tour une fois tronquée). Parité
> de comptage de lignes préservée (l'ancre ctrl+o est inchangée). Régression gardée
> par `test_agent_stream_renders_thought_and_indented_text`.

- **Token :** `glyph.turn_bullet` sur la prose + `indent.narrative`.
- **Réf. :** un segment de prose assistant s'ouvre sur `⏺` (col 0), contenu col 2.
- **Actuel :** la prose est rendue par le helper `_agent_markdown()` en
  `Padding(Markdown(...), (0, right, 0, left))` avec `left = 2` — indentée de
  2 colonnes **mais sans puce**. Le littéral `(0,0,0,2)` du livrable P0 a été
  remplacé par `2ca340b` par une largeur calculée (`right` plafonne la colonne de
  prose à `layout.TEXT_MAX_WIDTH`), l'indent gauche 2 étant **préservé**.
  - `secops_agent/ui/renderer.py:369` (`left = 2`), `:372-374` (tuple
    `Padding` `(0, right, 0, left)`), `:373` (`Markdown(...)`).
  - Sites d'appel : `renderer.py:3492` (replay d'un message modèle) et `:4089`
    (chemin de streaming `_build_display`) — tous deux via le même helper sans puce.
  - `secops_agent/ui/layout.py:56` — `TEXT_MAX_WIDTH = 100` (plafond appliqué via
    `right`). Docstring d'intention : `renderer.py:4063`.
- **Impact P1 :** sans puce, un lecteur ne distingue pas visuellement le **début**
  d'un segment de réponse assistant d'une continuation, surtout après un bloc
  d'outils. La colonne 2 est correcte ; il manque le `⏺` de tête sur la première
  ligne du segment. **Correctif :** préfixer la première ligne du bloc narratif d'un
  `⏺` coloré `accent`, contenu aligné col 2 (les lignes suivantes restent col 2,
  cf. `line.hang_alignment`).

### G3 — Glyphe de raisonnement : `▸` au lieu de `✻` (P3)

- **Token :** `glyph.thinking` — réf. `✻` (U+273B). **0** occurrence de `✻` dans `ui/`.
- **Actuel :** `▸` (U+25B8) à chaque site de rendu.
  - `secops_agent/ui/renderer.py:421` (rendu de l'item pensée), `:3822`
    (`_render_inline_thought_collapse`), `:3889` (`_finish_thinking`).
  - Références docstring/commentaire : `renderer.py:5, :3865, :3886, :4062`.
- **Impact P3 :** le repli « Thought for Xs » reste lisible ; seul le glyphe diffère.
  Le format texte (`Thought for <N>s`, `color.text_muted`) est déjà conforme à
  `anim.thinking.collapsed`. **Correctif :** substituer le glyphe aux trois sites de
  rendu si l'on veut la parité stricte ; sinon documenter `▸` comme variante `agy`
  tolérée.

### G4 — Nom d'outil coloré `accent_bright` au lieu de `text` (P2)

- **Token :** `line.tool_call.name_style` — réf. `bold` + `color.text`.
- **Actuel :** `bold` + `accent_bright`.
  - `secops_agent/ui/tool_display.py:368` — `f"[bold {COLORS['accent_bright']}]{escape(display_name)}[/]"`,
    dans `_tool_call_markup` (`:363-370`).
- **Impact P2 :** `color.principle` réserve la couleur au *signal*. Colorer le nom
  d'outil en accent brillant met une teinte sur un élément qui n'est pas un signal
  d'état, ce qui entre en concurrence avec la puce colorée (le vrai signal d'état) et
  avec les titres markdown (aussi en accent). **Correctif :** rendre le nom d'outil
  en `bold` + `color.text` ; réserver l'accent à la puce et aux titres.

### G5 — Référence de log en 2ᵉ ligne méta autonome au lieu de ` · ` (P3)

- **Token :** `fold.meta_separator` / `fold.counter_position`.
- **Réf. :** segments méta joints par ` · ` sur **une** ligne méta.
- **Actuel :** les métriques sont bien jointes par ` · ` sur une ligne
  (`tool_display.py:933` ; compteurs inline ` · ` aux `:907`, `:914`), mais
  `build_collapsed_result_lines` (`:859`) émet la **référence de log** comme un
  2ᵉ élément de liste distinct — ligne méta sans coin `⎿` ni jointure ` · ` — dans
  trois branches : `:885` (échec/texte), `:922` (une ligne significative), `:936`
  (métriques multi-lignes). Le `log_line` est calculé une fois (`:875`) et porte son
  propre préfixe `     log: …` (`:452`).
- **Impact P3 :** deux lignes méta consécutives allongent le bloc replié et diluent
  le compteur. **Correctif :** fusionner la référence de log dans la ligne méta
  unique quand elle tient, sinon la garder atténuée.

### G7 — Badge de risque `R0–R8` sur chaque ligne d'appel (P2)

- **Token :** absent de la référence Claude Code (pas de badge par ligne).
- **Actuel :** `_risk_badge_markup` ajoute `R0`–`R8` coloré par palier à **chaque**
  ligne d'appel.
  - `secops_agent/ui/tool_display.py:240` (`def _risk_badge_markup`) — palier→couleur
    via `_RISK_BADGE_COLOR_KEY`, gras pour le palier ≥ 8, gris `text_dim` en repli.
  - Sites d'appel : `tool_display.py:775, :800, :818`.
- **Impact P2 :** ajout de charge visuelle par rapport à la réf. épurée. C'est une
  **extension délibérée** propre au domaine offensif (scan rapide du risque par
  l'opérateur, FMT-01) et **pas** un défaut de parité. Retenu ici pour arbitrage :
  soit assumé comme extension SecOps documentée, soit déplacé en fin de ligne/mode
  compact. **Aucune régression fonctionnelle** ; décision produit.

### G8 — Arguments en `[dim]` au lieu du rôle `text_muted` (P3)

- **Token :** `line.tool_call.args_style` — réf. `color.text_muted`.
- **Actuel :** `[dim]` (atténuation Rich générique).
  - `secops_agent/ui/tool_display.py:369` — `f"[dim]{escape(args)}[/dim]"` (forme
    args construite `:366`, nom d'outil `:368`). Le rôle `text_muted` est disponible
    et utilisé ailleurs dans le même fichier (p. ex. `:777`, le hint `(ctrl+o …)`)
    mais **pas** sur la ligne des args.
- **Impact P3 :** `[dim]` applique une réduction d'intensité relative à la couleur
  courante plutôt que le rôle sémantique `text_muted` (dont le contraste est vérifié
  ≥ 4.5:1 par palette). Sur certaines palettes le résultat peut passer sous le seuil.
  **Correctif :** utiliser `color.text_muted` explicitement.

### G11 — `md.table.style` non implémenté (P3)

- **Token :** `md.table.style` — réf. filets `color.text_dim`, en-tête `bold`, sans
  fond de cellule.
- **Actuel :** `_build_rich_styles` (`secops_agent/ui/theme.py:146`) définit
  **13** clés `markdown.*` (`:159-173`, dict clos `:174`) mais **aucune** clé
  `markdown.table*` ni override de box `Table` — ni ici ni ailleurs dans
  `secops_agent/ui/` (grep `markdown.table` / `table.style` / `box=` / `Table(` =
  0 occurrence). Rich Markdown rend donc les tableaux avec sa *box* et ses styles par
  défaut (filets non `text_dim`).
- **Impact P3 :** divergence de détail sur un élément peu fréquent ; les filets par
  défaut de Rich sont plus contrastés que `text_dim`. **Correctif :** ajouter des
  styles `markdown.table` (filets `text_dim`, en-tête `bold`) à `_build_rich_styles`,
  ou assumer le rendu Rich par défaut et le noter comme cible non réalisée.

### G12 — Code inline en gras alors que la réf. le veut non-gras (P3)

- **Token :** `md.code.inline` — réf. `color.accent` bright, **non-gras** (§5, §4.3 :
  le code inline est la seule emphase colorée, la teinte y signale du code, pas du gras).
- **Actuel :** `markdown.code = "bold accent_bright"` — le gras est appliqué.
  - `secops_agent/ui/theme.py:159` — `"markdown.code": f"bold {colors['accent_bright']}"`.
- **Traçabilité :** ce `bold` **précède le livrable P0** (introduit par `e75adf7`,
  FMT-05, avant `6883f9c`) ; il avait été **manqué** par l'audit initial (qui n'avait
  vérifié que `markdown.strong`). Ce n'est donc pas une régression post-P0.
- **Impact P3 :** le code inline apparaît plus lourd que la réf. ; sur du texte dense
  cela ajoute une graisse que la spec réserve à `**gras**`. **Correctif :** retirer
  `bold`, ne garder que `accent_bright` ; ou, si le gras est un choix assumé,
  amender `md.code.inline` dans `DESIGN_SPEC.md` (la spec restant la source de vérité).

---

## Conformités vérifiées (non-écarts)

- **G6 / `md.list.bullet` :** puces de liste rendues par Rich Markdown, style
  `markdown.item.bullet = bold accent` (`theme.py:165`) — conforme.
- **G9 / `color.state_map` :** `_tool_status_color` (`tool_display.py:344`) mappe
  succès→`success` (`:347`), échec/annulé/interrompu/refusé→`error` (`:349`),
  en-cours/attente/risque→`warning` (`:351`), repos→`accent` (`:352`) — conforme §4.2.
- **G10 / `md.code.block` :** bloc de code rendu sans panneau, indenté col 2 via
  `Padding` (`renderer.py:372-374`) + thème Pygments `monokai` surchargable par
  `SECOPS_CODE_THEME` (`renderer.py:80`) — conforme à `md.code.block` / `md.code.theme`.
- **`color.strong` :** `markdown.strong = "bold"` sans couleur (`theme.py:163`) —
  conforme à la règle anti-décoration §4.3.
- **`fold.result_visible_lines = 4`** (`tool_display.py:891`, `summarize_output`
  `max_lines=4`), **`fold.diff_visible_lines = 6`** (`tool_display.py:983`,
  `min(6, …)`), **`fold.expanded_visible_lines = min(40, hauteur−8)`**
  (`views/common.py:76-78`), **`fold.char_truncate`** tête 80 % / queue 20 %
  (`tool_display.py:55-56`), **`anim.stream.throttle_ms = 50`**
  (`renderer.py:74`, `_RENDER_INTERVAL = 0.05`), **`anim.spinner.interval_ms = 80/100`**
  (`animations.py:111, :116`) + **`refresh_hz = 12`** (`animations.py:165`),
  **`anim.wait.*`** (`animations.py:53` `_TIP_INTERVAL_SECONDS = 4.0`, `:54`
  `_TIP_DELAY_SECONDS = 2.0`) — tous conformes aux valeurs de réf.

---

## Ordre de correction suggéré (par impact)

1. ✅ **G1** (`●`→`⏺`) et **G2** (puce de prose) — P1, **faits** le 2026-09-02.
2. **G4** (nom d'outil en `text`) et **G8** (args en `text_muted`) — P2/P3,
   remettent la couleur au rang de signal.
3. **G5** (fusion ligne méta), **G3** (glyphe `✻`), **G11** (style de tableau) et
   **G12** (code inline non-gras) — P3, parité fine.
4. **G7** (badge de risque) — décision produit, pas un correctif de parité.

*Livrable P0. Cette analyse se recalcule contre `docs/DESIGN_SPEC.md` à chaque
évolution du rendu ; citations re-vérifiées le 2026-09-02 contre `a36164f`.*
