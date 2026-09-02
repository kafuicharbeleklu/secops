# GAP_ANALYSIS.md — Écarts entre la référence et le rendu actuel

**Base de comparaison :** `docs/DESIGN_SPEC.md` (référence Claude Code, tokens
nommés). **Sujet :** le rendu actuel dans `secops_agent/ui/`.

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
| G1 | `glyph.turn_bullet` | `⏺` U+23FA | `●` U+25CF | P1 |
| G2 | `indent.narrative` / `glyph.turn_bullet` sur la prose | prose sous une puce `⏺`, col 2 | prose indentée 2 sp **sans** puce | P1 |
| G3 | `glyph.thinking` | `✻` U+273B | `▸` U+25B8 | P3 |
| G4 | `line.tool_call.name_style` | `bold` + `color.text` | `bold` + `accent_bright` | P2 |
| G5 | `fold.meta_separator` cohérence | ` · ` partout | mélange ` · ` et ligne autonome | P3 |
| G6 | `md.list.bullet` | `•` U+2022 | rendu Rich par défaut (`•`) — OK, mais puce colorée `accent` | conforme | — |
| G7 | Badge de risque `R0–R8` | absent de la réf. | présent sur chaque ligne d'appel | P2 |
| G8 | `line.tool_call.arg_form` couleur args | `color.text_muted` | `[dim]` (atténuation Rich, pas le rôle muted) | P3 |
| G9 | `color.state_map` (repos) | `accent` | `accent` ✔ | conforme |
| G10 | `md.code.block` cadre | sans bordure, indenté col 2 | conforme (Padding 2, pas de panel) | conforme |
| G11 | `md.table.style` | filets `text_dim` + en-tête `bold` | non implémenté (rendu Rich par défaut) | P3 |

Écarts retenus : **G1, G2, G3, G4, G5, G7, G8, G11**. (G6, G9, G10 vérifiés
conformes, listés pour traçabilité.)

---

## Détail des écarts

### G1 — Glyphe de puce : `●` au lieu de `⏺` (P1)

- **Token :** `glyph.turn_bullet` — réf. `⏺` (U+23FA).
- **Actuel :** `●` (U+25CF), codé en dur.
  - `secops_agent/ui/tool_display.py:364` — `_tool_status_marker` retourne `"●"`.
  - `secops_agent/ui/tool_display.py:807` (requête de permission), `:830` (running)
    — `●` littéral ; `:787` rend via la variable `indicator_marker` (= `●`).
  - `secops_agent/ui/renderer.py:314,321,325,3691` — `●` littéral (`:311` est le
    commentaire décrivant la règle, pas un rendu).
- **Impact P1 :** c'est le glyphe le plus fréquent de la charpente ; un `●` plein
  standard au lieu du `⏺` de Claude Code change l'identité visuelle de **chaque**
  ligne d'action. Choix `agy` assumé (commentaire ligne 361-363), mais divergent de
  la réf. **Correctif :** remplacer par `⏺` dans `_tool_status_marker` et les sites `●` littéraux listés ci-dessus (le mapping état→couleur §4.2 est déjà correct et n'est pas
  touché).

### G2 — La prose de l'assistant n'a pas de puce de tête (P1)

- **Token :** `glyph.turn_bullet` sur la prose + `indent.narrative`.
- **Réf. :** un segment de prose assistant s'ouvre sur `⏺` (col 0), contenu col 2.
- **Actuel :** la prose est rendue en `Padding(Markdown(...), (0,0,0,2))` — indentée
  de 2 colonnes **mais sans puce**.
  - `secops_agent/ui/renderer.py:370` et `:3476-3478`.
- **Impact P1 :** sans puce, un lecteur ne distingue pas visuellement le **début**
  d'un segment de réponse assistant d'une continuation, surtout après un bloc
  d'outils. La colonne 2 est correcte ; il manque le `⏺` de tête sur la première
  ligne du segment. **Correctif :** préfixer la première ligne du bloc narratif d'un
  `⏺` coloré `accent`, contenu aligné col 2 (les lignes suivantes restent col 2,
  cf. `line.hang_alignment`).

### G3 — Glyphe de raisonnement : `▸` au lieu de `✻` (P3)

- **Token :** `glyph.thinking` — réf. `✻` (U+273B).
- **Actuel :** `▸` (U+25B8).
  - `secops_agent/ui/renderer.py:405,3809,3876`.
- **Impact P3 :** le repli « Thought for Xs » reste lisible ; seul le glyphe diffère.
  Le format texte (`Thought for <N>s`, `color.text_muted`) est déjà conforme à
  `anim.thinking.collapsed`. **Correctif :** substituer le glyphe si l'on veut la
  parité stricte ; sinon documenter `▸` comme variante `agy` tolérée.

### G4 — Nom d'outil coloré `accent_bright` au lieu de `text` (P2)

- **Token :** `line.tool_call.name_style` — réf. `bold` + `color.text`.
- **Actuel :** `bold` + `accent_bright`.
  - `secops_agent/ui/tool_display.py:369-372` (`_tool_call_markup`).
- **Impact P2 :** `color.principle` réserve la couleur au *signal*. Colorer le nom
  d'outil en accent brillant met une teinte sur un élément qui n'est pas un signal
  d'état, ce qui entre en concurrence avec la puce colorée (le vrai signal d'état) et
  avec les titres markdown (aussi en accent). **Correctif :** rendre le nom d'outil
  en `bold` + `color.text` ; réserver l'accent à la puce et aux titres.

### G5 — Ligne méta parfois autonome au lieu de ` · ` (P3)

- **Token :** `fold.meta_separator` / `fold.counter_position`.
- **Réf. :** segments méta joints par ` · ` sur **une** ligne méta.
- **Actuel :** la plupart des chemins joignent bien par ` · `
  (`tool_display.py:937,938`), mais `build_collapsed_result_lines` émet parfois une
  2ᵉ ligne méta séparée pour la référence de log (`tool_display.py:889,926,940`)
  au lieu de la fondre dans la ligne ` · `.
- **Impact P3 :** deux lignes méta consécutives allongent le bloc replié et diluent
  le compteur. **Correctif :** fusionner la référence de log dans la ligne méta
  unique quand elle tient, sinon la garder atténuée.

### G7 — Badge de risque `R0–R8` sur chaque ligne d'appel (P2)

- **Token :** absent de la référence Claude Code (pas de badge par ligne).
- **Actuel :** `_risk_badge_markup` ajoute `R0`–`R8` coloré par palier à **chaque**
  ligne d'appel.
  - `secops_agent/ui/tool_display.py:213-256, 787-788, 831`.
- **Impact P2 :** ajout de charge visuelle par rapport à la réf. épurée. C'est une
  **extension délibérée** propre au domaine offensif (scan rapide du risque par
  l'opérateur, FMT-01) et **pas** un défaut de parité. Retenu ici pour arbitrage :
  soit assumé comme extension SecOps documentée, soit déplacé en fin de ligne/mode
  compact. **Aucune régression fonctionnelle** ; décision produit.

### G8 — Arguments en `[dim]` au lieu du rôle `text_muted` (P3)

- **Token :** `line.tool_call.args_style` — réf. `color.text_muted`.
- **Actuel :** `[dim]` (atténuation Rich générique).
  - `secops_agent/ui/tool_display.py:373` — `[dim]{escape(args)}[/dim]`.
- **Impact P3 :** `[dim]` applique une réduction d'intensité relative à la couleur
  courante plutôt que le rôle sémantique `text_muted` (dont le contraste est vérifié
  ≥ 4.5:1 par palette). Sur certaines palettes le résultat peut passer sous le seuil.
  **Correctif :** utiliser `color.text_muted` explicitement.

### G11 — `md.table.style` non implémenté (P3)

- **Token :** `md.table.style` — réf. filets `color.text_dim`, en-tête `bold`, sans
  fond de cellule.
- **Actuel :** aucune clé `markdown.table*` n'est définie dans `_build_rich_styles`
  (`secops_agent/ui/theme.py:158-172`) ; Rich Markdown rend les tableaux avec sa
  *box* et ses styles par défaut (filets non `text_dim`).
- **Impact P3 :** divergence de détail sur un élément peu fréquent ; les filets par
  défaut de Rich sont plus contrastés que `text_dim`. **Correctif :** ajouter des
  styles `markdown.table` (filets `text_dim`, en-tête `bold`) à `_build_rich_styles`,
  ou assumer le rendu Rich par défaut et le noter comme cible non réalisée.

---

## Conformités vérifiées (non-écarts)

- **G6 / `md.list.bullet` :** puces de liste rendues par Rich Markdown, style
  `markdown.item.bullet = bold accent` (`theme.py:164`) — conforme.
- **G9 / `color.state_map` :** `_tool_status_color` mappe succès→success,
  erreur→error, en-cours/risque→warning, repos→accent (`tool_display.py:348-357`) —
  conforme à §4.2.
- **G10 / `md.code.block` :** bloc de code rendu sans panneau, indenté col 2 via
  `Padding` + thème Pygments `monokai` surchargable (`renderer.py:80,370`) — conforme
  à `md.code.block` / `md.code.theme`.
- **`color.strong` :** `markdown.strong = "bold"` sans couleur (`theme.py:162`) —
  conforme à la règle anti-décoration §4.3.
- **`fold.result_visible_lines = 4`** (`tool_display.py:895`, `summarize` max_lines=4),
  **`fold.diff_visible_lines = 6`** (`tool_display.py:987`),
  **`fold.expanded_visible_lines = min(40, hauteur−8)`** (`views/common.py:82-84`),
  **`fold.char_truncate`** tête 80 % / queue 20 % (`tool_display.py:49-65`),
  **`anim.stream.throttle_ms = 50`** (`renderer.py:74`),
  **`anim.spinner.interval_ms = 80/100`** + **`refresh_hz = 12`**
  (`animations.py:91-101,150-151`),
  **`anim.wait.*`** (`animations.py:42-43,52-66`) — tous conformes aux valeurs de réf.

---

## Ordre de correction suggéré (par impact)

1. **G1** (`●`→`⏺`) et **G2** (puce de prose) — P1, restaurent la charpente.
2. **G4** (nom d'outil en `text`) et **G8** (args en `text_muted`) — P2/P3,
   remettent la couleur au rang de signal.
3. **G5** (fusion ligne méta), **G3** (glyphe `✻`) et **G11** (style de tableau) — P3, parité fine.
4. **G7** (badge de risque) — décision produit, pas un correctif de parité.

*Livrable P0. Cette analyse se recalcule contre `docs/DESIGN_SPEC.md` à chaque
évolution du rendu.*
