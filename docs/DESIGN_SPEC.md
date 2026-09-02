# DESIGN_SPEC.md — Référence de formatage « à la Claude Code »

**Statut : normatif (P0).** Ce document est la **source de vérité** pour tous les
prompts de mise en forme qui suivent. Chaque règle est exprimée comme un *token de
design nommé* dont la valeur est **objectivement vérifiable** : un glyphe (avec son
point de code), un nombre, une couleur sémantique ou une condition booléenne.
Aucune formulation subjective (« plus élégant », « plus propre ») n'a valeur de règle.

L'analyse d'écart entre cette référence et le rendu actuel vit dans
`docs/GAP_ANALYSIS.md`. Le rendu actuel est implémenté dans `secops_agent/ui/`
(`theme.py`, `renderer.py`, `tool_display.py`, `animations.py`, `views/common.py`).

## 0. Conventions de nommage des tokens

- Format : `NAMESPACE.role[.variant]`, en minuscules, séparé par des points.
- Namespaces : `glyph.*`, `indent.*`, `color.*`, `fold.*`, `rhythm.*`, `md.*`,
  `anim.*`, `line.*`.
- Une valeur de token est **une** de ces catégories :
  - **glyphe** : caractère + `U+XXXX`.
  - **mesure** : entier de colonnes/lignes/millisecondes.
  - **couleur** : *rôle sémantique* (jamais un hex ; voir §4 pour la justification).
  - **condition** : prédicat vrai/faux testable.
- Toute la mise en forme est **monospace, 1 cellule = 1 colonne**. Les glyphes de
  charpente sont width-1 en contexte non-CJK et ne contiennent aucun émoji large
  (East-Asian `W`/`F`) ; trois d'entre eux — `─` U+2500, `…` U+2026, `•` U+2022 —
  sont *East-Asian Ambiguous* (largeur 2 uniquement en locale CJK).

---

## 1. Glyphes structurels et indentation

Claude Code n'encadre pas ses sorties : la structure est portée par **un jeu réduit
de glyphes en tête de ligne** et par l'**indentation**, jamais par des bordures de
panneau. Les glyphes de charpente sont fixes ; **l'état est porté par la couleur**,
pas par le glyphe (§4).

| Token | Glyphe | Point de code | Rôle | Colonne du glyphe | Colonne du contenu |
|-------|--------|---------------|------|-------------------|--------------------|
| `glyph.turn_bullet`   | `⏺` | U+23FA | Puce de tête d'un segment assistant (prose **ou** appel d'outil) | 0 | 2 |
| `glyph.result_corner` | `⎿` | U+23BF | Coin de résultat/sous-élément rattaché à la puce | 2 | 5 |
| `glyph.user_prompt`   | `>` | U+003E | Marqueur de la saisie utilisateur | 0 | 2 |
| `glyph.todo_done`     | `☒` | U+2612 | Élément de tâche accompli | (contextuel) | +2 |
| `glyph.todo_pending`  | `☐` | U+2610 | Élément de tâche à faire | (contextuel) | +2 |
| `glyph.thinking`      | `✻` | U+273B | Tête d'un bloc de raisonnement | 0 | 2 |
| `glyph.diff_add`      | `+` | U+002B | Ligne ajoutée dans un diff | (voir §1.3) | — |
| `glyph.diff_del`      | `-` | U+002D | Ligne retirée dans un diff | (voir §1.3) | — |
| `glyph.rule`          | `─` | U+2500 | Filet de séparation horizontal | 0 | pleine largeur |
| `glyph.ellipsis`      | `…` | U+2026 | Marque de troncature (unique caractère) | inline | — |
| `glyph.list_bullet`   | `•` | U+2022 | Puce de liste markdown (niveau 1) | +2 par niveau | +2 |

### 1.1 Règles d'indentation (charpente)

| Token | Valeur | Condition |
|-------|--------|-----------|
| `indent.bullet_col`        | `0`  | La puce `⏺` commence toujours en colonne 0. |
| `indent.bullet_content`    | `2`  | Le contenu après `⏺ ` (glyphe + 1 espace) commence en colonne 2. |
| `indent.result_corner_col` | `2`  | `⎿` est indenté de 2 colonnes sous la puce parente. |
| `indent.result_content`    | `5`  | Contenu après `⎿  ` (2 sp + glyphe + 2 sp) → colonne 5. |
| `indent.result_meta`       | `5`  | La ligne méta d'un résultat s'aligne sur le contenu du résultat (col 5). |
| `indent.narrative`         | `2`  | La prose de l'assistant s'aligne sur `indent.bullet_content` (col 2), sous la même puce ; **pas** de puce distincte par paragraphe. |
| `indent.list_step`         | `2`  | Chaque niveau d'imbrication d'une liste markdown ajoute 2 colonnes. |

**Règle d'or de l'alignement (`line.hang_alignment`) :** quand une ligne logique se
replie (wrap) ou se poursuit sur plusieurs lignes physiques, les lignes de
continuation s'alignent sur **la colonne du contenu**, pas sur la colonne 0. Le
glyphe de tête (`⏺`, `⎿`, `>`) n'apparaît **qu'une seule fois**, sur la première
ligne physique.

### 1.2 Anatomie d'une ligne d'appel d'outil (`line.tool_call`)

Ordre canonique des segments, de gauche à droite :

```
⏺ ToolName(param_résumé)  description·optionnelle
```

- `glyph.turn_bullet` (`⏺`), couleur = état (§4.2)
- nom d'outil : `bold` + `color.text` (jamais `color.accent` seul)
- « primary arg » : `color.text_muted`, entre parenthèses
- description facultative : `color.text_muted`

| Token | Valeur | Condition |
|-------|--------|-----------|
| `line.tool_call.name_style`   | `bold` + `color.text` | Le nom d'outil est en gras, couleur texte primaire. |
| `line.tool_call.args_style`   | `color.text_muted`    | L'argument principal entre `( )` est en gris secondaire. |
| `line.tool_call.arg_form`     | `Name(primary_arg)`   | **Un seul** argument résumé dans la parenthèse ; le reste est replié. |
| `line.tool_call.status_glyph` | *(néant)*             | L'état n'ajoute **pas** de glyphe : il colore `glyph.turn_bullet`. |
| `line.tool_call.duration`     | inline, fin de ligne résultat | La durée s'affiche sur le résultat, pas sur l'appel (§1.3). |

**Extension SecOps — badge de risque (`line.tool_call.risk_badge`).** Élément **hors
référence Claude Code** : le domaine offensif ajoute un badge de risque `R<0–8>` à
chaque ligne d'appel, pour que l'opérateur évalue la dangerosité d'une action d'un
coup d'œil (FMT-01). Ce n'est **pas** un défaut de parité mais un token **normatif de
ce produit** (décision produit, 2026-09-02), tenu aux mêmes exigences de vérifiabilité :

| Token | Valeur | Condition |
|-------|--------|-----------|
| `line.tool_call.risk_badge.form`     | `R<n>` (n ∈ 0–8) ou `R?` | Un **seul** badge par ligne d'appel ; `R?` quand le tier ne se résout pas. |
| `line.tool_call.risk_badge.position` | suit `line.tool_call` (nom+args), même ligne | Le badge vient **après** le nom+args ; fin de ligne dans les rangs *collapsed*/*running* (après le hint `ctrl+o`), avant le hint dans la ligne de permission. Jamais avant le nom. |
| `line.tool_call.risk_badge.color`    | palier → rôle sémantique | R0–R2 = `color.text_muted` ; R3–R5 = `color.warning` ; R6–R7 = `color.error` ; R8 = `bold` + `color.error` (variante vive `danger_bright`) ; `R?` = `color.text_dim`. |

### 1.3 Anatomie d'une ligne de résultat (`line.tool_result`)

```
  ⎿  Résumé d'une ligne de la sortie
     … +N lines (ctrl+o to expand)
```

- `indent.result_corner_col` = 2, puis `glyph.result_corner` (`⎿`) + 2 espaces
- ligne méta : compteur + raccourci, alignée en colonne 5 (voir §3)

| Token | Valeur | Condition |
|-------|--------|-----------|
| `line.tool_result.corner`      | `⎿` (U+23BF) + 2 espaces | Toujours 2 espaces après le coin → contenu col 5. |
| `line.tool_result.headline`    | 1 ligne, `color.text`     | Le résultat s'ouvre sur la **première ligne non vide** dont le contenu n'est pas composé uniquement de caractères de décoration (`─ ═ │ ┌ ┐ └ ┘ ├ ┤ ┬ ┴ ┼ - = _ ~ * # . +`, espaces) et qui ne contient pas le marqueur `TOOL DATA` ; à défaut, la 1ʳᵉ ligne non vide. |
| `line.tool_result.error_style` | `color.error`             | Un échec colore tout le bloc résultat en rouge. |
| `line.diff.add`                | `+ ` + fond vert tinté    | Ligne ajoutée : `glyph.diff_add`, avant-plan `color.success`, fond `color.diff_add_bg`. |
| `line.diff.del`                | `- ` + fond rouge tinté   | Ligne retirée : `glyph.diff_del`, avant-plan `color.error`, fond `color.diff_del_bg`. |
| `line.diff.gutter`             | n° de ligne, largeur `4`, aligné à droite, `color.text_muted` | Colonne de numéros avant le `+`/`-`. |

---

## 2. Rythme vertical (`rhythm.*`)

Le rythme vertical de Claude Code est **parcimonieux** : une ligne vide sépare des
*groupes logiques*, jamais des lignes d'un même groupe.

| Token | Valeur | Condition (vérifiable) |
|-------|--------|------------------------|
| `rhythm.before_tool_group` | `1` ligne vide | Une ligne vide précède le **premier** appel d'un groupe d'outils. |
| `rhythm.within_tool_group` | `0` ligne vide | **Aucune** ligne vide entre appels consécutifs d'un même groupe, ni entre un appel et son résultat. |
| `rhythm.after_user_turn`   | `1` ligne vide | Une ligne vide sépare la saisie utilisateur de la réponse. |
| `rhythm.between_md_blocks` | `1` ligne vide | Une ligne vide sépare deux blocs markdown de **type différent** (para ↔ liste ↔ titre ↔ code). |
| `rhythm.within_md_block`   | `0` ligne vide | Aucune ligne vide entre items d'une même liste ou lignes d'un même paragraphe. |
| `rhythm.result_to_meta`    | `0` ligne vide | La ligne méta suit immédiatement la ligne de résultat. |
| `rhythm.trailing_prose`    | `0` ligne vide finale | Pas de ligne vide superflue en fin de réponse (pas de padding pleine largeur en fin de flux). |

---

## 3. Règles de troncature et de repli (`fold.*`)

Claude Code **replie par défaut** toute sortie d'outil au-delà d'un petit seuil, et
place l'affordance de dépliage **à la fin**, sur la ligne méta.

| Token | Valeur | Condition |
|-------|--------|-----------|
| `fold.result_visible_lines`   | `4`  | Un résultat multi-lignes montre au plus 4 lignes de tête repliées. |
| `fold.diff_visible_lines`     | `6`  | Un diff (write/create) montre au plus 6 lignes de contenu. |
| `fold.line_width`             | `≤ largeur_terminal − 8` | Une ligne repliée est tronquée à droite à cette largeur. |
| `fold.counter_format`         | `+N lines` | Le compteur de lignes masquées est de la forme `+<N> lines` (`line`/`lines` accordé). |
| `fold.counter_position`       | fin du bloc replié | Le compteur est **sur la ligne méta**, jamais au milieu du contenu. |
| `fold.expand_hint`            | `(ctrl+o to expand)` | Le raccourci de dépliage clôt la ligne méta, entre parenthèses. |
| `fold.meta_separator`         | ` · ` (espace·espace) | Les segments méta (durée, compteur, hint) sont joints par ` · `. |
| `fold.char_truncate`          | `+N chars hidden` | Une troncature au caractère (tête 80 % / queue 20 %) signale `+<N> chars hidden`. |
| `fold.expanded_visible_lines` | `min(40, hauteur − 8)` | En mode déplié (ctrl+o), la sortie reste bornée pour se nettoyer en place. |
| `fold.ellipsis_glyph`         | `…` (U+2026) | La troncature *au milieu d'une ligne* utilise l'ellipse unique, pas `...`. |

**Ordre de priorité du contenu replié (`fold.headline_priority`)** — condition
testable, du plus prioritaire au moins :
1. Message d'échec (si non-succès) → couleur `color.error`.
2. Trailer de code de sortie non nul → surface la commande + `[Exit Code: N]`.
3. Fait-clé structuré fourni par un parser → sert de titre.
4. Sortie mono-ligne → rendue directement.
5. Sinon → titre métrique (`N lines · M chars`).

---

## 4. Rôles de couleur (`color.*`)

**Principe (`color.principle`) : la couleur est un *signal*, jamais une décoration.**
Elle est réservée à l'état, aux titres et au code. L'emphase (`**gras**`) est un
attribut **bold sans couleur**.

### 4.1 Rôles sémantiques

Les tokens de couleur sont définis par **rôle**, pas par hex, car la référence
Claude Code s'adapte au thème du terminal. Une implémentation MAP chaque rôle vers
une valeur concrète (§4.4).

| Token | Rôle | Contrainte de contraste |
|-------|------|-------------------------|
| `color.text`           | Texte primaire (corps, noms d'outils) | ≥ 7:1 sur le fond |
| `color.text_secondary` | Texte secondaire (fait-clé de résultat) | ≥ 4.5:1 |
| `color.text_muted`     | Métadonnées, arguments, coin `⎿`, hints | ≥ 4.5:1 |
| `color.text_dim`       | Filets, séparateurs (jamais du texte lisible) | ≥ 3:1 (non-texte) |
| `color.accent`         | Titres, liens, puce assistant au repos | ≥ 4.5:1 |
| `color.success`        | Succès, additions de diff | ≥ 4.5:1 |
| `color.warning`        | En attente / à confirmer / risque moyen | ≥ 4.5:1 |
| `color.error`          | Échec, suppressions de diff, risque élevé | ≥ 4.5:1 |
| `color.diff_add_bg`    | Fond tinté d'une addition | contraste avant-plan préservé |
| `color.diff_del_bg`    | Fond tinté d'une suppression | contraste avant-plan préservé |

### 4.2 État → couleur du glyphe de puce (`color.state_map`)

| État | Couleur de `glyph.turn_bullet` |
|------|-------------------------------|
| repos / neutre | `color.accent` |
| en cours / en attente / risque | `color.warning` |
| succès | `color.success` |
| échec / annulé / refusé | `color.error` |

### 4.3 Emphase et diff — règles anti-décoration

| Token | Valeur | Condition |
|-------|--------|-----------|
| `color.strong`   | `bold` **sans couleur** | `**gras**` markdown n'introduit aucune teinte. |
| `color.emph`     | `italic` sans couleur   | `*italique*` n'introduit aucune teinte. |
| `md.code.inline` | cf. §5 (`md.*`) | Le code inline est la **seule** emphase colorée ; la teinte y signale du code, pas de l'emphase. |

### 4.4 Note d'implémentation (référence ↔ concret)

La référence exprime des **rôles adaptatifs au terminal**. L'implémentation actuelle
les fige en palettes hex (`theme.py`). C'est admissible **tant que** : (a) chaque
rôle satisfait sa contrainte de contraste §4.1 sur le fond de sa palette, et (b) le
mapping état→couleur §4.2 est respecté. Les écarts concrets sont listés dans
`GAP_ANALYSIS.md`.

---

## 5. Rendu du markdown en terminal (`md.*`)

| Token | Valeur | Condition |
|-------|--------|-----------|
| `md.h1.style`        | `bold` + `color.accent` (bright) | Titre niveau 1. |
| `md.h2.style`        | `bold` + `color.accent`          | Titre niveau 2. |
| `md.h3.style`        | `bold` + `color.accent`          | Titre niveau 3. |
| `md.list.bullet`     | `glyph.list_bullet` (`•`) + `color.accent` | Puce de liste non ordonnée. |
| `md.list.number`     | `N.` + `color.accent`            | La numérotation d'origine est **préservée** (pas renumérotée). |
| `md.list.nest_indent`| `2` colonnes par niveau          | Cf. `indent.list_step`. |
| `md.code.inline`     | `color.accent` bright, non-gras  | `` `code` `` inline. |
| `md.code.block`      | pas de fond appliqué, coloration syntaxique, sans bordure | Bloc de code : indenté à `indent.bullet_content`, jamais encadré d'un panneau (aucun `Panel`/box). |
| `md.code.theme`      | `monokai` (défaut), surchargable via `SECOPS_CODE_THEME` | Thème = valeur de `SECOPS_CODE_THEME` si définie, sinon `monokai` (nom de thème Pygments valide) ; chaque couleur de token du thème satisfait ≥ 4.5:1 sur le fond de `md.code.block`. |
| `md.table.style`     | filets `color.text_dim`, en-tête `bold` | Filets = `color.text_dim` ; en-tête = `bold` ; aucun fond de cellule. |
| `md.rule`            | `glyph.rule` pleine largeur, `color.text_dim` | `---` markdown → filet horizontal. |
| `md.blockquote`      | `color.text_muted`               | Citation en gris secondaire. |
| `md.link`            | `color.accent`, OSC 8 si supporté | Lien cliquable si le terminal gère OSC 8, sinon texte + URL. |

**Condition de robustesse (`md.block_separation`) :** un changement de type de bloc
(para → liste, liste → titre, intro → liste numérotée) **doit** être précédé d'une
ligne vide avant passage au moteur markdown, faute de quoi les blocs fusionnent en
une ligne courante. (Cf. `rhythm.between_md_blocks`.)

---

## 6. États transitoires (`anim.*`)

| Token | Valeur | Condition |
|-------|--------|-----------|
| `anim.spinner.frames`      | jeu Braille rotatif, largeur 1 | Ex. `⣾⣷⣯⣟⡿⢿⣻⣽` ou `⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`. |
| `anim.spinner.interval_ms` | `80` ou `100` ms | Intervalle par trame, selon le jeu de trames (`agy_dots` = 80, `antigravity` = 100). |
| `anim.spinner.refresh_hz`  | `12` | Fréquence de rafraîchissement de la région live. |
| `anim.reduced_motion`      | trame statique + `2` Hz | Sous préférence « moins d'animation », pas de glyphe rotatif. |
| `anim.stream.throttle_ms`  | `50` | Le markdown streamé est re-rendu au plus toutes les 50 ms. |
| `anim.stream.tail_lines`   | `hauteur_viewport − 6` (min `4`) | La région live streamée n'affiche que sa queue pour ne jamais dépasser le viewport. |
| `anim.elapsed.format`      | `<1ms` / `Nms` / `N.NNs` / `Nm N.Ns` | Format du compteur de temps écoulé, par palier. |
| `anim.wait.tip_delay_s`    | `2.0` | Un conseil d'usage n'apparaît qu'après 2 s d'attente. |
| `anim.wait.tip_interval_s` | `4.0` | Les conseils tournent toutes les 4 s. |
| `anim.wait.urgency`        | `<10s`→`text_muted`, `10–30s`→`accent`, `>30s`→`accent` bright | La couleur de l'indicateur d'attente s'approfondit avec le temps : gris `text_muted` sous ~10 s, puis la famille accent au-delà. |
| `anim.thinking.collapsed`  | `✻ Thought for <N>s` | Le bloc de raisonnement se replie en une ligne, glyphe `glyph.thinking`, texte `color.text_muted`. |

---

## 7. Récapitulatif des tokens (index)

Charpente : `glyph.turn_bullet`, `glyph.result_corner`, `glyph.user_prompt`,
`glyph.thinking`, `glyph.rule`, `glyph.ellipsis`, `glyph.list_bullet`,
`glyph.diff_add`, `glyph.diff_del`, `glyph.todo_done`, `glyph.todo_pending`.

Indentation : `indent.bullet_col`, `indent.bullet_content`,
`indent.result_corner_col`, `indent.result_content`, `indent.result_meta`,
`indent.narrative`, `indent.list_step`, `line.hang_alignment`.

Ligne : `line.tool_call.*` (`.name_style`, `.args_style`, `.arg_form`,
`.status_glyph`, `.duration`, **extension SecOps** `.risk_badge.form` /
`.risk_badge.position` / `.risk_badge.color`), `line.tool_result.*` (`.corner`,
`.headline`, `.error_style`), `line.diff.*` (`.add`, `.del`, `.gutter`).
(`line.hang_alignment` est rangé sous *Indentation* par nature.)

Repli : `fold.result_visible_lines`, `fold.diff_visible_lines`, `fold.line_width`,
`fold.counter_format`, `fold.counter_position`, `fold.expand_hint`,
`fold.meta_separator`, `fold.char_truncate`, `fold.expanded_visible_lines`,
`fold.ellipsis_glyph`, `fold.headline_priority`.

Couleur : `color.principle`, `color.text`, `color.text_secondary`,
`color.text_muted`, `color.text_dim`, `color.accent`, `color.success`,
`color.warning`, `color.error`, `color.diff_add_bg`, `color.diff_del_bg`,
`color.state_map`, `color.strong`, `color.emph`.

Rythme : `rhythm.before_tool_group`, `rhythm.within_tool_group`,
`rhythm.after_user_turn`, `rhythm.between_md_blocks`, `rhythm.within_md_block`,
`rhythm.result_to_meta`, `rhythm.trailing_prose`.

Markdown : `md.h1.style`..`md.h3.style`, `md.list.bullet`, `md.list.number`,
`md.list.nest_indent`, `md.code.inline`, `md.code.block`, `md.code.theme`,
`md.table.style`, `md.rule`, `md.blockquote`, `md.link`, `md.block_separation`.

Animation : `anim.spinner.*`, `anim.reduced_motion`, `anim.stream.*`,
`anim.elapsed.format`, `anim.wait.*`, `anim.thinking.collapsed`.

---

*Livrable P0. Toute évolution de la mise en forme se mesure contre ce fichier ;
les écarts constatés sont suivis dans `docs/GAP_ANALYSIS.md`.*
