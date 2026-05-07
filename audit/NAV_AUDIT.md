# Audit Navigation TUI

Date: 2026-05-07

Sources officielles Claude Code:
- https://code.claude.com/docs/en/interactive-mode
- https://code.claude.com/docs/en/keybindings
- https://code.claude.com/docs/en/permission-modes

Sources Codex CLI:
- https://developers.openai.com/codex/cli
- https://github.com/openai/codex/blob/main/codex-rs/tui/src/resume_picker.rs

Portee: navigation clavier, menus, focus, raccourcis, historique, transcript et comportement de selection. Le style visuel et la logique metier SECOPS n'ont pas ete changes volontairement.

## 1. Inventaire SECOPS Valide

| Zone | Comportement avant alignement |
| --- | --- |
| Prompt principal | `Enter` soumettait, `Ctrl+J` et `\` + `Enter` gereraient le multiline, `Ctrl+L` effacait l'input, `Ctrl+C`/`Esc` annulaient l'input, `Ctrl+R` rappelait un match d'historique, `Ctrl+T` ouvrait `/jobs`, `Ctrl+O` ouvrait `/view last --pager`, `Alt+P` ouvrait `/model`, `Alt+T` togglait le thinking. |
| Slash commands | Commandes explicites via `/...`; texte libre vers l'agent; `!cmd` executait une commande ponctuelle via les permissions SECOPS. |
| Palette `/menu` | Recherche fuzzy dediee, `Tab` completions, `Enter` ouverture, `Esc`/`Ctrl+C` annulation, `Ctrl+P/N` navigation. |
| Choix transitoires | `/phase`, `/scope`, `/permissions` utilisaient `choice` avec `Up/Down`, `Ctrl+P/N`, `Enter`, `Esc`. |
| Picker `/model` | Liste modele + thinking dans une grande liste; `Up/Down`, `Ctrl+P/N`, `Left/Right`, `Enter`, `Esc/Ctrl+C/Ctrl+D`. Avant la correction finale, l'effort etait en une seule ligne avec `Enter/Esc`, le `✔` etait decale en colonne, et les niveaux `Low/Medium/High/Max` Claude n'etaient pas rendus exactement. |
| Permissions | Modes `read-only`, `ask`, `auto-low-risk`, `session`, `deny`; dialog outil avec once/session/deny. |
| Transcript/sorties | Panneaux statiques, sorties tronquees, `/view last|job --pager` via pager systeme. |
| Historique | `FileHistory` prompt_toolkit + rappel simple `Ctrl+R`. |
| Side question | `/side` sans mutation de la memoire agent, rendu comme panneau normal. |

## 2. Reference Claude CLI

| Zone | Claude CLI |
| --- | --- |
| Aide | `?` affiche les raccourcis disponibles. |
| Prompt | `Enter` submit, `Ctrl+J` newline, `\` + `Enter` newline, `Ctrl+L` redraw sans perte, `Ctrl+D` exit, `Ctrl+G` ou `Ctrl+X Ctrl+E` editeur externe. |
| Menus/listes | `Up/K/Ctrl+P` precedent, `Down/J/Ctrl+N` suivant, `Enter` selection, `Esc` retour. |
| Slash menu | `/` ouvre/filtre les commandes. |
| Model | `Alt/Meta+P` ouvre `Select model`; la liste contient les modeles seulement, `Default` en premier, et l'effort est affiche en bas avec `Left/Right` pour ajuster. |
| Permissions | `Shift+Tab` cycle les modes; confirmation: `Y/Enter`, `N/Esc`, `Up/Down`, `Tab`, `Space`, `Ctrl+E`, `Ctrl+D`. |
| Transcript | `Ctrl+O` viewer; dans la vue: `Ctrl+E`, `[`, `v`, `q/Ctrl+C/Esc`. |
| Scroll | En fullscreen: `PageUp/PageDown`, `Ctrl+Home/Ctrl+End`. |
| Historique | `Ctrl+R` recherche interactive; `Ctrl+S` scope; `Tab/Esc` accepter; `Enter` executer; `Ctrl+C` annuler. |
| Side question | `/btw`, reponse ephemere dismissible, sans historique conversationnel. |

## 3. Gap Analysis

| Feature | Our TUI | Claude CLI | Action needed |
| --- | --- | --- | --- |
| Aide clavier | `/help`, pas `?` global | `?` ouvre l'aide raccourcis | Fait: `?` affiche une aide clavier SECOPS. |
| `/help` | Panneau statique listant toutes les commandes. | Vue d'aide transitoire same-page avec onglets `general`, `commands`, `custom-commands`, raccourcis et navigation clavier; l'onglet actif est rendu dans un conteneur colore. | Fait: `/help` ouvre un overlay effacable sur la meme page, inspire Claude et adapte a SECOPS; l'onglet actif a maintenant un fond colore avec padding; fallback panneau en non-TTY. |
| Slash seul | `/menu` se tapait explicitement | `/` declenche le menu | Fait: `/` seul ouvre la palette. |
| Palette `/menu` | En TTY, imprimait un panneau `• Palette` avant la recherche, ce qui laissait des traces dans le transcript. | Palette transitoire effacable sur la meme page, sans panneau persistant. | Fait: `/menu` utilise maintenant un overlay same-page `erase_when_done`, sans `render_panel_state()` prealable. |
| Reprise de session | La reprise etait accrochee a `/session resume`; `/session list` affichait une liste statique non filtrable, et l'action n'etait pas exposee comme commande dediee. | Codex expose une action `resume` dediee avec `Resume a previous session`, tri `Updated/Created`, recherche directe, navigation clavier, `Enter`, `Esc`, `Ctrl+C`, et expansion/preview de session. | Fait: `/resume` ouvre l'overlay `Resume a previous session  Sort: Updated`; `/resume --last` reprend la derniere session; recherche directe, `Esc` efface d'abord la recherche puis ferme, `←/→` change le tri, `Ctrl+E` affiche les details, `Ctrl+C` quitte proprement. |
| Inventaire `/tools` | Panneau long unique `Outils pentest`, sans onglets ni navigation par famille; la liste remplissait le transcript. | Vues longues type Claude: overlay same-page, onglets, onglet actif dans un conteneur colore, navigation clavier, fermeture `Esc` sans trace. | Fait: `/tools` sans argument ouvre un overlay `SECOPS tools` sur la meme page avec onglets `overview`, `installed`, `missing`, `recon`, `enum`, `exploit`, `util`; l'onglet actif utilise le meme conteneur colore que `/help`; `←/→`/`Tab` changent d'onglet, `↑/↓` parcourt les outils, fallback non-TTY structure les sections. |
| `/doctor` | Panneau `• Diagnostic` avec lignes `ok/attention`, sans structure Claude, sans onglets et sans pause clavier. | Vue diagnostic type Claude adaptee SECOPS: onglets directs, ligne de separation, sections `Diagnostics`, `Updates`, `Version locks`, branches `├/└`, puis `Press Enter to continue`. | Fait: `/doctor` ouvre un overlay a onglets `diagnostics`, `updates`, `locks`; onglet actif colore comme `/help`; `←/→`/`Tab` changent d'onglet, `Enter` revient au prompt, fallback non-TTY garde le contenu complet en panel plain. |
| Resultat commandes transitoires | `/phase`, `/model`, `/theme`, `/help`, `/doctor` laissaient seulement la ligne de prompt, sans indication de fermeture ou de contenu. | Claude garde la commande puis affiche une ligne `⎿ ... dismissed` ou `⎿ (no content)`. | Fait: les commandes transitoires impriment une ligne resultat `⎿` apres fermeture; `/help`, `/doctor`, `/model`, `/phase`, `/theme`, `/tools`, `/resume`, `/clear` et les autres vues transitoires sont couverts. |
| Vues d'information persistantes | `/status`, `/stats`, `/case`, `/target`, `/session`, `/plan`, `/learn`, `/workflow`, `/rewind`, `/jobs` et `/findings` rendaient leur panneau directement dans la discussion. | Claude affiche ces sorties de consultation dans une vue transitoire effacable sur la meme page, puis ne garde qu'une ligne `⎿ ... dismissed` dans le transcript. | Fait: ajout d'un dialog generique same-page pour les panneaux de consultation; les variantes mutantes (`/case <slug>`, `/target <ip>`, `/workflow <slug>`, `/session save`, `/jobs cancel`) restent persistantes. |
| Hauteur listes de choix | Les listes navigables pouvaient afficher 8 a 12 options selon le terminal, et la completion slash reservait 8 lignes. | Les listes Claude affichent 6 options visibles par defaut, puis scrollent avec `↑/↓`. | Fait: limite commune a 6 options pour les listes de choix, palette, help/tools/resume browse et completion slash. |
| Completion slash native | Le prompt principal affichait d'abord une completion native mal ordonnee, puis la palette overlay ajoutait une seconde ligne `› /` sous le placeholder du prompt; une correction intermediaire limitait les resultats a 6 commandes seulement, puis une autre affichait jusqu'a 16 lignes. | `/` reste dans le prompt courant et affiche une completion inline Codex: 6 lignes visibles par defaut, toutes les commandes accessibles avec `↑/↓`, ligne active en couleur/bold sans reverse. | Fait: `/` demarre la completion inline sans sortir du prompt; auto-suggestion d'historique slash desactivee; ordre initial `/model`, `/permissions`, `/theme`, `/reasoning`, `/profile`, `/statusline`; le menu prompt_toolkit est cappe a 6 lignes visibles et le completer fournit toutes les commandes. |
| Listes | Pas `J/K` partout | `J/K` equivalents de fleches | Fait: `J/K` ajoutes aux choix, palette, picker modele. |
| `Ctrl+L` | Effacait l'input | Redraw non destructif | Fait: redraw/invalidate sans reset buffer. |
| `Ctrl+D` | EOF direct | Quitte la session | Fait: dans le prompt, route vers `/quit` pour sortie propre. |
| `Ctrl+C` prompt | Vidait la saisie et revenait au prompt, sans fermer la session. | Quitte la session depuis le prompt principal. | Fait: `Ctrl+C` route vers `/quit` et affiche le resume de session. |
| `Enter` prompt vide | Soumettait une entree vide et pouvait reimprimer plusieurs fois le placeholder du prompt. | Ne soumet rien si le champ de saisie est vide. | Fait: `Enter` sur input vide invalide seulement l'affichage courant et reste dans le meme prompt. |
| `Esc` prompt vide | Annulait le prompt courant avec un resultat vide, ce qui relancait la boucle et pouvait empiler le placeholder. | Ne valide rien et reste dans le prompt courant. | Fait: `Esc` vide invalide seulement l'affichage; `Esc` avec texte efface la saisie sans relancer le prompt. |
| `Tab` prompt | Completait, mais ne validait pas une commande deja complete. | Complete d'abord, puis valide une commande slash complete comme `Enter`. | Fait: `Tab` soumet les commandes slash exactes et garde la completion pour les prefixes incomplets. |
| Editeur externe | `enable_open_in_editor`, pas `Ctrl+G` explicite | `Ctrl+G`, `Ctrl+X Ctrl+E` | Fait: `Ctrl+G` appelle l'editeur prompt_toolkit. |
| `Ctrl+O` | Pager `/view last --pager` | Transcript viewer toggle | Fait: viewer transcript interne via commande cachee. |
| Scroll transcript | Pager systeme | `PageUp/PageDown`, `Ctrl+Home/End` | Fait dans le viewer transcript. |
| Transcript actions | Pas `Ctrl+E`, `[`, `v`, `q` | Actions dediees | Fait: `Ctrl+E`, `[`, `v`, `q/Ctrl+C/Esc`. |
| `Ctrl+R` | Rappel one-shot | Recherche interactive | Fait: mini recherche interactive avec scope et accept/execute. |
| Picker modele | Liste combinee modele + thinking; puis footer partiellement aligne mais sans les quatre etats Claude exacts | Liste courte `Default` + modeles, effort en footer `○ Low`, `◐ Medium`, `● High (default)`, `◈ Max`; sous-menu inline | Fait: `/model` reproduit la structure `Select model`; `✔` est colle au choix actif, `←/→` ajuste l'effort sans changer la ligne selectionnee, footer commun, pas de page separee. |
| Permissions aliases | Modes SECOPS seulement | Labels Claude `default`, `acceptEdits`, `plan`, `auto`, `bypassPermissions` | Fait: aliases mappes vers modes SECOPS. |
| Sous-menus de selection | `/phase`, `/scope`, `/permissions`, `/model`, `/theme`, `/profile`, `/reasoning`, `/notify` et `/statusline` utilisaient des pages transitoires, des panneaux d'information, ou des rendus non uniformes; certains menus laissaient aussi le panneau precedent se reimprimer apres validation. | Liste deroulante inline, ligne active contrastee, `Enter` valide, `Esc` revient, puis retour propre au prompt sans trace du menu. | Fait: composant inline commun pour les sous-menus pertinents, effacement automatique apres fermeture, et marquage transitoire de `/theme` et `/reasoning`. |
| Prompt d'autorisation outil | Le choix `once/session/deny` utilisait encore `prompt_toolkit.choice`, avec un style different des sous-menus. | Meme liste numerotee que les autres choix, marqueur `›`, ligne active contrastee, fermeture propre. | Fait: le prompt d'autorisation outil passe par `ClaudeStyleRadioList` et le composant inline commun. |
| Zone de saisie | Le prompt principal utilisait le meme fond que le terminal, sans contraste avec le background general. | Ligne de saisie legerement contrastee par rapport au fond principal. | Fait: ajout de `input_bg_hex` dans les palettes et application au style prompt/input-selection. |
| Details de menus | Les descriptions et metadonnees etaient rendues de facon incoherente selon les listes. | Les details d'option dans les listes de choix Claude gardent la meme mise en valeur de police que le nom de l'option; les lignes de contexte hors option restent attenuees. | Fait: descriptions de listes interactives rendues avec le meme style que leur option; `menu.detail` reste en `fg` uniquement pour les lignes secondaires hors selection. |
| `/btw` | `/side` panneau normal | `/btw` ephemere dismissible | Fait: `/btw` ajoute, overlay dismissible en TTY. |
| `!` autocomplete | Commande ponctuelle sans completion dediee | Historique shell autocomplete | Fait: commandes `!` recentes exposees au catalogue de completion. |
| Style titres/listes | Les panneaux affichaient `✓/!/✕/●` selon le ton et ajoutaient `•` devant chaque ligne; premier correctif incomplet sans tirets automatiques. | Style Codex: titre court `• Titre`, paragraphes indentés, listes avec `-`. | Fait: rendu panneau aligne, lignes de contenu converties en `- ...`, et prompt agent contraint au style Codex. |
| `Alt+O` fast mode | Aucun equivalent | Toggle fast mode | Divergence: pas de mode SECOPS equivalent. |
| `Ctrl+B` background | Jobs existent, pas de background key | Background task | Divergence: toucherait l'execution metier. |
| Vim mode | Absent | Optionnel | Divergence: changerait le modele d'edition global. |
| Image paste | Absent | Image chip | Divergence: hors scope TUI SECOPS actuel. |

## 4. Changements Appliques

| Changement | Avant | Apres | Fichiers |
| --- | --- | --- | --- |
| Aide clavier `?` | `?` partait vers l'agent comme texte libre. | `?` affiche `Raccourcis clavier`. | `app/project_shell.py`, `tests/test_project_shell.py` |
| `/help` Claude-like | Panneau `Commandes` dense et statique; onglet actif d'abord seulement en majuscules. | Overlay effacable avec onglets `general`, `commands`, `custom-commands`; onglet actif dans un conteneur colore avec padding; onglet commandes browsable avec `↑/↓`; onglet custom base sur les workflows TOML locaux; `Esc` ferme sans trace. | `app/project_shell.py`, `tests/test_project_shell.py` |
| Palette `/` | `/` seul etait une commande inconnue ou incomplete. | `/` seul ouvre la palette fuzzy. | `app/project_shell.py`, `tests/test_project_shell.py` |
| Palette sans trace | `/menu` rendait `• Palette` dans la conversation avant d'ouvrir le prompt de recherche. | Overlay same-page effacable avec recherche, liste `›`, `Enter` ouvrir, `Esc` retour; aucun panneau `Palette` n'est imprime en TTY. | `app/project_shell.py`, `tests/test_project_shell.py` |
| `/resume` Codex-like | La reprise dependait de `/session resume`; sans ID, l'usage non-TTY demandait encore `/session resume <id>`. | Commande dediee `/resume`; overlay same-page `Resume a previous session` avec colonnes `Created`, `Updated`, `Branch`, `Conversation`; tri par `Updated`, recherche au clavier, `←/→` pour basculer le tri, `Ctrl+E` details, `Enter` restaure, `Esc` clear/cancel. | `app/project_shell.py`, `tests/test_project_shell.py` |
| `/tools` onglets | Inventaire plat et tronque a 20 lignes dans un panneau persistant. | Overlay same-page `SECOPS tools` avec onglets `overview`, `installed`, `missing`, `recon`, `enum`, `exploit`, `util`; onglet actif dans le meme conteneur colore que `/help`; liste selectionnable `›`; footer de navigation; `/tools install <name>` reste l'action explicite. | `app/project_shell.py`, `tests/test_project_shell.py` |
| `/doctor` Claude-like | Panneau Codex generique `• Diagnostic` listant `ok` ou `attention`, puis premier alignement avec un onglet `overview` inutile. | Overlay same-page `SECOPS doctor` avec onglets directs `diagnostics`, `updates`, `locks`; sections en arbre, valeurs runtime SECOPS, `Press Enter to continue`; pas de bullet/panneau autour du diagnostic. | `app/project_shell.py`, `tests/test_project_shell.py` |
| `Enter` prompt vide | Appuyer sur `Enter` avec le champ vide pouvait relancer le prompt et empiler le placeholder. | `Enter` vide ne soumet plus d'interaction; le prompt courant reste en place. | `app/project_shell.py`, `tests/test_project_shell.py` |
| Transcript commandes transitoires | Ligne commande seule, par exemple `› /doctor`, puis retour direct au prompt. | Ligne commande suivie de `⎿  SECOPS diagnostics dismissed`, `⎿  Help dialog dismissed`, ou `⎿  (no content)` pour `/clear`. | `app/project_shell.py`, `tests/test_project_shell.py` |
| Panneaux de consultation transitoires | Les commandes de lecture (`/status`, `/workflow`, `/case`, etc.) imprimaient leur contenu complet dans le transcript. | Vue same-page effacable avec fond legerement contraste, `↑/↓`, `PageUp/PageDown`, `Enter`, `Esc`; retour au prompt avec seulement `⎿ ... dialog dismissed`. | `app/project_shell.py`, `tests/test_project_shell.py` |
| Listes limitees a 6 options | Listes de choix et completion slash affichaient plus de 6 entrees visibles. | `ClaudeStyleRadioList` fixe une hauteur de 6 options max; palette/help/tools/resume/completion slash utilisent la meme limite. | `app/project_shell.py`, `app/branding.py`, `tests/test_project_shell.py` |
| Completion slash inline | Le slash ouvrait une palette overlay, ce qui pouvait laisser le placeholder `› Decris...` au-dessus de la liste; puis seuls 6 resultats etaient fournis au menu; ensuite toutes les commandes etaient visibles jusqu'a la limite interne prompt_toolkit de 16 lignes. | La saisie `/` reste dans le prompt courant: `› /`, blanc, 6 commandes visibles, toutes les autres accessibles avec `↑/↓`, sans titre, sans aide, sans footer, sans suggestion fantome comme `/theme`, sans reverse sur la ligne active. | `app/project_shell.py`, `app/shell_template.py`, `tests/test_project_shell.py` |
| Fond et details des listes | Le style selectionne utilisait un fond/reverse, ce qui donnait un conteneur autour de l'option; les details de radio-list utilisaient parfois `menu.detail`; l'option courante pouvait rester mise en evidence meme sans etre pointee. | Fond contraste applique a la zone de liste seulement; toutes les listes utilisent le meme `class:selected-option` que `/menu`; seule l'option pointee et sa description sont en couleur/bold, sans `bg` ni reverse. | `app/shell_template.py`, `app/project_shell.py`, `tests/test_project_shell.py` |
| Details attenues | Descriptions longues hors ligne d'option avec la meme intensite que l'entree principale. | Style commun `menu.detail` en couleur de police seulement pour les lignes secondaires de contenu (`/tools`, `/help`, resume details), sans couleur de fond. | `app/shell_template.py`, `app/project_shell.py`, `tests/test_project_shell.py` |
| Navigation `J/K` | Plusieurs vues n'avaient que fleches ou `Ctrl+P/N`. | `J/K` ajoutés aux listes, palette et picker modele. | `app/project_shell.py` |
| `Ctrl+L` | Reset du buffer courant. | Redraw/invalidate sans supprimer la saisie. | `app/project_shell.py` |
| `Ctrl+G` | Pas de binding explicite. | Ouvre l'editeur externe du buffer. | `app/project_shell.py` |
| `Ctrl+D` | EOF prompt_toolkit. | Retourne `/quit` pour resume de session. | `app/project_shell.py` |
| `Ctrl+C` prompt | Annulait la saisie sans sortir. | Retourne `/quit` et ferme proprement la session. | `app/project_shell.py`, `tests/test_project_shell.py` |
| `Tab` prompt | Completait seulement. | Complete les prefixes; si la commande slash est deja complete, soumet comme `Enter`. | `app/project_shell.py`, `tests/test_project_shell.py` |
| `Esc` prompt vide | Sortait du prompt avec un resultat vide, puis le loop recréait une nouvelle invite visible. | Reste dans le prompt courant; avec du texte, efface la saisie en place; avec completion ouverte, ferme la completion. | `app/project_shell.py`, `tests/test_project_shell.py` |
| `Ctrl+O` | Ouvrait le pager du dernier output. | Ouvre un viewer transcript interne. | `app/project_shell.py`, `tests/test_project_shell.py` |
| Viewer transcript | Pas de viewer interne. | `Ctrl+E` show-all, `PageUp/PageDown`, `Ctrl+Home/End`, `[`, `v`, `q/Esc/Ctrl+C`. | `app/project_shell.py`, `tests/test_project_shell.py` |
| `Ctrl+R` | Remplacement direct par un match. | Recherche interactive avec `Ctrl+R`, `Ctrl+S`, `Tab/Esc`, `Enter`, `Ctrl+C`. | `app/project_shell.py`, `tests/test_project_shell.py` |
| `/model` Claude-like | Grande liste combinant chaque modele avec chaque niveau de thinking; ensuite footer partiel non conforme, page separee, puis marqueur `❯` different des autres listes. | `Select model`: meme marqueur `›` que les autres choix, modeles custom ensuite, effort en lignes `○ Low`, `◐ Medium`, `● High effort (default)`, `◈ Max effort`; footer commun `Press enter to confirm or esc to go back`, inline. | `app/project_shell.py`, `tests/test_project_shell.py` |
| Marqueurs de selection | `/model` utilisait `❯`, `/phase` ajoutait un `*` interne au label actif, et `/help` utilisait aussi `❯` dans les listes. | Un seul marqueur interactif `›`; l'etat actif est indique par `(current)`. | Fait: `/model`, `/phase`, `/help commands` et `/help custom-commands` sont harmonises. |
| Permissions Claude aliases | `default`, `acceptEdits`, `plan`, `bypassPermissions` invalides. | Aliases acceptes et mappes vers `ask`, `auto-low-risk`, `read-only`, `session`. | `app/project_shell.py`, `tests/test_project_shell.py` |
| Sous-menus inline Codex | Touches limitees, page transitoire separee, panneau statique, ou trace residuelle apres fermeture pour `/permissions`, `/theme`, `/phase`, `/scope`, `/model`, `/profile`, `/reasoning`, `/notify` et `/statusline`. | Liste deroulante inline, ligne active par couleur/bold sans conteneur d'option, footer `Press enter to confirm or esc to go back`; fermeture `Enter`/`Esc` avec effacement du dropdown; `/permissions` affiche `Update Model Permissions` avec `› 1. Default (current)`, `2. Auto-review`, `3. Full Access`. | `app/project_shell.py`, `app/shell_template.py`, `app/branding.py`, `tests/test_project_shell.py` |
| Prompt d'autorisation outil | `prompt_toolkit.choice` rendait `once/session/deny` differemment des autres menus. | Meme rendu `ClaudeStyleRadioList`: titre, champs contexte, options numerotees, `›`, selection contrastee, `Enter`/`Space`/`Y` accepter, `N` refuser, `Esc` annuler. | `app/project_shell.py`, `tests/test_project_shell.py` |
| Contraste zone de saisie | Le prompt principal et les listes non selectionnees etaient poses sur le fond general. | `input_bg_hex` donne un fond legerement contraste a l'input et aux listes; `selection_bg_hex` reste reserve a la ligne active. | `app/shell_template.py`, `app/branding.py`, `tests/test_project_shell.py` |
| `/btw` | Absent. | Ajoute comme question laterale ephemere, sans memoire agent. | `app/project_shell.py`, `tests/test_project_shell.py` |
| Completion `!` | Pas de completion shell recente. | Les commandes `!` recentes sont completables. | `app/project_shell.py`, `tests/test_project_shell.py` |
| Style Codex titres/listes | Titre du panneau colore avec icone de ton; chaque ligne forcee en `•`; puis lignes conservees sans tirets. | Titre en `• Titre`; lignes de contenu rendues en `- ...`; titres de section conserves; prompt agent demande le meme style. | `app/shell_template.py`, `app/agent_loop.py`, `tests/test_project_shell.py`, `tests/test_agent_loop.py` |

## 5. Fichiers Modifies

- `templates/automation_project/app/project_shell.py`
- `templates/automation_project/app/shell_template.py`
- `templates/automation_project/app/branding.py`
- `templates/automation_project/app/agent_loop.py`
- `templates/automation_project/tests/test_project_shell.py`
- `templates/automation_project/tests/test_agent_loop.py`
- `audit/NAV_AUDIT.md`

Le worktree contenait deja d'autres fichiers modifies avant cet alignement; ils n'ont pas ete revertes.

## 6. Limitations Et Divergences

- Le prompt d'autorisation outil garde le vocabulaire SECOPS (`Autoriser une fois`, `Autoriser pour la session`, `Refuser`) plutot que les libelles exacts Claude.
- La recherche historique a trois scopes visibles (`session`, `projet`, `partout`), mais `projet` et `partout` utilisent le meme historique local disponible dans SECOPS.
- Le viewer transcript est interne et navigable, mais il n'implemente pas la selection/copie fullscreen de Claude.
- Le selecteur `/resume` affiche `Branch` a `-`, car SECOPS ne persiste pas encore de metadonnees Git par session.
- `/session resume` reste route vers `/resume` comme compatibilite legacy, mais l'UX cible expose maintenant `/resume`.
- `/tools` ne lance pas l'installation avec `Enter` depuis l'overlay; l'action reste volontairement explicite via `/tools install <name>` pour eviter une installation accidentelle.
- `/btw` est dismissible en TTY. En non-TTY, il retombe sur un panneau normal.
- Le libelle exact du modele depend de Gemini/Gemma, donc il ne reprend pas les noms Claude `Sonnet/Opus/Haiku`; la structure UX du picker est alignee. Le texte de contexte dit `SECOPS`/`GEMINI_MODEL` au lieu de `Claude Code`/`--model` pour ne pas annoncer une option qui n'existe pas dans cette CLI.
- `Shift+Enter` et `Option+Enter` restent dependants du terminal; les chemins portables `Ctrl+J` et `\` + `Enter` sont conserves.
- `Alt+O` fast mode, `Ctrl+B` background, image paste et Vim mode complet sont volontairement non implementes, car ils touchent a des capacites absentes ou a l'execution metier.
- `@` garde les references SECOPS securisees; l'autocomplete fichier brute de Claude n'a pas ete ajoutee.

## 7. Verification

- `env PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX=/tmp/secops_pycache .venv/bin/python -m unittest tests.test_project_shell`
  - Resultat: 198 tests OK.
- `env PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX=/tmp/secops_pycache .venv/bin/python -m unittest tests.test_agent_loop`
  - Resultat: 13 tests OK.
- `env PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX=/tmp/secops_pycache .venv/bin/python -m unittest discover -s tests`
  - Resultat: 691 tests OK.
- TTY smoke `/model`
  - Resultat: rendu observe avec `› 1. Default ✔`, `● High effort (default) ← → to adjust`, `◈ Max effort` via fleche droite, `○ Low effort` via fleche gauche, puis `Press enter to confirm or esc to go back`.
- TTY smoke `/help`
  - Resultat: overlay same-page observe avec onglets `general`, `commands`, `custom-commands`; aucune sequence d'ecran alternatif `?1049h`; l'onglet actif est dans un conteneur colore avec padding; retour `Esc` propre au prompt avec `⎿  Help dialog dismissed`.
- TTY smoke `/menu`
  - Resultat: overlay same-page observe au format compact `› /`, ligne vide, 6 lignes d'options visibles (`/model` a `/statusline`), sans titre `Command palette`, sans footer, pas de reverse/conteneur sur l'option; retour `Esc` propre au prompt.
- TTY smoke slash direct
  - Resultat: saisie `/` sur prompt vide reste sur une seule ligne `› /`; l'ancien placeholder `› Decris...` ne reste pas au-dessus de la liste; aucune suggestion d'historique `/theme`; 6 options visibles avec `/model` en premier; `↓` fait defiler vers les commandes suivantes; a hauteur de `/menu`, seules 6 lignes restent visibles et la ligne active est en bold/couleur sans reverse.
- TTY smoke `/resume`
  - Resultat: overlay same-page observe avec `Resume a previous session  Sort: Updated`, colonnes `Created`, `Updated`, `Branch`, `Conversation`, selection `›`, recherche clavier, pas de sequence `?1049h`, retour propre au prompt.
- TTY smoke `/tools`
  - Resultat: overlay same-page observe avec `SECOPS tools`; onglets `overview` puis `installed` rendus comme conteneur actif colore; navigation `→`, selection `› gobuster`; les lignes `description/phases/targets` passent par un style detail en couleur de police uniquement, sans `bg`; retour `Esc` propre au prompt, sans panneau `• Outils pentest` dans le transcript.
- TTY smoke `/doctor`
  - Resultat: overlay same-page observe avec `SECOPS doctor`, onglets `diagnostics`, `updates`, `locks`, onglet actif colore; `Press Enter to continue`, puis retour propre au prompt apres `Enter` avec `⎿  SECOPS diagnostics dismissed`.
- TTY smoke `/clear`
  - Resultat: ecran reinitialise, header rendu, puis ligne `⎿  (no content)`.
- TTY smoke prompt vide
  - Resultat: deux appuis `Enter` et trois appuis `Esc` avec le champ vide ne creent pas de nouvelles lignes `› Decris...`; le prompt reste en place.
- TTY smoke `/phase`
  - Resultat: liste observee avec `› 1. Reconnaissance (current)` sans marqueur `*`.
- TTY smoke `/status`
  - Resultat: overlay same-page observe avec `Status`, navigation `↑/↓` disponible, aucune sequence d'ecran alternatif `?1049h`, retour `Enter` propre au prompt avec `⎿  Status dialog dismissed`; aucun panneau `• Status` persistant dans le transcript.
- TTY smoke `/workflow`
  - Resultat: overlay same-page observe avec `Workflows`, details de workflows visibles, retour `Esc` propre au prompt avec `⎿  Workflow dialog dismissed`; aucun panneau `• Workflows` persistant dans le transcript.
- TTY smoke `/case`
  - Resultat: overlay same-page observe avec `Memoire de lab`, retour `Esc` propre au prompt avec `⎿  Case dialog dismissed`; aucun panneau `• Memoire de lab` persistant dans le transcript.
- TTY smoke prompt principal
  - Resultat: `/status` + `Tab` execute la commande; `Ctrl+C` ferme la session avec `• Session terminee`.
- TTY smoke `/permissions`
  - Resultat: rendu observe inline avec `Update Model Permissions`, `› 1. Default (current)`, `2. Auto-review`, `3. Full Access`; meme style que `/menu`: option pointee et detail en mise en valeur de police uniquement (`bold`/couleur), sans reverse ni fond d'option.
- TTY smoke prompt d'autorisation `!pwd`
  - Resultat: rendu observe avec `Permission requise`, champs contexte, `› 1. Autoriser une fois`, `2. Autoriser pour la session`, `3. Refuser`; retour `Esc` verifie sans trace residuelle du dropdown.
- TTY smoke `/theme`
  - Resultat: rendu observe inline avec `Select theme`, options numerotees, footer commun et retour `Esc`.
- TTY smoke `/profile`, `/reasoning`, `/notify`, `/statusline`
  - Resultat: rendu observe inline avec titre, description courte, options numerotees, ligne active contrastee, footer commun et retour `Esc`; `/statusline` verifie avec separation correcte entre `Profile default (current)` et sa description; `/reasoning` verifie avec `Enter` sans reimpression du panneau precedent.
- `printf '/quit\n' | env PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX=/tmp/secops_pycache bash entrypoints/run_secops_agent.sh`
  - Resultat: code 0, demarrage et sortie non-interactive OK.
