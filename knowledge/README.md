# Base de connaissance

Ce dossier doit servir de memoire d'experiences pour l'agent secops, pas de collection de procedures figees.

## Objectif
Face a un nouveau lab ou a une nouvelle situation, l'agent doit pouvoir :
- reconnaitre des signaux deja vus ;
- formuler plusieurs hypotheses plausibles ;
- choisir une action utile a faible cout ;
- changer d'approche si le premier essai ne confirme pas l'hypothese ;
- enregistrer ce qu'il a appris pour reutilisation future.

## Convention
- Un dossier par plateforme puis par lab : `knowledge/<platform>/<lab_slug>/`
- Garder la source brute separee du contenu nettoye, idealement dans `sources/<platform>/<lab_slug>/`.
- Stocker des fiches transferables, lisibles par un humain comme par un moteur RAG.

## Fichiers recommandes par lab
- `lab_profile.md` : faits stables sur le lab, signaux observes, artefacts clefs.
- `case_memory.md` : hypotheses, essais, echecs, pivots et lecons reutilisables.
- `attempt_journal.jsonl` : journal append-only des tentatives executees par l'agent.
- `notes.md` ou autres annexes si un lab demande des details supplementaires.
- `agent_runbook.md` uniquement si une compatibilite historique est necessaire.

## Schema de connaissance conseille
Chaque cas doit separer clairement :
- `signaux` : ports, banniere, erreurs, chemins, utilisateurs, fichiers, privileges ;
- `hypotheses` : ce que ces signaux peuvent indiquer ;
- `actions candidates` : quoi tester et pourquoi ;
- `resultats` : ce qui a marche, echoue ou reste ambigu ;
- `pivot` : quand et pourquoi changer d'approche ;
- `transfert` : dans quels autres contextes ce cas peut aider ;
- `techniques` : techniques utilisees (brute_force, sql_injection, directory_traversal, privesc, etc.) ;
- `services` : services concernes (ssh, http, smb, ftp, ldap, mysql, etc.).

## Regles de cadrage
- Contenu applicable aux labs autorises (TryHackMe, HackTheBox), aux infrastructures internes, et aux bacs a sable.
- Toujours distinguer les faits, les hypotheses et les suppositions.
- Eviter les recettes universelles ; privilegier les conditions d'application.
- Enrichir la memoire apres chaque tentative reussie ou non.
- Un cas peut representer un lab, un audit reel, ou un scenario d'infrastructure.

## Integration future
Quand le modele sera branche au shell, la recherche doit se faire d'abord par similarite de signaux et d'echecs passes, pas par nom exact de lab. Le transcript brut doit rester une source secondaire utile pour verification, pas la base principale du raisonnement.
