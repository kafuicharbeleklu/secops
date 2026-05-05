# Case Memory

## Situation abstraite
Une cible expose plusieurs surfaces d'entree modestes. Aucune ne donne seule la solution complete, mais leur combinaison revele une progression plausible vers le secret final.

## Signaux declencheurs
- Presence conjointe de `HTTP`, `SMB` et `SSH`
- Repertoire web cache contenant des notes humaines ou de dev
- Enumeration SMB qui revele des utilisateurs nominatifs
- Premier acces shell avec peu de privileges
- Presence de fichiers sensibles dans le home d'un autre utilisateur

## Hypotheses utiles
- Les indices web peuvent decrire une faiblesse de credentials ou confirmer un nom d'utilisateur.
- SMB peut fournir des noms de comptes reutilisables pour `SSH`.
- Un acces initial a un utilisateur faible sert surtout a faire de l'enumeration locale.
- Une cle privee ou un fichier de sauvegarde dans le home d'un autre utilisateur peut offrir un pivot plus utile que l'utilisateur courant.

## Actions candidates et lecture du resultat
- Si le web semble vide, chercher des repertoires ou fichiers de travail non lies dans l'interface.
  Signal attendu : notes, brouillons, chemins internes, indices de comptes ou de mots de passe.
- Si `SMB` est ouvert, enumerer les utilisateurs et les partages.
  Signal attendu : noms de comptes, acces anonymes, chemins reutilisables ailleurs.
- Si un utilisateur faible devient plausible, tester l'acces distant autorise du lab.
  Signal attendu : premier shell, meme non privilegie.
- Si le shell initial n'ouvre pas directement la voie, enumerer les homes, permissions et clefs.
  Signal attendu : artefact de pivot, cle privee, sauvegarde, secret local.
- Si une cle est chiffree, tenter d'obtenir sa passphrase a partir d'un outillage adapte.
  Signal attendu : second acces plus pertinent.

## Pivot et deuxieme approche
Quand une hypothese echoue, le point important n'est pas de "forcer plus", mais de changer de surface ou de niveau.

Exemples de pivots observes dans ce cas :
- web pauvre -> enumeration de repertoires ;
- SMB peu bavard -> extraction de noms d'utilisateurs ;
- premier shell limite -> chasse aux artefacts locaux ;
- acces utilisateur A insuffisant -> pivot vers utilisateur B.

## Lecons transferables
- Les rooms debutantes reutilisent souvent des indices croises entre services.
- Un echec sur une surface n'invalide pas le cas ; il reduit seulement l'hypothese courante.
- Les artefacts locaux ont souvent plus de valeur qu'une escalation prematuree.
- Ce qu'un agent doit memoriser n'est pas seulement "quoi faire", mais "dans quelles conditions cela devient pertinent".

## Memoire a enrichir apres execution
- Quels signaux ont ete les plus predictifs ?
- Quelle hypothese etait fausse et pourquoi ?
- Quel pivot a debloque la situation ?
- Quelle action a coute du temps sans apporter de preuve ?
- Quel pattern semble transferable a un autre lab proche ?
