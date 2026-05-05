# Agent Runbook

Ce fichier est conserve pour compatibilite, mais le projet ne doit pas s'appuyer sur un runbook rigide.

## Direction retenue
Le raisonnement doit partir d'une memoire de cas :
- signaux observes ;
- hypotheses possibles ;
- actions candidates ;
- resultat obtenu ;
- pivot si l'hypothese echoue.

## Reference a utiliser
La source principale pour ce lab est maintenant `case_memory.md`.

## Garde-fous
- Rester dans le perimetre du lab autorise.
- Journaliser les observations et les echecs, pas seulement les succes.
- Favoriser les actions justifiees par les signaux actuels.
- Changer d'approche quand une piste n'apporte plus de preuve.
