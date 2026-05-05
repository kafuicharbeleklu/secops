# Basic Penetration

## Meta
- Plateforme : TryHackMe
- Source locale : `sources/tryhackme/basic_penetration/basic_penetration_transcript.txt`
- Type : walkthrough transcript nettoye
- Usage cible : memoire de reference pour agent secops sur environnement autorise

## Portee
Cette fiche ne vaut que pour le lab TryHackMe cible. Elle ne doit pas etre generalisee a des cibles reelles sans validation humaine et autorisation explicite.

## Profil de la cible observe
- OS probable : Linux
- Services vus : `22/tcp` SSH, `80/tcp` HTTP, `139/tcp` et `445/tcp` SMB
- Indices complementaires : Apache sur Ubuntu, hostname `basic2`

## Signaux saillants
- La combinaison `HTTP + SMB + SSH` oriente vers une resolution multi-surface.
- Le site web expose un indice faible mais exploitable via un repertoire cache.
- SMB ne donne pas directement l'acces, mais aide a identifier des comptes utiles.
- Le premier acces n'est pas le dernier objectif : il sert de pivot vers un autre utilisateur.
- La resolution finale depend d'un artefact local trouve apres connexion initiale.

## Outils cites
- `nmap` pour l'enumeration initiale
- `gobuster` ou `dirbuster` pour l'enumeration web
- `enum4linux` pour SMB
- `hydra` pour l'essai de credentials SSH du lab
- `linpeas` pour l'enumeration locale
- `ssh2john` puis `john` pour traiter la passphrase de la cle SSH

## Artefacts a memoriser
- Repertoire web cache : `/development/`
- Utilisateurs identifies : `jan`, `kay`
- Service d'acces interactif : `SSH`
- Fichier pivot pour le second acces : `/home/kay/.ssh/id_rsa`
- Fichier final a lire : `/home/kay/pass.bak`

## Actions reconnues dans ce cas
```bash
nmap -sC -sV -oN nmap/initial <target_ip>
gobuster dir -u http://<target_ip>/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
enum4linux <target_ip>
hydra -l jan -P <wordlist> ssh://<target_ip>
scp linpeas.sh jan@<target_ip>:/dev/shm/
ssh2john id_rsa > id_rsa.hash
john --wordlist=<wordlist> id_rsa.hash
```

## Ce que ce cas doit apprendre a l'agent
- Ne pas se bloquer sur la premiere surface visible ; recouper web, SMB et acces shell.
- Utiliser les noms d'utilisateurs obtenus sur une surface comme hypotheses pour une autre surface.
- Traiter un premier shell comme point d'enumeration, pas comme fin du raisonnement.
- Chercher des artefacts reutilisables localement quand un second compte semble plus prometteur.
- Basculer de strategie quand une piste ne donne pas de preuve supplementaire.

## Zones d'incertitude du transcript
- Le transcript est bruité et comporte des erreurs de transcription.
- Certaines valeurs exactes de credentials ou de reponse finale doivent etre revalidees sur le lab avant de servir de verite terrain.
