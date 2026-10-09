# Étape 1 — Lire les en-têtes généraux et les indices de routage

## Objectif

Le programme affiche les champs `From`, `To`, `Subject`, `Date` et `Reply-To`. Il recense aussi chaque ligne `Received`, `Authentication-Results` et `ARC-Authentication-Results` présente dans le fichier. Les lignes répétées sont conservées.

## Notions

Un serveur de messagerie ajoute généralement une ligne `Received` lorsqu’il transmet un message. L’ordre et la fiabilité de ces lignes dépendent du chemin et des serveurs qui ont traité le message ; il faut les examiner comme des éléments rapportés dans le fichier.

Les valeurs SPF, DKIM et DMARC écrites dans `Authentication-Results` sont des résultats rapportés par un système de messagerie. Ce programme les affiche, mais ne refait ni la vérification DNS de SPF/DMARC ni la vérification cryptographique de DKIM.

Un domaine différent entre `From` et `Reply-To` est signalé comme un indice à examiner, jamais comme une preuve autonome de phishing.

## Lancer l’analyse

Depuis la racine du projet :

```powershell
python src\email_analyzer.py samples\01-urgence-authentification.eml
```

Pour obtenir ces informations en JSON :

```powershell
python src\email_analyzer.py samples\01-urgence-authentification.eml --json
```

Le programme lit le fichier localement. Il ne rend pas le HTML, ne visite aucun lien et n’extrait aucune pièce jointe.
