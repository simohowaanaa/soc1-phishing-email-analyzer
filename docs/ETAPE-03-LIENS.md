# Étape 3 — Extraire et désactiver l’affichage des liens

## Objectif

L’analyseur repère les URL dans le texte brut, le texte visible du HTML et les destinations `href` des liens HTML. Pour chaque lien, il affiche le domaine et compare le domaine de destination au texte visible lorsque celui-ci ressemble lui-même à une URL.

## Affichage sûr

Les schémas `http` et `https` sont changés en `hxxp` et `hxxps`, et les points du domaine en `[.]`. Les paramètres de requête et fragments sont masqués car ils peuvent contenir des identifiants. L’outil ne fait aucune requête réseau.

## Limites

Un texte de lien descriptif, comme « ouvrir le document », ne contient pas un domaine à comparer ; il est affiché sans annoncer de différence. Les règles couvrent les URL HTTP(S) courantes, mais ne prouvent pas à elles seules que la destination est malveillante ou légitime.

## Lancer l’analyse

```powershell
python src\email_analyzer.py samples\02-lien-destination-differente.eml
```

Les exemples du projet emploient des domaines fictifs ou réservés. Les URL des e-mails réels restent des données hostiles : ne les réactive pas et ne les visite pas.
