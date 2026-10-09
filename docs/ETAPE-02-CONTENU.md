# Étape 2 — Lire le texte du message

## Objectif

L’analyseur compte les parties `text/plain` et `text/html`, puis cherche quelques formulations souvent associées à l’urgence, à une menace ou à une demande d’informations. Chaque signal affiche le terme exact repéré.

## Notions

Un e-mail peut contenir une version texte et une version HTML. Le programme extrait le texte visible du HTML avec un analyseur de balises ; il ne l’affiche pas dans un navigateur et n’exécute aucun script. Les autres types de contenu et les parties MIME marquées comme pièces jointes sont laissés de côté à cette étape.

Les règles sont volontairement simples. Un mot comme « urgent » peut apparaître dans un message légitime : c’est un signal à vérifier dans son contexte, pas une preuve. À l’inverse, l’absence de ces mots ne prouve pas qu’un e-mail est sûr.

## Lancer l’analyse

```powershell
python src\email_analyzer.py samples\01-urgence-authentification.eml
```

Pour obtenir le rapport structuré :

```powershell
python src\email_analyzer.py samples\01-urgence-authentification.eml --json
```

## Limites

Cette étape ne suit pas les liens, ne décode pas de pièce jointe, ne vérifie pas les domaines sur Internet et ne décide pas si le message est malveillant. Les règles linguistiques couvrent seulement quelques expressions françaises et anglaises.
