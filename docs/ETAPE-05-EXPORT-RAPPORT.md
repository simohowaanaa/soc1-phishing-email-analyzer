# Étape 5 — Enregistrer un rapport

Le rapport peut être conservé dans un fichier texte, JSON ou Markdown. Aucune donnée n'est envoyée sur Internet.

Rapport lisible :
python src\email_analyzer.py samples\04-piece-jointe-synthetique.eml --output reports\analyse-piece-jointe.txt

Rapport structuré JSON :
python src\email_analyzer.py samples\04-piece-jointe-synthetique.eml --json --output reports\analyse-piece-jointe.json

Le dossier de destination est créé s'il n'existe pas. Les rapports peuvent contenir des données sensibles : ne les publie pas sans anonymisation.


Rapport Markdown :
python src\email_analyzer.py samples\04-piece-jointe-synthetique.eml --markdown --output reports\analyse-piece-jointe.md

Les champs qui proviennent du courriel sont placés dans des blocs de code Markdown pour qu'ils ne soient pas interprétés comme des liens ou du HTML actif.
