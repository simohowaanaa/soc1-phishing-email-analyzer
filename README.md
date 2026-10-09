# SOC N1 — Analyse automatisée d’e-mails de phishing

> **Avertissement :** `samples/real-public/` contient deux copies redigées et défangées de vrais e-mails de phishing. Traitez-les comme du contenu hostile : analyse en texte brut uniquement, sans ouvrir dans un client mail et sans visiter les liens.

Projet personnel et pédagogique : construire un outil local qui aide un analyste SOC de niveau 1 à examiner un fichier `.eml` et à expliquer les indices observés.

> L’outil fournit une aide à l’analyse. Un score ne prouve pas qu’un message est malveillant ; la décision finale appartient à l’analyste et doit s’appuyer sur les preuves.

## État du projet

Fonctionnalités disponibles : lecture des en-têtes, extraction prudente du texte, repérage de formulations et de liens, désactivation des URL dans le rapport et inventaire des métadonnées des pièces jointes et export des rapports texte, JSON et Markdown. Chaque étape est documentée dans `docs/` et illustrée avec des exemples synthétiques.

## Sécurité et confidentialité

- Traitement local : aucun e-mail, lien ou fichier n’est envoyé à un service externe.
- Les liens ne sont jamais visités automatiquement.
- Les pièces jointes sont inventoriées et hachées, mais jamais ouvertes ni exécutées.
- Utiliser uniquement des messages synthétiques ou des messages dûment anonymisés et autorisés.

## Limites prévues

Lire des résultats SPF, DKIM ou DMARC inscrits dans les en-têtes ne revient pas à effectuer une vérification cryptographique ou DNS réelle. Le rapport distinguera les faits présents dans le message, les hypothèses et les informations impossibles à confirmer localement.

## Structure

- `src/` : code de l’analyseur.
- `samples/` : messages synthétiques inoffensifs.
- `reports/` : exemples de rapports générés.
- `docs/` : architecture, méthode et glossaire.
- `tests/` : vérifications sur les exemples synthétiques.
- `screenshots/` : captures de démonstration sans données privées.

## Échantillons réels publiés

Le dossier [`samples/real-public/`](samples/real-public/README.md) contient deux copies pédagogiques redigées de messages réels de phishing. **Elles contiennent du texte hostile : ne les ouvrez pas dans un client mail, ne visitez aucun lien et analysez-les uniquement comme texte brut.** Les adresses sont anonymisées et les URL défangées. Les fichiers synthétiques restent disponibles dans `samples/`.