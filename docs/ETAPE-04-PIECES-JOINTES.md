# Étape 4 — Inventorier les pièces jointes

## Objectif

L’analyseur relève le nom, le type MIME déclaré, la taille décodée et l’empreinte SHA-256 des pièces jointes. Il signale certaines extensions à examiner, sans en déduire que le fichier est malveillant.

## Manipulation sûre

Les pièces jointes ne sont jamais écrites sur disque ni ouvertes. L’empreinte est calculée sur le contenu décodé en mémoire pour les fichiers jusqu’à 25 Mio ; au-delà, elle est omise. Les noms sont nettoyés des caractères de contrôle avant affichage. L’inventaire ne valide pas le type réel du fichier et n’effectue aucune analyse antivirus.

## Lancer l’analyse

```powershell
python src\email_analyzer.py samples\04-piece-jointe-synthetique.eml
```

Un résultat « aucune pièce jointe » indique seulement que le parseur n’en a pas identifié dans le message.
