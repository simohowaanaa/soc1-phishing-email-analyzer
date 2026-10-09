# Rapport d'analyse e-mail

Fichier : `02-lien-destination-differente.eml`

## Informations générales
- **Expéditeur (From) :** `Portail RH <notifications@rh-exemple.invalid>`
- **Destinataire (To) :** `Analyste SOC <analyste@example.invalid>`
- **Objet (Subject) :** `Document à consulter`
- **Date :** `Fri, 09 Oct 2026 10:30:00 +0000`
- **Réponse à (Reply-To) :** `absent`

## Routage et authentification observés

Lignes `Received` : 1
- `from relay.rh-exemple.invalid (192.0.2.40) by mx.example.invalid`

### Authentication-Results
- `mx.example.invalid; spf=pass smtp.mailfrom=rh-exemple.invalid; dkim=pass header.d=rh-exemple.invalid; dmarc=pass header.from=rh-exemple.invalid`

### ARC-Authentication-Results
- absent

## Indices à examiner
- **`reply_to_domain_differs` — non évalué : domaine absent ou indéterminé.** Une différence de domaine entre From et Reply-To mérite un examen, mais ne prouve pas une fraude.

## Corps du message

0 partie(s) texte brut ; 1 partie(s) HTML. Le HTML est extrait sans rendu.

Aucune formulation surveillée détectée par les règles simples actuelles.

## Liens

Liens trouvés : 2
- **Lien 1 (lien HTML) :** `hxxps://espace-partage[.]example[.]invalid/document-demo`
  - Domaine : `espace-partage[.]example[.]invalid`
  - Texte affiché : `https://portail-rh.example.invalid`
  - Domaine du texte URL / destination : différent
- **Lien 2 (texte visible HTML) :** `hxxps://portail-rh[.]example[.]invalid`
  - Domaine : `portail-rh[.]example[.]invalid`

## Pièces jointes

Pièces jointes trouvées : 0

## Limites

En-têtes, texte, destinations URL désactivées et métadonnées de pièces jointes uniquement; aucun lien n'est visité, aucune pièce jointe n'est ouverte ou extraite, et SPF/DKIM/DMARC ne sont pas revérifiés.
