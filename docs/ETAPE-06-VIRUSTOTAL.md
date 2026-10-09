# Étape 6 — Enrichissement facultatif avec VirusTotal

## Fonctionnement

Avec l’option `--virustotal`, l’outil consulte au maximum quatre indicateurs : domaines extraits des liens et en-têtes, et empreintes SHA-256 des pièces jointes. Il ne transmet ni fichier `.eml`, ni pièce jointe, ni URL complète. Les domaines réservés des exemples (`.invalid`, `.example`, `.test`, etc.) ne sont pas interrogés.

VirusTotal indique que les IoC soumis ou consultés par son API peuvent être ajoutés à son jeu de données et rendus accessibles à sa communauté. N’utilise pas cette option avec des domaines, empreintes ou messages confidentiels, sensibles ou personnels. Une absence de résultat n’est pas une preuve d’innocuité ; les détections sont des résultats tiers, pas un verdict. Le code n’effectue aucun envoi de fichier ou scan actif.

Pour l’API publique, VirusTotal annonce une limite de 4 requêtes par minute et 500 par jour, ainsi qu’un usage non commercial. Cette intégration plafonne chaque analyse à quatre requêtes et signale les indicateurs ignorés. Les limites et permissions dépendent de l’offre ; vérifie-les dans les conditions de VirusTotal avant tout autre usage.

## Clé API

Obtiens une clé auprès de VirusTotal, puis configure-la uniquement pour la session de terminal courante. Ne la colle pas dans le projet ni dans le chat. Dans PowerShell :

```powershell
$secure = Read-Host "Clé API VirusTotal" -AsSecureString
$env:VT_API_KEY = [System.Net.NetworkCredential]::new("", $secure).Password
Remove-Variable secure
python src\email_analyzer.py samples\04-piece-jointe-synthetique.eml --virustotal --markdown --output reports\analyse-virustotal.md
```

Dans CMD, tu peux utiliser `set /p VT_API_KEY=Clé API VirusTotal: ` dans la session courante, puis lancer la même commande `python`.

Sans l’option `--virustotal`, l’analyse reste entièrement locale. La clé est lue depuis la variable d’environnement `VT_API_KEY` et n’est jamais incluse dans le rapport. Les nouveaux rapports sous `reports/` sont ignorés par Git par défaut pour éviter de publier par inadvertance des données d’analyse.

Références officielles :
- https://docs.virustotal.com/reference/domain-info
- https://docs.virustotal.com/reference/file-info
- https://docs.virustotal.com/reference/public-vs-premium-api
