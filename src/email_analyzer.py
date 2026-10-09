"""Analyse locale et progressive d'en-têtes, de texte et de liens d'e-mails .eml."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from virustotal_client import lookup_indicators


HEADER_FIELDS = {
    "from": "From",
    "to": "To",
    "subject": "Subject",
    "date": "Date",
    "reply_to": "Reply-To",
}

OBSERVED_HEADERS = {
    "received": "Received",
    "authentication_results": "Authentication-Results",
    "arc_authentication_results": "ARC-Authentication-Results",
}

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
DOMAIN_LABEL_PATTERN = re.compile(
    r"^(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:/.*)?$",
    re.IGNORECASE,
)

MAX_HASH_SIZE = 25 * 1024 * 1024
REVIEW_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".js", ".vbs", ".hta", ".lnk",
    ".iso", ".img", ".html", ".htm", ".docm", ".xlsm", ".pptm",
    ".zip", ".rar", ".7z",
}

CONTENT_PATTERNS = {
    "urgence": re.compile(
        r"\b(?:urgent(?:e|ment)?|immédiatement|immédiat(?:e)?|aujourd'hui|"
        r"dans les prochaines? heures?|immediately|today)\b",
        re.IGNORECASE,
    ),
    "menace_ou_delai": re.compile(
        r"\b(?:suspendu(?:e)?|bloqué(?:e)?|désactivé(?:e)?|expire(?:r|ra|z)?|"
        r"expiré(?:e)?|suspended|blocked|disabled|expires?)\b",
        re.IGNORECASE,
    ),
    "demande_d_information": re.compile(
        r"\b(?:confirmez|vérifiez|mettez à jour|verify|confirm|update|enter)"
        r"\b.{0,70}\b(?:vos informations|informations|identifiants|mot de passe|"
        r"password|credentials|compte|account)\b",
        re.IGNORECASE,
    ),
}


class _VisibleTextExtractor(HTMLParser):
    """Récupère les nœuds texte et les destinations des liens sans rendre le HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[dict[str, str]] = []
        self._hidden_depth = 0
        self._anchor_href: str | None = None
        self._anchor_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in {"script", "style", "head", "title"}:
            self._hidden_depth += 1
        elif tag == "a" and not self._hidden_depth:
            self._anchor_href = dict(attrs).get("href")
            self._anchor_text = []

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in {"script", "style", "head", "title"} and self._hidden_depth:
            self._hidden_depth -= 1
        elif tag == "a" and self._anchor_href is not None:
            self.links.append(
                {"url": self._anchor_href, "text": " ".join(self._anchor_text)}
            )
            self._anchor_href = None
            self._anchor_text = []

    def handle_data(self, data: str) -> None:
        if not self._hidden_depth and data.strip():
            text = data.strip()
            self.parts.append(text)
            if self._anchor_href is not None:
                self._anchor_text.append(text)


def _domain_from_address(header_value: str | None) -> str | None:
    """Retourne le domaine d'une adresse analysée, sans conclure à son authenticité."""
    if not header_value:
        return None
    _display_name, address = parseaddr(header_value)
    if "@" not in address:
        return None
    return address.rsplit("@", 1)[1].lower()


def _domain_from_url_label(label: str) -> str | None:
    candidate = label.strip().strip("<>()[]{}.,;:!?\"'")
    if not DOMAIN_LABEL_PATTERN.fullmatch(candidate):
        return None
    if not re.match(r"^https?://", candidate, re.IGNORECASE):
        candidate = "http://" + candidate
    try:
        return urlsplit(candidate).hostname
    except ValueError:
        return None


def _defanged_host(host: str) -> str:
    return host.replace(".", "[.]" )


def _safe_url_display(url: str) -> tuple[str, str | None]:
    """Produit une URL non cliquable; masque identifiants, paramètres et fragment."""
    candidate = url.strip().rstrip(".,;:!?)>")
    try:
        parsed = urlsplit(candidate)
        host = parsed.hostname
        if parsed.scheme.lower() not in {"http", "https"} or not host:
            return "[URL non affichée : format non reconnu]", None
        scheme = "hxxps" if parsed.scheme.lower() == "https" else "hxxp"
        domain = _defanged_host(host.lower())
        try:
            port = f":{parsed.port}" if parsed.port else ""
        except ValueError:
            port = ""
        destination = f"{scheme}://{domain}{port}{parsed.path}"
        if parsed.query:
            destination += "?[paramètres masqués]"
        if parsed.fragment:
            destination += "#[fragment masqué]"
        return destination, domain
    except ValueError:
        return "[URL non affichée : format non reconnu]", None


def _find_links(plain_parts: list[str], html_links: list[dict[str, str]], html_parts: list[str]) -> list[dict[str, Any]]:
    candidates: list[dict[str, str]] = []
    for part in plain_parts:
        candidates.extend({"url": match.group(0), "text": "", "source": "texte brut"} for match in URL_PATTERN.finditer(part))
    for link in html_links:
        if link["url"].strip():
            candidates.append({"url": link["url"], "text": link["text"], "source": "lien HTML"})
    for part in html_parts:
        candidates.extend({"url": match.group(0), "text": "", "source": "texte visible HTML"} for match in URL_PATTERN.finditer(part))

    links: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in candidates:
        key = (item["url"].strip(), item["text"].strip())
        if key in seen:
            continue
        seen.add(key)
        destination, domain = _safe_url_display(item["url"])
        label_domain = _domain_from_url_label(item["text"]) if item["text"] else None
        differs = (
            label_domain.lower() != domain.lower()
            if label_domain is not None and domain is not None
            else None
        )
        links.append(
            {
                "source": item["source"],
                "visible_text": item["text"] or None,
                "destination": destination,
                "domain": domain,
                "displayed_url_domain_differs": differs,
            }
        )
    return links


def _extract_text(message: Any) -> tuple[list[str], list[str], list[dict[str, str]], list[str]]:
    """Décode les seules parties MIME texte hors pièces jointes."""
    plain_parts: list[str] = []
    html_parts: list[str] = []
    html_links: list[dict[str, str]] = []
    warnings: list[str] = []
    part_number = 0

    def visit(part: Any) -> None:
        nonlocal part_number
        part_number += 1
        current_number = part_number
        if part.get_content_disposition() == "attachment":
            return
        if part.is_multipart():
            for child in part.iter_parts():
                visit(child)
            return

        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"}:
            return
        try:
            content = part.get_content()
        except (LookupError, UnicodeError, TypeError):
            warnings.append(
                f"Partie MIME {current_number} ({content_type}) illisible avec son encodage déclaré."
            )
            return
        if not isinstance(content, str):
            return
        if content_type == "text/html":
            extractor = _VisibleTextExtractor()
            extractor.feed(content)
            extractor.close()
            visible_text = " ".join(extractor.parts)
            if visible_text:
                html_parts.append(visible_text)
            html_links.extend(extractor.links)
        elif content.strip():
            plain_parts.append(content.strip())

    visit(message)
    return plain_parts, html_parts, html_links, warnings


def _find_content_evidence(text: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for category, pattern in CONTENT_PATTERNS.items():
        for match in pattern.finditer(text):
            findings.append({"category": category, "evidence": match.group(0)})
            if len(findings) >= 20:
                return findings
    return findings



def _safe_filename(value: str) -> str:
    """Évite les caractères de contrôle d'un nom de pièce jointe dans le terminal."""
    return "".join(char for char in value if char.isprintable())[:255]


def _extract_attachment_metadata(message: Any) -> list[dict[str, Any]]:
    """Inventorie les pièces jointes sans les écrire sur disque ni les exécuter."""
    attachments: list[dict[str, Any]] = []

    def visit(part: Any) -> None:
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if disposition == "attachment" or filename:
            safe_name = _safe_filename(filename or "(nom absent)")
            payload = part.get_payload(decode=True)
            payload_available = isinstance(payload, bytes)
            size = len(payload) if payload_available else None
            extension = Path(filename or "").suffix.lower()
            can_hash = payload_available and size is not None and size <= MAX_HASH_SIZE
            item: dict[str, Any] = {
                "filename": safe_name,
                "content_type_declared": part.get_content_type(),
                "disposition": disposition or "non précisée",
                "size_bytes": size,
                "sha256": hashlib.sha256(payload).hexdigest() if can_hash else None,
                "sha256_note": None if can_hash else (
                    "Empreinte indisponible : contenu décodé absent."
                    if not payload_available else "Empreinte omise : taille supérieure à 25 Mio."
                ),
                "extension_to_review": extension in REVIEW_EXTENSIONS,
                "note": "Métadonnées uniquement : le fichier n'est ni extrait sur disque ni ouvert.",
            }
            attachments.append(item)
            return
        if part.is_multipart():
            for child in part.iter_parts():
                visit(child)

    visit(message)
    return attachments


def read_general_information(path: Path) -> dict[str, Any]:
    """Lit les en-têtes, le texte et les liens sans rendre le HTML ni extraire les pièces jointes."""
    raw_message = path.read_bytes()
    message = BytesParser(policy=policy.default).parsebytes(raw_message)

    headers: dict[str, str | None] = {}
    for field, header_name in HEADER_FIELDS.items():
        value = message.get(header_name)
        headers[field] = str(value).strip() if value is not None else None

    observed: dict[str, list[str]] = {}
    for field, header_name in OBSERVED_HEADERS.items():
        observed[field] = [str(value).strip() for value in message.get_all(header_name, [])]

    from_domain = _domain_from_address(headers["from"])
    reply_to_domain = _domain_from_address(headers["reply_to"])
    reply_to_domain_differs = (
        None
        if from_domain is None or reply_to_domain is None
        else from_domain != reply_to_domain
    )

    plain_parts, html_parts, html_links, body_warnings = _extract_text(message)
    combined_text = "\n".join([*plain_parts, *html_parts])
    links = _find_links(plain_parts, html_links, html_parts)
    attachments = _extract_attachment_metadata(message)

    return {
        "source_file": path.name,
        "headers": headers,
        "observed_routing_and_authentication": observed,
        "indicators_to_review": [
            {
                "id": "reply_to_domain_differs",
                "observed": reply_to_domain_differs,
                "from_domain": from_domain,
                "reply_to_domain": reply_to_domain,
                "meaning": "Une différence de domaine entre From et Reply-To mérite un examen, mais ne prouve pas une fraude.",
            }
        ],
        "body": {
            "plain_text_parts": len(plain_parts),
            "html_parts": len(html_parts),
            "content_warnings": body_warnings,
            "language_indicators": _find_content_evidence(combined_text),
        },
        "links": links,
        "attachments": attachments,
        "scope": "En-têtes, texte, destinations URL désactivées et métadonnées de pièces jointes uniquement; aucun lien n'est visité, aucune pièce jointe n'est ouverte ou extraite, et SPF/DKIM/DMARC ne sont pas revérifiés.",
    }


def render_text(report: dict[str, Any]) -> str:
    """Formate les valeurs observées et sépare faits et interprétations."""
    labels = {
        "from": "Expéditeur (From)",
        "to": "Destinataire (To)",
        "subject": "Objet (Subject)",
        "date": "Date",
        "reply_to": "Réponse à (Reply-To)",
    }
    lines = [f"Fichier : {report['source_file']}", "", "Informations générales lues :"]
    for field, label in labels.items():
        value = report["headers"][field]
        lines.append(f"- {label} : {value if value is not None else 'absent'}")

    observed = report["observed_routing_and_authentication"]
    lines.extend(["", f"Lignes Received : {len(observed['received'])}"])
    for value in observed["received"]:
        lines.append(f"- {value}")

    for field, label in (
        ("authentication_results", "Authentication-Results"),
        ("arc_authentication_results", "ARC-Authentication-Results"),
    ):
        values = observed[field]
        lines.extend(["", f"{label} observé :"])
        lines.extend((f"- {value}" for value in values) if values else ["- absent"])

    for indicator in report["indicators_to_review"]:
        if indicator["observed"] is True:
            status = "à examiner"
        elif indicator["observed"] is False:
            status = "aucune différence de domaine observée"
        else:
            status = "non évalué : domaine absent ou indéterminé"
        lines.extend(["", f"Indice à examiner — {indicator['id']} : {status}"])
        lines.append(f"  {indicator['meaning']}")

    body = report["body"]
    lines.extend(
        [
            "",
            "Corps du message : "
            f"{body['plain_text_parts']} partie(s) texte brut, "
            f"{body['html_parts']} partie(s) HTML (texte visible extrait sans rendu).",
        ]
    )
    if body["language_indicators"]:
        lines.append("Formulations à examiner (mots observés, pas une conclusion) :")
        for finding in body["language_indicators"]:
            lines.append(f"- {finding['category']} : « {finding['evidence']} »")
    else:
        lines.append("Aucune formulation surveillée détectée par les règles simples actuelles.")
    lines.extend(f"Avertissement de lecture : {warning}" for warning in body["content_warnings"])

    lines.extend(["", f"Liens trouvés : {len(report['links'])}"])
    for number, link in enumerate(report["links"], start=1):
        lines.append(f"- Lien {number} ({link['source']}) : {link['destination']}")
        lines.append(f"  Domaine : {link['domain'] or 'non déterminé'}")
        if link["visible_text"]:
            lines.append(f"  Texte affiché : {link['visible_text']}")
        if link["displayed_url_domain_differs"] is not None:
            status = "différent" if link["displayed_url_domain_differs"] else "identique"
            lines.append(f"  Domaine du texte URL / destination : {status}")

    lines.extend(["", f"Pièces jointes trouvées : {len(report['attachments'])}"])
    for number, attachment in enumerate(report["attachments"], start=1):
        size = attachment["size_bytes"]
        size_display = f"{size} octet(s)" if size is not None else "indisponible"
        lines.append(f"- Pièce {number} : {attachment['filename']}")
        lines.append(f"  Type déclaré : {attachment['content_type_declared']} ; taille : {size_display}")
        lines.append(f"  SHA-256 : {attachment['sha256'] or attachment['sha256_note']}")
        if attachment["extension_to_review"]:
            lines.append("  Extension à examiner : cela ne suffit pas à conclure que le fichier est malveillant.")
        lines.append(f"  {attachment['note']}")

    vt = report.get("virustotal")
    if vt:
        lines.extend(["", "VirusTotal — réputation externe (pas un verdict)", vt["notice"]])
        if not vt["results"]:
            lines.append("Aucun indicateur public admissible à la consultation (les domaines de démonstration sont ignorés).")
        for item in vt["results"]:
            lines.append(f"- {item['type']} {item['indicator']} : {item['status']}")
            if item.get("last_analysis_stats"):
                stats = item["last_analysis_stats"]
                lines.append("  Résultats antivirus : " + ", ".join(f"{key}={value}" for key, value in sorted(stats.items())))
            if item.get("reputation") is not None:
                lines.append(f"  Réputation communautaire : {item['reputation']}")
            if item.get("http_status"):
                lines.append(f"  Code HTTP : {item['http_status']}")
        if vt["not_queried_count"]:
            lines.append(f"Indicateurs non interrogés (limite par exécution) : {vt['not_queried_count']}")

    lines.extend(["", f"Limite : {report['scope']}"])
    return "\n".join(lines)


def _markdown_code(value: Any) -> str:
    """Place une valeur non fiable dans un code span Markdown inerte."""
    text = str(value).replace(chr(13), " ").replace(chr(10), " ")
    runs = re.findall(r"`+", text)
    fence = "`" * (max((len(run) for run in runs), default=0) + 1)
    padding = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{padding}{text}{padding}{fence}"


def render_markdown(report: dict[str, Any]) -> str:
    """Produit un rapport Markdown dont les données du message restent inertes."""
    labels = {
        "from": "Expéditeur (From)",
        "to": "Destinataire (To)",
        "subject": "Objet (Subject)",
        "date": "Date",
        "reply_to": "Réponse à (Reply-To)",
    }
    lines = ["# Rapport d'analyse e-mail", "", f"Fichier : {_markdown_code(report['source_file'])}", "", "## Informations générales"]
    for field, label in labels.items():
        value = report["headers"][field]
        lines.append(f"- **{label} :** {_markdown_code(value if value is not None else 'absent')}")

    observed = report["observed_routing_and_authentication"]
    lines.extend(["", "## Routage et authentification observés", "", f"Lignes `Received` : {len(observed['received'])}"])
    lines.extend(f"- {_markdown_code(value)}" for value in observed["received"])
    for field, label in (
        ("authentication_results", "Authentication-Results"),
        ("arc_authentication_results", "ARC-Authentication-Results"),
    ):
        values = observed[field]
        lines.extend(["", f"### {label}"])
        lines.extend((f"- {_markdown_code(value)}" for value in values) if values else ["- absent"])

    lines.extend(["", "## Indices à examiner"])
    for indicator in report["indicators_to_review"]:
        if indicator["observed"] is True:
            status = "à examiner"
        elif indicator["observed"] is False:
            status = "aucune différence de domaine observée"
        else:
            status = "non évalué : domaine absent ou indéterminé"
        lines.append(f"- **{_markdown_code(indicator['id'])} — {status}.** {indicator['meaning']}")

    body = report["body"]
    lines.extend(["", "## Corps du message", "", f"{body['plain_text_parts']} partie(s) texte brut ; {body['html_parts']} partie(s) HTML. Le HTML est extrait sans rendu."])
    if body["language_indicators"]:
        lines.extend(["", "Formulations relevées (indices, pas une conclusion) :"])
        lines.extend(f"- {_markdown_code(item['category'])} : {_markdown_code(item['evidence'])}" for item in body["language_indicators"])
    else:
        lines.extend(["", "Aucune formulation surveillée détectée par les règles simples actuelles."])
    lines.extend(f"- Avertissement de lecture : {_markdown_code(warning)}" for warning in body["content_warnings"])

    lines.extend(["", "## Liens", "", f"Liens trouvés : {len(report['links'])}"])
    for number, link in enumerate(report["links"], start=1):
        lines.append(f"- **Lien {number} ({link['source']}) :** {_markdown_code(link['destination'])}")
        lines.append(f"  - Domaine : {_markdown_code(link['domain'] or 'non déterminé')}")
        if link["visible_text"]:
            lines.append(f"  - Texte affiché : {_markdown_code(link['visible_text'])}")
        if link["displayed_url_domain_differs"] is not None:
            status = "différent" if link["displayed_url_domain_differs"] else "identique"
            lines.append(f"  - Domaine du texte URL / destination : {status}")

    lines.extend(["", "## Pièces jointes", "", f"Pièces jointes trouvées : {len(report['attachments'])}"])
    for number, attachment in enumerate(report["attachments"], start=1):
        size = attachment["size_bytes"]
        size_display = f"{size} octet(s)" if size is not None else "indisponible"
        lines.append(f"- **Pièce {number} :** {_markdown_code(attachment['filename'])}")
        lines.append(f"  - Type déclaré : {_markdown_code(attachment['content_type_declared'])} ; taille : {size_display}")
        lines.append(f"  - SHA-256 : {_markdown_code(attachment['sha256'] or attachment['sha256_note'])}")
        if attachment["extension_to_review"]:
            lines.append("  - Extension à examiner ; ce signal ne suffit pas à conclure que le fichier est malveillant.")
        lines.append(f"  - {attachment['note']}")

    vt = report.get("virustotal")
    if vt:
        lines.extend(["", "## Réputation VirusTotal", "", vt["notice"], ""])
        if not vt["results"]:
            lines.append("Aucun indicateur public admissible à la consultation (les domaines de démonstration sont ignorés).")
        for item in vt["results"]:
            lines.append(f"- **{item['type']} {_markdown_code(item['indicator'])} :** {item['status']}")
            if item.get("last_analysis_stats"):
                stats = item["last_analysis_stats"]
                lines.append("  - Détections observées : " + ", ".join(f"{key}={value}" for key, value in sorted(stats.items())))
            if item.get("reputation") is not None:
                lines.append(f"  - Réputation communautaire : {item['reputation']}")
            if item.get("http_status"):
                lines.append(f"  - Code HTTP : {item['http_status']}")
        if vt["not_queried_count"]:
            lines.append(f"Indicateurs non interrogés (limite par exécution) : {vt['not_queried_count']}")

    lines.extend(["", "## Limites", "", report["scope"]])
    return chr(10).join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Lit un fichier .eml local sans visiter ses liens ni ouvrir ses pièces jointes."
    )
    parser.add_argument("eml", type=Path, help="Chemin vers le fichier .eml à lire")
    format_group = parser.add_mutually_exclusive_group()
    format_group.add_argument("--json", action="store_true", help="Produit le rapport en JSON")
    format_group.add_argument("--markdown", action="store_true", help="Produit le rapport en Markdown")
    parser.add_argument("--virustotal", action="store_true", help="Consulte VirusTotal (envoie domaines/empreintes au service)")
    parser.add_argument("--output", type=Path, help="Enregistre le rapport dans un fichier")
    args = parser.parse_args(argv)

    if not args.eml.is_file():
        parser.error(f"fichier introuvable : {args.eml}")

    try:
        report = read_general_information(args.eml)
    except OSError as error:
        parser.error(f"impossible de lire le fichier : {error}")

    if args.virustotal:
        api_key = os.environ.get("VT_API_KEY")
        if not api_key:
            parser.error("variable VT_API_KEY absente ; configure ta clé localement, sans la partager dans le chat ni l'ajouter au dépôt")
        report["virustotal"] = lookup_indicators(report, api_key)

    if args.json:
        rendered = json.dumps(report, ensure_ascii=False, indent=2)
    elif args.markdown:
        rendered = render_markdown(report)
    else:
        rendered = render_text(report)
    if args.output:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered + "\n", encoding="utf-8")
        except OSError as error:
            parser.error(f"impossible d'enregistrer le rapport : {error}")
        print(f"Rapport enregistré : {args.output}")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
