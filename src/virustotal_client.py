"""Consultations ponctuelles de réputation VirusTotal, sans soumission de contenu."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

API_BASE = "https://www.virustotal.com/api/v3"
MAX_LOOKUPS = 4
RESERVED_SUFFIXES = (".invalid", ".example", ".test", ".localhost", ".local", ".internal", ".onion")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
SHA256_RE = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)


def _defang_domain(domain: str) -> str:
    return domain.replace(".", "[.]")


def _candidate_indicators(report: dict[str, Any]) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str) -> None:
        key = (kind, value.lower())
        if key not in seen:
            seen.add(key)
            candidates.append((kind, value.lower()))

    for attachment in report.get("attachments", []):
        value = attachment.get("sha256")
        if value and SHA256_RE.fullmatch(value):
            add("file_hash_sha256", value)

    domains: list[str] = []
    for link in report.get("links", []):
        value = link.get("domain")
        if value:
            domains.append(value.replace("[.]", "."))
    for indicator in report.get("indicators_to_review", []):
        domains.extend(
            value for value in (indicator.get("from_domain"), indicator.get("reply_to_domain")) if value
        )

    for domain in domains:
        domain = domain.strip().rstrip(".").lower()
        if DOMAIN_RE.fullmatch(domain) and not domain.endswith(RESERVED_SUFFIXES):
            add("domain", domain)
    return candidates


def _fetch_report(kind: str, indicator: str, api_key: str) -> dict[str, Any]:
    endpoint = "files" if kind == "file_hash_sha256" else "domains"
    target = urllib.parse.quote(indicator, safe="")
    request = urllib.request.Request(
        f"{API_BASE}/{endpoint}/{target}",
        headers={"x-apikey": api_key, "Accept": "application/json", "User-Agent": "soc1-phishing-email-analyzer/0.1"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            document = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        status = "not_found" if error.code == 404 else "rate_limited" if error.code == 429 else "error"
        return {"status": status, "http_status": error.code}
    except (urllib.error.URLError, TimeoutError, UnicodeError, json.JSONDecodeError):
        return {"status": "network_or_response_error"}

    attributes = document.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats")
    return {
        "status": "found",
        "last_analysis_stats": stats if isinstance(stats, dict) else None,
        "reputation": attributes.get("reputation"),
        "last_analysis_date": attributes.get("last_analysis_date"),
    }


def lookup_indicators(report: dict[str, Any], api_key: str) -> dict[str, Any]:
    """Interroge au plus quatre domaines ou empreintes ; n'envoie aucun fichier/URL."""
    candidates = _candidate_indicators(report)
    selected = candidates[:MAX_LOOKUPS]
    results: list[dict[str, Any]] = []
    for kind, value in selected:
        result = _fetch_report(kind, value, api_key)
        result.update({
            "type": kind,
            "indicator": _defang_domain(value) if kind == "domain" else value,
        })
        results.append(result)

    return {
        "service": "VirusTotal API v3",
        "lookups_performed": len(selected),
        "lookup_limit": MAX_LOOKUPS,
        "not_queried_count": max(0, len(candidates) - len(selected)),
        "notice": "La consultation transmet les domaines ou empreintes à VirusTotal, où les IoC interrogés peuvent être partagés avec sa communauté. Aucun .eml, contenu de pièce jointe ou URL complète n'est envoyé.",
        "results": results,
    }
