"""
cve_lookup.py
Associe les services/versions détectés par Nmap à des CVE connues.

Deux sources, dans cet ordre :
1. Cache local (evite de re-taper l'API à chaque scan, respecte le rate-limit NVD)
2. API NVD (https://nvd.nist.gov/developers/vulnerabilities) si accessible

Si l'API est injoignable (pas de réseau, rate-limit, pare-feu d'entreprise...),
l'outil bascule sur une petite base locale de CVE notoires pour continuer à
fonctionner en mode dégradé plutôt que de planter.
"""

import json
import os
import time
from pathlib import Path
from typing import Dict, List, Optional

import requests

from .scanner import ScanResult

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_PATH = Path.home() / ".umbralyn_cve_cache.json"
CACHE_TTL_SECONDS = 7 * 24 * 3600  # 1 semaine
REQUEST_DELAY_SECONDS = 6  # NVD limite à ~10 req/min sans clé API

# Base de repli hors-ligne : quelques CVE notoires, pour démo/tests sans réseau
# ou quand l'API NVD est indisponible. Clé = (produit en minuscule, préfixe de version).
OFFLINE_FALLBACK: Dict[str, List[dict]] = {
    "openssh 7.": [
        {"id": "CVE-2018-15473", "severity": "medium",
         "summary": "Énumération de noms d'utilisateurs via une faille de timing dans l'authentification."}
    ],
    "samba 4.5": [
        {"id": "CVE-2017-7494", "severity": "critical",
         "summary": "Exécution de code arbitraire via upload d'une bibliothèque partagée malveillante (SambaCry)."}
    ],
    "vsftpd 2.3": [
        {"id": "CVE-2011-2523", "severity": "critical",
         "summary": "Backdoor connue dans vsftpd 2.3.4, permet un accès shell à distance."}
    ],
    "apache 2.4.49": [
        {"id": "CVE-2021-41773", "severity": "critical",
         "summary": "Traversée de répertoire permettant lecture de fichiers arbitraires, exploitée massivement."}
    ],
    "microsoft-ds": [  # SMB générique, souvent lié à EternalBlue si non patché
        {"id": "CVE-2017-0144", "severity": "critical",
         "summary": "Exécution de code à distance via SMBv1 (EternalBlue, utilisé par WannaCry)."}
    ],
}


def _load_cache() -> dict:
    if CACHE_PATH.exists():
        try:
            return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_cache(cache: dict) -> None:
    try:
        CACHE_PATH.write_text(json.dumps(cache), encoding="utf-8")
    except OSError:
        pass  # cache best-effort, ne doit jamais faire planter le scan


def _query_nvd(keyword: str) -> Optional[List[dict]]:
    try:
        headers = {}
        api_key = os.environ.get("UMBRALYN_NVD_API_KEY")
        if api_key:
            headers["apiKey"] = api_key
        resp = requests.get(
            NVD_API_URL,
            params={"keywordSearch": keyword, "resultsPerPage": 5},
            headers=headers,
            timeout=10,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
    except (requests.RequestException, ValueError):
        return None

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        summary = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        severity = "medium"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                severity = metrics[key][0]["cvssData"].get("baseSeverity", "medium").lower()
                break
        results.append({"id": cve_id, "severity": severity, "summary": summary[:200]})
    return results


def _offline_lookup(product: str, version: str) -> List[dict]:
    key_candidates = [f"{product.lower()} {version}", product.lower()]
    for key, cves in OFFLINE_FALLBACK.items():
        for candidate in key_candidates:
            if candidate.startswith(key) or key.startswith(candidate):
                return cves
    return []


def lookup_cves_for_scan(scan: ScanResult, use_api: bool = True) -> Dict[str, List[dict]]:
    """
    Retourne un dict {"ip:port": [ {id, severity, summary}, ... ]}
    pour tous les ports ouverts avec un produit/version identifié.
    """
    cache = _load_cache()
    results: Dict[str, List[dict]] = {}
    api_calls_made = 0

    for host in scan.hosts_up:
        for port in host.open_ports:
            if not port.product:
                continue
            key = f"{port.product.lower()} {port.version}".strip()
            cache_key = f"cve::{key}"
            entry_key = f"{host.ip}:{port.number}"

            if cache_key in cache and (time.time() - cache[cache_key]["ts"]) < CACHE_TTL_SECONDS:
                cves = cache[cache_key]["data"]
            elif use_api:
                cves = _query_nvd(key)
                if cves is None:
                    cves = _offline_lookup(port.product, port.version)
                else:
                    cache[cache_key] = {"ts": time.time(), "data": cves}
                    api_calls_made += 1
                if not api_key:
                    time.sleep(REQUEST_DELAY_SECONDS)  # respecter le rate-limit sans clé
            else:
                cves = _offline_lookup(port.product, port.version)

            if cves:
                results[entry_key] = cves

    if api_calls_made:
        _save_cache(cache)

    return results
