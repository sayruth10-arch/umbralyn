"""
scoring.py
Calcule un score de risque (0 = aucun risque détecté, 100 = critique)
par hôte et un score global pour le scan, à partir des findings détectés
et des CVE candidates associées aux services.

Le calcul est volontairement simple et explicable :
- les findings issus de l'analyse heuristique apportent un score selon leur sévérité ;
- les CVE candidates apportent un score supplémentaire selon leur criticité ;
- le score final de chaque hôte est plafonné à 100.

Le score constitue un indicateur de tri et ne représente pas une mesure
absolue du niveau de sécurité d'un hôte.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from .risk_analysis import Finding
from .scanner import ScanResult


SEVERITY_WEIGHTS = {
    "high": 30,
    "medium": 15,
    "info": 5,
}

CVE_SEVERITY_WEIGHTS = {
    "critical": 35,
    "high": 25,
    "medium": 12,
    "low": 4,
}


@dataclass
class HostScore:
    host_ip: str
    score: int
    grade: str
    breakdown: List[str]


def _grade_for(score: int) -> str:
    if score >= 75:
        return "Critique"

    if score >= 45:
        return "Élevé"

    if score >= 20:
        return "Modéré"

    if score > 0:
        return "Faible"

    return "Aucun risque détecté"


def score_host(
    host_ip: str,
    findings: List[Finding],
    cves: Dict[str, list] | None = None,
) -> HostScore:
    """
    Calcule le score d'un hôte.

    Les findings et les CVE sont comptabilisés séparément afin de conserver
    une explication claire du score final.
    """

    total = 0
    breakdown: List[str] = []

    host_findings = [
        finding
        for finding in findings
        if finding.host_ip == host_ip
    ]

    for finding in host_findings:
        weight = SEVERITY_WEIGHTS.get(
            finding.severity.lower(),
            5,
        )

        total += weight

        breakdown.append(
            f"Port {finding.port} "
            f"({finding.service_label}) — "
            f"{finding.severity} : +{weight}"
        )

    if cves:
        for port_key, cve_list in cves.items():
            if not port_key.startswith(f"{host_ip}:"):
                continue

            for cve in cve_list:
                severity = str(
                    cve.get(
                        "severity",
                        "medium",
                    )
                ).lower()

                weight = CVE_SEVERITY_WEIGHTS.get(
                    severity,
                    8,
                )

                cve_id = cve.get(
                    "id",
                    "CVE inconnue",
                )

                total += weight

                breakdown.append(
                    f"{cve_id} "
                    f"({severity}) sur "
                    f"{port_key} : +{weight}"
                )

    score = min(
        total,
        100,
    )

    return HostScore(
        host_ip=host_ip,
        score=score,
        grade=_grade_for(score),
        breakdown=breakdown,
    )


def score_all_hosts(
    scan: ScanResult,
    findings: List[Finding],
    cves: Dict[str, list] | None = None,
) -> List[HostScore]:
    """
    Calcule le score de tous les hôtes actifs du scan.
    """

    scores = [
        score_host(
            host.ip,
            findings,
            cves,
        )
        for host in scan.hosts_up
    ]

    scores.sort(
        key=lambda score: score.score,
        reverse=True,
    )

    return scores


def global_score(
    host_scores: List[HostScore],
) -> int:
    """
    Calcule un score global du scan.

    Le score privilégie le pire hôte (70 %) tout en tenant
    compte du niveau moyen des hôtes actifs (30 %).
    """

    if not host_scores:
        return 0

    worst = max(
        score.score
        for score in host_scores
    )

    average = (
        sum(
            score.score
            for score in host_scores
        )
        / len(host_scores)
    )

    return round(
        worst * 0.7
        + average * 0.3
    )
