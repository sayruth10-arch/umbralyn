"""
scoring.py
Calcule un score de risque (0 = sûr, 100 = critique) par hôte et
un score global pour le scan, à partir des findings détectés.

Le calcul est volontairement simple et explicable (pas de boîte noire) :
chaque finding pèse selon sa sévérité, avec un plafond à 100.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from .risk_analysis import Finding
from .scanner import ScanResult

SEVERITY_WEIGHTS = {"high": 30, "medium": 15, "info": 5}
CVE_SEVERITY_WEIGHTS = {"critical": 35, "high": 25, "medium": 12, "low": 4}


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


def score_host(host_ip: str, findings: List[Finding], cves: Dict[str, list] | None = None) -> HostScore:
    total = 0
    breakdown = []

    host_findings = [f for f in findings if f.host_ip == host_ip]
    for f in host_findings:
        weight = SEVERITY_WEIGHTS.get(f.severity, 5)
        total += weight
        breakdown.append(f"Port {f.port} ({f.service_label}) — {f.severity} : +{weight}")

    if cves:
        for port_key, cve_list in cves.items():
            if not port_key.startswith(f"{host_ip}:"):
                continue
            for cve in cve_list:
                weight = CVE_SEVERITY_WEIGHTS.get(cve.get("severity", "medium").lower(), 8)
                total += weight
                breakdown.append(f"{cve['id']} ({cve.get('severity', '?')}) sur {port_key} : +{weight}")

    score = min(total, 100)
    return HostScore(host_ip=host_ip, score=score, grade=_grade_for(score), breakdown=breakdown)


def score_all_hosts(scan: ScanResult, findings: List[Finding], cves: Dict[str, list] | None = None) -> List[HostScore]:
    scores = [score_host(h.ip, findings, cves) for h in scan.hosts_up]
    scores.sort(key=lambda s: s.score, reverse=True)
    return scores


def global_score(host_scores: List[HostScore]) -> int:
    if not host_scores:
        return 0
    # Le score global privilégie le pire hôte tout en tenant compte des autres
    worst = max(s.score for s in host_scores)
    avg = sum(s.score for s in host_scores) / len(host_scores)
    return round(worst * 0.7 + avg * 0.3)
