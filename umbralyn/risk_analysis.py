"""
risk_analysis.py
Analyse heuristique des résultats de scan : signale les services
historiquement associés à des risques connus (protocoles non chiffrés,
services d'administration exposés, versions obsolètes...).

Ceci ne remplace pas un vrai scanner de vulnérabilités (Nessus, OpenVAS...) :
c'est une première passe de tri, pédagogique et pratique pour un rapport rapide.
"""

from dataclasses import dataclass
from typing import List
from .scanner import ScanResult, Host, Port

# Ports/service connus pour poser question s'ils sont exposés (liste non exhaustive)
RISKY_PORTS = {
    21: ("FTP", "Souvent non chiffré ; vérifier si l'accès anonyme est autorisé."),
    23: ("Telnet", "Protocole non chiffré, à proscrire au profit de SSH."),
    25: ("SMTP", "Vérifier l'absence de relais ouvert (open relay)."),
    69: ("TFTP", "Aucune authentification, à restreindre au réseau d'administration."),
    110: ("POP3", "Non chiffré par défaut ; préférer POP3S."),
    135: ("MSRPC", "Souvent ciblé pour l'énumération Windows ; à filtrer côté WAN."),
    139: ("NetBIOS", "À ne jamais exposer sur Internet."),
    143: ("IMAP", "Non chiffré par défaut ; préférer IMAPS."),
    445: ("SMB", "Cible fréquente de ransomwares (ex : EternalBlue) ; vérifier le patch niveau et le filtrage."),
    1433: ("MSSQL", "Ne devrait pas être exposé hors réseau applicatif."),
    3306: ("MySQL", "Ne devrait pas être exposé hors réseau applicatif."),
    3389: ("RDP", "Cible n°1 des attaques par force brute ; imposer VPN + MFA."),
    5432: ("PostgreSQL", "Ne devrait pas être exposé hors réseau applicatif."),
    5900: ("VNC", "Souvent mal sécurisé (mots de passe faibles/absents)."),
    6379: ("Redis", "Historiquement déployé sans authentification par défaut."),
    9200: ("Elasticsearch", "De nombreuses instances exposées sans authentification."),
    27017: ("MongoDB", "Historiquement exposé sans authentification par défaut."),
}


@dataclass
class Finding:
    host_ip: str
    port: int
    service_label: str
    detail: str
    severity: str  # "high", "medium", "info"


def _severity_for(port_number: int) -> str:
    high = {23, 445, 3389, 6379, 9200, 27017, 135, 139}
    return "high" if port_number in high else "medium"


def analyze(scan_result: ScanResult) -> List[Finding]:
    findings: List[Finding] = []
    for host in scan_result.hosts_up:
        for port in host.open_ports:
            if port.number in RISKY_PORTS:
                label, detail = RISKY_PORTS[port.number]
                if port.banner != "inconnu":
                    detail = f"{detail} Bannière détectée : {port.banner}."
                findings.append(
                    Finding(
                        host_ip=host.ip,
                        port=port.number,
                        service_label=label,
                        detail=detail,
                        severity=_severity_for(port.number),
                    )
                )

            # Résultats des scripts NSE --script vuln (si activé lors du scan)
            for script_output in port.script_findings:
                if "VULNERABLE" in script_output.upper():
                    script_id = script_output.split(":", 1)[0]
                    findings.append(
                        Finding(
                            host_ip=host.ip,
                            port=port.number,
                            service_label=port.service or script_id,
                            detail=f"Script NSE '{script_id}' rapporte une vulnérabilité confirmée sur ce port.",
                            severity="high",
                        )
                    )

    # Tri : sévérité haute d'abord, puis par IP
    order = {"high": 0, "medium": 1, "info": 2}
    findings.sort(key=lambda f: (order[f.severity], f.host_ip, f.port))
    return findings


def summarize(scan_result: ScanResult, findings: List[Finding]) -> dict:
    return {
        "hosts_scanned": len(scan_result.hosts),
        "hosts_up": len(scan_result.hosts_up),
        "total_open_ports": sum(len(h.open_ports) for h in scan_result.hosts_up),
        "findings_high": sum(1 for f in findings if f.severity == "high"),
        "findings_medium": sum(1 for f in findings if f.severity == "medium"),
    }
