"""
scanner.py
Lance un scan Nmap sur une cible (hôte ou plage) et parse le résultat XML
en une structure de données Python exploitable par le reste du programme.
"""

import subprocess
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class Port:
    number: int
    protocol: str
    state: str
    service: str
    product: str
    version: str
    script_findings: List[str] = field(default_factory=list)  # sorties des scripts NSE --script vuln

    @property
    def banner(self) -> str:
        parts = [p for p in (self.product, self.version) if p]
        return " ".join(parts) if parts else "inconnu"


@dataclass
class Host:
    ip: str
    hostname: str
    status: str
    os_guess: str
    ports: List[Port] = field(default_factory=list)

    @property
    def open_ports(self) -> List[Port]:
        return [p for p in self.ports if p.state == "open"]


@dataclass
class ScanResult:
    target: str
    started_at: datetime
    duration_seconds: float
    hosts: List[Host] = field(default_factory=list)
    raw_nmap_args: str = ""

    @property
    def hosts_up(self) -> List[Host]:
        return [h for h in self.hosts if h.status == "up"]


class ScanError(RuntimeError):
    pass


def check_nmap_available() -> None:
    if shutil.which("nmap") is None:
        raise ScanError(
            "nmap est introuvable sur ce système. Installe-le avec "
            "'sudo apt install nmap' (Linux) ou 'brew install nmap' (macOS)."
        )


def run_scan(target: str, fast: bool = True, service_detection: bool = True,
             vuln_scripts: bool = False, os_detection: bool = False, timeout: int = 600) -> ScanResult:
    """
    Lance nmap sur `target` (ex: '192.168.1.0/24', '10.0.0.5', 'scanme.example.com')
    et retourne un ScanResult structuré.

    fast=True              -> -F (top 100 ports courants), plus rapide.
    service_detection=True -> -sV (détection version des services).
    vuln_scripts=True      -> --script vuln (scripts NSE de détection de vulnérabilités,
                               nettement plus lent, à réserver aux scans ponctuels/lab).

    ATTENTION : ne scanner que des cibles pour lesquelles tu as une
    autorisation explicite (ton propre lab, ou accord écrit du client/employeur).
    """
    check_nmap_available()

    args = ["nmap", "-oX", "-"]  # sortie XML sur stdout
    if fast:
        args.append("-F")
    if service_detection:
        args.append("-sV")
    if os_detection:
        args.append("-O")
    if vuln_scripts:
        args.extend(["--script", "vuln"])
    args.append(target)

    started_at = datetime.now()
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError:
        raise ScanError("nmap n'a pas pu être lancé.")
    except subprocess.TimeoutExpired:
        raise ScanError(f"Le scan a dépassé le délai maximal ({timeout}s).")

    if proc.returncode != 0 and not proc.stdout:
        raise ScanError(f"Échec du scan nmap : {proc.stderr.strip()}")

    duration = (datetime.now() - started_at).total_seconds()
    result = _parse_nmap_xml(proc.stdout, target, started_at, duration)
    result.raw_nmap_args = " ".join(args)
    return result


def _parse_nmap_xml(xml_data: str, target: str, started_at: datetime, duration: float) -> ScanResult:
    root = ET.fromstring(xml_data)
    result = ScanResult(target=target, started_at=started_at, duration_seconds=duration)

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        status = status_el.get("state") if status_el is not None else "unknown"

        addr_el = host_el.find("address")
        ip = addr_el.get("addr") if addr_el is not None else "?"

        hostname = ""
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        os_guess = ""
        os_el = host_el.find("os")
        if os_el is not None:
            match = os_el.find("osmatch")
            if match is not None:
                os_guess = match.get("name", "")

        host = Host(ip=ip, hostname=hostname, status=status, os_guess=os_guess)

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                state = state_el.get("state") if state_el is not None else "unknown"

                service_el = port_el.find("service")
                service = service_el.get("name", "") if service_el is not None else ""
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""

                script_findings = [
                    f"{script_el.get('id', '?')}: {script_el.get('output', '').strip()}"
                    for script_el in port_el.findall("script")
                    if script_el.get("output", "").strip()
                ]

                host.ports.append(
                    Port(
                        number=int(port_el.get("portid")),
                        protocol=port_el.get("protocol", "tcp"),
                        state=state,
                        service=service,
                        product=product,
                        version=version,
                        script_findings=script_findings,
                    )
                )

        result.hosts.append(host)

    return result
