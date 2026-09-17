"""
scheduler.py
Exécute des scans à intervalle régulier, les stocke en historique,
et envoie un email d'alerte si des changements sont détectés
(nouveau port ouvert, nouvel hôte, service modifié...).

Usage typique : lancer ce script en arrière-plan (tmux/screen/systemd/cron)
sur une machine qui a accès en permanence au réseau à surveiller.
"""

import smtplib
import time
from dataclasses import dataclass
from email.mime.text import MIMEText
from typing import Optional

from .scanner import run_scan, ScanError
from .history import save_scan, latest_scans_for_target, compare_scans, DiffEntry


@dataclass
class EmailConfig:
    smtp_host: str
    smtp_port: int
    username: str
    password: str
    from_addr: str
    to_addr: str
    use_tls: bool = True


def send_alert_email(config: EmailConfig, target: str, diffs: list[DiffEntry]) -> None:
    lines = [f"Changements détectés sur {target} :", ""]
    for d in diffs:
        lines.append(f"- [{d.kind}] {d.host_ip} : {d.detail}")

    msg = MIMEText("\n".join(lines), _charset="utf-8")
    msg["Subject"] = f"[umbralyn] {len(diffs)} changement(s) détecté(s) sur {target}"
    msg["From"] = config.from_addr
    msg["To"] = config.to_addr

    with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=15) as server:
        if config.use_tls:
            server.starttls()
        server.login(config.username, config.password)
        server.send_message(msg)


def run_once(target: str, fast: bool = True, service_detection: bool = True,
             email_config: Optional[EmailConfig] = None) -> list[DiffEntry]:
    """Lance un scan, le sauvegarde, compare au précédent, alerte si besoin."""
    scan = run_scan(target, fast=fast, service_detection=service_detection)
    save_scan(scan)

    previous_scans = latest_scans_for_target(target, limit=2)
    if len(previous_scans) < 2:
        return []  # premier scan, rien à comparer

    new_scan, old_scan = previous_scans[0], previous_scans[1]
    diffs = compare_scans(old_scan, new_scan)

    if diffs and email_config:
        try:
            send_alert_email(email_config, target, diffs)
        except (smtplib.SMTPException, OSError) as e:
            print(f"[!] Échec de l'envoi de l'alerte email : {e}")

    return diffs


def run_loop(target: str, interval_seconds: int, fast: bool = True,
             service_detection: bool = True, email_config: Optional[EmailConfig] = None) -> None:
    """Boucle infinie : scanne `target` toutes les `interval_seconds` secondes."""
    print(f"[*] Surveillance planifiée de {target} toutes les {interval_seconds}s. Ctrl+C pour arrêter.")
    while True:
        try:
            diffs = run_once(target, fast, service_detection, email_config)
            if diffs:
                print(f"[!] {len(diffs)} changement(s) détecté(s) sur {target}")
                for d in diffs:
                    print(f"    - {d.host_ip} : {d.detail}")
            else:
                print(f"[*] {target} : aucun changement.")
        except ScanError as e:
            print(f"[!] Erreur de scan : {e}")
        time.sleep(interval_seconds)
