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
from pathlib import Path
from typing import Optional

from .scanner import run_scan, ScanError
from .history import (
    save_scan,
    latest_scans_for_target,
    compare_scans,
    DiffEntry,
)


DB_PATH = Path("data/umbralyn.db")


@dataclass
class EmailConfig:
    smtp_host: str
    smtp_port: int
    username: str
    password: str
    from_addr: str
    to_addr: str
    use_tls: bool = True


def send_alert_email(
    config: EmailConfig,
    target: str,
    diffs: list[DiffEntry],
) -> None:
    lines = [
        f"Changements détectés sur {target} :",
        "",
    ]

    for diff in diffs:
        lines.append(
            f"- [{diff.kind}] {diff.host_ip} : {diff.detail}"
        )

    msg = MIMEText(
        "\n".join(lines),
        _charset="utf-8",
    )

    msg["Subject"] = (
        f"[umbralyn] {len(diffs)} changement(s) "
        f"détecté(s) sur {target}"
    )
    msg["From"] = config.from_addr
    msg["To"] = config.to_addr

    with smtplib.SMTP(
        config.smtp_host,
        config.smtp_port,
        timeout=15,
    ) as server:
        if config.use_tls:
            server.starttls()

        server.login(
            config.username,
            config.password,
        )

        server.send_message(msg)


def run_once(
    target: str,
    fast: bool = True,
    service_detection: bool = True,
    vuln_scripts: bool = False,
    os_detection: bool = False,
    timeout: int = 600,
    email_config: Optional[EmailConfig] = None,
    db_path: Path = DB_PATH,
) -> list[DiffEntry]:
    """
    Lance un scan, le sauvegarde, compare au précédent
    et envoie une alerte email si des changements sont détectés.
    """

    if timeout <= 0:
        raise ValueError(
            "timeout doit être supérieur à 0."
        )

    scan = run_scan(
        target,
        fast=fast,
        service_detection=service_detection,
        vuln_scripts=vuln_scripts,
        os_detection=os_detection,
        timeout=timeout,
    )

    save_scan(
        scan,
        db_path=db_path,
    )

    previous_scans = latest_scans_for_target(
        target,
        limit=2,
        db_path=db_path,
    )

    if len(previous_scans) < 2:
        return []

    new_scan, old_scan = (
        previous_scans[0],
        previous_scans[1],
    )

    diffs = compare_scans(
        old_scan,
        new_scan,
    )

    if diffs and email_config:
        try:
            send_alert_email(
                email_config,
                target,
                diffs,
            )
        except (
            smtplib.SMTPException,
            OSError,
        ) as error:
            print(
                f"[!] Échec de l'envoi de l'alerte email : {error}"
            )

    return diffs


def run_loop(
    target: str,
    interval_seconds: int,
    fast: bool = True,
    service_detection: bool = True,
    vuln_scripts: bool = False,
    os_detection: bool = False,
    timeout: int = 600,
    email_config: Optional[EmailConfig] = None,
    db_path: Path = DB_PATH,
) -> None:
    """
    Boucle infinie : scanne `target` toutes les `interval_seconds`
    secondes.
    """

    if interval_seconds <= 0:
        raise ValueError(
            "interval_seconds doit être supérieur à 0."
        )

    if timeout <= 0:
        raise ValueError(
            "timeout doit être supérieur à 0."
        )

    print(
        f"[*] Surveillance planifiée de {target} "
        f"toutes les {interval_seconds}s. "
        "Ctrl+C pour arrêter."
    )

    while True:
        try:
            diffs = run_once(
                target=target,
                fast=fast,
                service_detection=service_detection,
                vuln_scripts=vuln_scripts,
                os_detection=os_detection,
                timeout=timeout,
                email_config=email_config,
                db_path=db_path,
            )

            if diffs:
                print(
                    f"[!] {len(diffs)} changement(s) "
                    f"détecté(s) sur {target}"
                )

                for diff in diffs:
                    print(
                        f"    - {diff.host_ip} : {diff.detail}"
                    )
            else:
                print(
                    f"[*] {target} : aucun changement."
                )

        except ScanError as error:
            print(
                f"[!] Erreur de scan : {error}"
            )

        time.sleep(interval_seconds)
