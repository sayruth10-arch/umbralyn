"""
umbralyn — outil d'audit réseau (Nmap + CVE + scoring + historique + rapport HTML/PDF)

Usage :
    python -m umbralyn scan 192.168.1.0/24
    python -m umbralyn scan 10.0.0.5 --full --pdf --cve --vuln-scripts
    python -m umbralyn scan 192.168.1.0/24 --save-history --compare
    python -m umbralyn schedule 192.168.1.0/24 --interval 3600 --email-to alerte@exemple.com

ATTENTION : ne scanner que des cibles que tu es autorisé à scanner
(ton propre lab, ou accord écrit explicite du propriétaire du réseau).
Scanner un réseau sans autorisation peut être illégal.
"""

import argparse
import os
import sys
from pathlib import Path

from .scanner import run_scan, ScanError
from .risk_analysis import analyze, summarize
from .report import save_html, save_pdf
from .cve_lookup import lookup_cves_for_scan
from .history import (
    save_scan,
    latest_scans_for_target,
    compare_scans,
    list_scans,
    load_scan_json,
    save_scan_json,
)
from .scheduler import run_loop, EmailConfig
from .config import load_config


def sanitize_filename(target: str) -> str:
    return target.replace("/", "_").replace(":", "_")


def add_scan_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "target",
        help="Cible à scanner : IP, plage CIDR ou nom d'hôte",
    )

    parser.add_argument(
        "--full",
        action="store_true",
        help="Scan complet (tous les ports) au lieu du scan rapide (top 100).",
    )

    parser.add_argument(
        "--no-service-detection",
        action="store_true",
        help="Désactive la détection de version des services (-sV).",
    )

    parser.add_argument(
        "--vuln-scripts",
        action="store_true",
        help="Active les scripts NSE --script vuln (plus lent, plus précis).",
    )

    parser.add_argument(
        "--cve",
        action="store_true",
        help="Recherche les CVE associées aux services/versions détectés.",
    )

    parser.add_argument(
        "--out",
        default=None,
        help="Chemin du rapport HTML de sortie "
             "(défaut : reports/<cible>.html)",
    )

    parser.add_argument(
        "--pdf",
        action="store_true",
        help="Génère aussi une version PDF du rapport.",
    )

    parser.add_argument(
        "--save-history",
        action="store_true",
        help="Sauvegarde ce scan dans l'historique SQLite "
             "(data/umbralyn.db).",
    )

    parser.add_argument(
        "--compare",
        action="store_true",
        help="Compare avec le scan précédent de la même cible "
             "(implique --save-history).",
    )


def cmd_scan(args: argparse.Namespace) -> int:
    config = load_config(args.config)

    out_html = args.out or str(
        config.reports_dir
        / f"{sanitize_filename(args.target)}.html"
    )

    print(f"[*] Lancement du scan sur {args.target} ...")

    try:
        scan = run_scan(
            args.target,
            fast=not args.full,
            service_detection=(
                not args.no_service_detection
                and config.scan.service_detection
            ),
            vuln_scripts=(
                args.vuln_scripts
                or config.scan.nse
            ),
            os_detection=(
                args.os_detection
                or config.scan.os_detection
            ),
            timeout=config.scan.timeout_seconds,
        )

    except ScanError as error:
        print(
            f"[!] Erreur : {error}",
            file=sys.stderr,
        )
        return 1

    if not scan.hosts_up:
        print(
            "[!] Aucun hôte actif détecté sur la cible."
        )

    findings = analyze(scan)
    stats = summarize(scan, findings)

    print(
        f"[*] {stats['hosts_up']}/{stats['hosts_scanned']} "
        f"hôte(s) actif(s), "
        f"{stats['total_open_ports']} port(s) ouvert(s)"
    )

    print(
        f"[*] {stats['findings_high']} alerte(s) critique(s), "
        f"{stats['findings_medium']} alerte(s) moyenne(s)"
    )

    cves = {}

    if args.cve:
        print(
            "[*] Recherche des CVE associées "
            "(API NVD, peut prendre quelques minutes)..."
        )

        cves = lookup_cves_for_scan(scan)

        print(
            f"[*] {sum(len(value) for value in cves.values())} "
            f"CVE trouvée(s) sur {len(cves)} port(s)"
        )

    diffs = []

    if args.compare or args.save_history:
        save_scan(
            scan,
            config.database_path,
        )

        print(
            "[+] Scan sauvegardé dans l'historique."
        )

        if args.compare:
            previous = latest_scans_for_target(
                args.target,
                limit=2,
                db_path=config.database_path,
            )

            if len(previous) == 2:
                diffs = compare_scans(
                    previous[1],
                    previous[0],
                )

                print(
                    f"[*] {len(diffs)} changement(s) "
                    "depuis le scan précédent."
                )

            else:
                print(
                    "[*] Pas de scan précédent pour cette cible : "
                    "rien à comparer."
                )

    html_path = save_html(
        scan,
        findings,
        out_html,
        cves=cves,
        diffs=diffs,
    )

    print(
        f"[+] Rapport HTML : {html_path}"
    )

    if args.pdf:
        pdf_path = save_pdf(
            scan,
            findings,
            str(Path(out_html).with_suffix(".pdf")),
            cves=cves,
            diffs=diffs,
        )

        print(
            f"[+] Rapport PDF : {pdf_path}"
        )

    if args.json_out:
        json_path = save_scan_json(
            scan,
            args.json_out,
        )

        print(
            f"[+] Export JSON : {json_path}"
        )

    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    old_scan = load_scan_json(args.old_scan)
    new_scan = load_scan_json(args.new_scan)

    diffs = compare_scans(
        old_scan,
        new_scan,
    )

    if not diffs:
        print(
            "Aucun changement détecté."
        )
        return 0

    for diff in diffs:
        print(
            f"[{diff.kind.upper()}] "
            f"{diff.host_ip} — {diff.detail}"
        )

    return 0


def cmd_history(args: argparse.Namespace) -> int:
    config = load_config(args.config)

    entries = list_scans(
        args.target,
        config.database_path,
    )

    if not entries:
        print(
            "Aucun scan dans l'historique."
        )
        return 0

    for entry in entries:
        print(
            f"#{entry['id']}  "
            f"{entry['started_at']}  "
            f"{entry['target']}"
        )

    return 0


def cmd_report(args: argparse.Namespace) -> int:
    scan = load_scan_json(
        args.scan_file
    )

    findings = analyze(scan)

    output = save_html(
        scan,
        findings,
        args.out,
    )

    print(
        f"[+] Rapport HTML : {output}"
    )

    return 0


def cmd_config(args: argparse.Namespace) -> int:
    config = load_config(
        args.config
    )

    print(
        f"Base de données : {config.database_path}"
    )

    print(
        f"Rapports : {config.reports_dir}"
    )

    print(
        f"Cible : {config.target_network or 'non définie'}"
    )

    print(
        f"Détection de service : "
        f"{config.scan.service_detection}"
    )

    print(
        f"Détection d'OS : "
        f"{config.scan.os_detection}"
    )

    print(
        f"Scripts NSE : "
        f"{config.scan.nse}"
    )

    print(
        f"Timeout : "
        f"{config.scan.timeout_seconds}s"
    )

    print(
        f"Seuil d'alerte : "
        f"{config.risk_alert_threshold}"
    )

    return 0


def cmd_schedule(args: argparse.Namespace) -> int:
    config = load_config(
        args.config
    )

    email_config = None

    if args.email_to:
        smtp_user = os.environ.get(
            "UMBRALYN_SMTP_USER"
        )

        smtp_pass = os.environ.get(
            "UMBRALYN_SMTP_PASS"
        )

        if not smtp_user or not smtp_pass:
            print(
                "[!] --email-to nécessite les variables "
                "d'environnement UMBRALYN_SMTP_USER "
                "et UMBRALYN_SMTP_PASS.",
                file=sys.stderr,
            )
            return 1

        email_config = EmailConfig(
            smtp_host=args.smtp_host,
            smtp_port=args.smtp_port,
            username=smtp_user,
            password=smtp_pass,
            from_addr=smtp_user,
            to_addr=args.email_to,
        )

    try:
        run_loop(
            target=args.target,
            interval_seconds=args.interval,
            fast=not args.full,
            service_detection=(
                not args.no_service_detection
                and config.scan.service_detection
            ),
            vuln_scripts=(
                args.vuln_scripts
                or config.scan.nse
            ),
            os_detection=(
                args.os_detection
                or config.scan.os_detection
            ),
            timeout_seconds=config.scan.timeout_seconds,
            email_config=email_config,
            db_path=config.database_path,
        )

    except ValueError as error:
        print(
            f"[!] Configuration invalide : {error}",
            file=sys.stderr,
        )
        return 1

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="umbralyn",
        description=(
            "Scanne une cible réseau et génère "
            "un rapport d'audit HTML/PDF."
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # ------------------------------------------------------------------
    # SCAN
    # ------------------------------------------------------------------

    scan_parser = subparsers.add_parser(
        "scan",
        help="Lance un scan unique et génère un rapport.",
    )

    add_scan_common_args(
        scan_parser
    )

    scan_parser.add_argument(
        "--os-detection",
        action="store_true",
        help=(
            "Active la détection d'OS (-O, "
            "peut nécessiter des privilèges)."
        ),
    )

    scan_parser.add_argument(
        "--json-out",
        help="Exporte aussi le scan en JSON portable.",
    )

    scan_parser.add_argument(
        "--config",
        help="Chemin du fichier YAML de configuration.",
    )

    scan_parser.set_defaults(
        func=cmd_scan
    )

    # ------------------------------------------------------------------
    # COMPARE
    # ------------------------------------------------------------------

    compare_parser = subparsers.add_parser(
        "compare",
        help="Compare deux exports JSON sans lancer de scan.",
    )

    compare_parser.add_argument(
        "old_scan",
        help="Export JSON de référence",
    )

    compare_parser.add_argument(
        "new_scan",
        help="Nouvel export JSON",
    )

    compare_parser.set_defaults(
        func=cmd_compare
    )

    # ------------------------------------------------------------------
    # HISTORY
    # ------------------------------------------------------------------

    history_parser = subparsers.add_parser(
        "history",
        help="Affiche les scans archivés.",
    )

    history_parser.add_argument(
        "--target",
        help="Filtre sur une cible",
    )

    history_parser.add_argument(
        "--config",
        help="Chemin du fichier YAML de configuration.",
    )

    history_parser.set_defaults(
        func=cmd_history
    )

    # ------------------------------------------------------------------
    # REPORT
    # ------------------------------------------------------------------

    report_parser = subparsers.add_parser(
        "report",
        help="Génère un rapport HTML depuis un export JSON.",
    )

    report_parser.add_argument(
        "scan_file",
        help="Export JSON Umbralyn",
    )

    report_parser.add_argument(
        "--out",
        default="reports/report.html",
        help="Chemin du rapport HTML",
    )

    report_parser.set_defaults(
        func=cmd_report
    )

    # ------------------------------------------------------------------
    # CONFIG
    # ------------------------------------------------------------------

    config_parser = subparsers.add_parser(
        "config",
        help="Affiche la configuration effective.",
    )

    config_parser.add_argument(
        "--config",
        help="Chemin du fichier YAML de configuration.",
    )

    config_parser.set_defaults(
        func=cmd_config
    )

    # ------------------------------------------------------------------
    # SCHEDULE
    # ------------------------------------------------------------------

    schedule_parser = subparsers.add_parser(
        "schedule",
        help="Surveille une cible à intervalle régulier.",
    )

    schedule_parser.add_argument(
        "target",
        help="Cible à surveiller",
    )

    schedule_parser.add_argument(
        "--interval",
        type=int,
        default=3600,
        help=(
            "Intervalle entre deux scans, "
            "en secondes (défaut : 3600)"
        ),
    )

    schedule_parser.add_argument(
        "--full",
        action="store_true",
        help="Scan complet au lieu du top 100.",
    )

    schedule_parser.add_argument(
        "--no-service-detection",
        action="store_true",
        help="Désactive la détection de version des services.",
    )

    schedule_parser.add_argument(
        "--vuln-scripts",
        action="store_true",
        help="Active les scripts NSE de vulnérabilité.",
    )

    schedule_parser.add_argument(
        "--os-detection",
        action="store_true",
        help="Active la détection d'OS.",
    )

    schedule_parser.add_argument(
        "--email-to",
        default=None,
        help="Adresse email d'alerte en cas de changement détecté.",
    )

    schedule_parser.add_argument(
        "--smtp-host",
        default="smtp.gmail.com",
        help="Serveur SMTP utilisé pour les alertes.",
    )

    schedule_parser.add_argument(
        "--smtp-port",
        type=int,
        default=587,
        help="Port SMTP utilisé pour les alertes.",
    )

    schedule_parser.add_argument(
        "--config",
        help="Chemin du fichier YAML de configuration.",
    )

    schedule_parser.set_defaults(
        func=cmd_schedule
    )

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())                         help="Scan complet (tous les ports) au lieu du scan rapide (top 100).")
    parser.add_argument("--no-service-detection", action="store_true",
                         help="Désactive la détection de version des services (-sV).")
    parser.add_argument("--vuln-scripts", action="store_true",
                         help="Active les scripts NSE --script vuln (plus lent, plus précis).")
    parser.add_argument("--cve", action="store_true",
                         help="Recherche les CVE connues pour les services/versions détectés (API NVD).")
    parser.add_argument("--out", default=None,
                         help="Chemin du rapport HTML de sortie (défaut : reports/<cible>.html)")
    parser.add_argument("--pdf", action="store_true", help="Génère aussi une version PDF du rapport.")
    parser.add_argument("--save-history", action="store_true",
                         help="Sauvegarde ce scan dans l'historique SQLite (umbralyn_history.db).")
    parser.add_argument("--compare", action="store_true",
                         help="Compare avec le scan précédent de la même cible (implique --save-history).")


def cmd_scan(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    out_html = args.out or str(config.reports_dir / f"{sanitize_filename(args.target)}.html")

    print(f"[*] Lancement du scan sur {args.target} ...")
    try:
        scan = run_scan(
            args.target,
            fast=not args.full,
            service_detection=not args.no_service_detection,
            vuln_scripts=args.vuln_scripts,
            os_detection=args.os_detection or config.scan.os_detection,
            timeout=config.scan.timeout_seconds,
        )
    except ScanError as e:
        print(f"[!] Erreur : {e}", file=sys.stderr)
        return 1

    if not scan.hosts_up:
        print("[!] Aucun hôte actif détecté sur la cible.")

    findings = analyze(scan)
    stats = summarize(scan, findings)
    print(f"[*] {stats['hosts_up']}/{stats['hosts_scanned']} hôte(s) actif(s), "
          f"{stats['total_open_ports']} port(s) ouvert(s)")
    print(f"[*] {stats['findings_high']} alerte(s) critique(s), "
          f"{stats['findings_medium']} alerte(s) moyenne(s)")

    cves = {}
    if args.cve:
        print("[*] Recherche des CVE associées (API NVD, peut prendre quelques minutes)...")
        cves = lookup_cves_for_scan(scan)
        print(f"[*] {sum(len(v) for v in cves.values())} CVE trouvée(s) sur {len(cves)} port(s)")

    diffs = []
    if args.compare or args.save_history:
        save_scan(scan, config.database_path)
        print("[+] Scan sauvegardé dans l'historique.")
        if args.compare:
            previous = latest_scans_for_target(args.target, limit=2, db_path=config.database_path)
            if len(previous) == 2:
                diffs = compare_scans(previous[1], previous[0])
                print(f"[*] {len(diffs)} changement(s) depuis le scan précédent.")
            else:
                print("[*] Pas de scan précédent pour cette cible : rien à comparer.")

    html_path = save_html(scan, findings, out_html, cves=cves, diffs=diffs)
    print(f"[+] Rapport HTML : {html_path}")

    if args.pdf:
        pdf_path = save_pdf(scan, findings, str(Path(out_html).with_suffix(".pdf")), cves=cves, diffs=diffs)
        print(f"[+] Rapport PDF : {pdf_path}")
    if args.json_out:
        json_path = save_scan_json(scan, args.json_out)
        print(f"[+] Export JSON : {json_path}")

    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    old_scan, new_scan = load_scan_json(args.old_scan), load_scan_json(args.new_scan)
    diffs = compare_scans(old_scan, new_scan)
    if not diffs:
        print("Aucun changement détecté.")
        return 0
    for diff in diffs:
        print(f"[{diff.kind.upper()}] {diff.host_ip} — {diff.detail}")
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    entries = list_scans(args.target, config.database_path)
    if not entries:
        print("Aucun scan dans l'historique.")
        return 0
    for entry in entries:
        print(f"#{entry['id']}  {entry['started_at']}  {entry['target']}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    scan = load_scan_json(args.scan_file)
    findings = analyze(scan)
    output = save_html(scan, findings, args.out)
    print(f"[+] Rapport HTML : {output}")
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    print(f"Base de données : {config.database_path}")
    print(f"Rapports : {config.reports_dir}")
    print(f"Détection de service : {config.scan.service_detection}")
    print(f"Seuil d'alerte : {config.risk_alert_threshold}")
    return 0


def cmd_schedule(args: argparse.Namespace) -> int:
    email_config = None
    if args.email_to:
        smtp_user = os.environ.get("UMBRALYN_SMTP_USER")
        smtp_pass = os.environ.get("UMBRALYN_SMTP_PASS")
        if not smtp_user or not smtp_pass:
            print("[!] --email-to nécessite les variables d'environnement "
                  "UMBRALYN_SMTP_USER et UMBRALYN_SMTP_PASS.", file=sys.stderr)
            return 1
        email_config = EmailConfig(
            smtp_host=args.smtp_host,
            smtp_port=args.smtp_port,
            username=smtp_user,
            password=smtp_pass,
            from_addr=smtp_user,
            to_addr=args.email_to,
        )

    run_loop(
        args.target,
        interval_seconds=args.interval,
        fast=not args.full,
        service_detection=not args.no_service_detection,
        email_config=email_config,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="umbralyn",
        description="Scanne une cible réseau et génère un rapport d'audit HTML/PDF.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Lance un scan unique et génère un rapport.")
    add_scan_common_args(scan_parser)
    scan_parser.add_argument("--os-detection", action="store_true", help="Active la détection d'OS (-O, peut nécessiter des privilèges).")
    scan_parser.add_argument("--json-out", help="Exporte aussi le scan en JSON portable.")
    scan_parser.add_argument("--config", help="Chemin du fichier YAML de configuration.")
    scan_parser.set_defaults(func=cmd_scan)

    compare_parser = subparsers.add_parser("compare", help="Compare deux exports JSON sans lancer de scan.")
    compare_parser.add_argument("old_scan", help="Export JSON de référence")
    compare_parser.add_argument("new_scan", help="Nouvel export JSON")
    compare_parser.set_defaults(func=cmd_compare)

    history_parser = subparsers.add_parser("history", help="Affiche les scans archivés.")
    history_parser.add_argument("--target", help="Filtre sur une cible")
    history_parser.add_argument("--config", help="Chemin du fichier YAML de configuration.")
    history_parser.set_defaults(func=cmd_history)

    report_parser = subparsers.add_parser("report", help="Génère un rapport HTML depuis un export JSON.")
    report_parser.add_argument("scan_file", help="Export JSON Umbralyn")
    report_parser.add_argument("--out", default="reports/report.html", help="Chemin du rapport HTML")
    report_parser.set_defaults(func=cmd_report)

    config_parser = subparsers.add_parser("config", help="Affiche la configuration effective.")
    config_parser.add_argument("--config", help="Chemin du fichier YAML de configuration.")
    config_parser.set_defaults(func=cmd_config)

    schedule_parser = subparsers.add_parser("schedule", help="Surveille une cible à intervalle régulier.")
    schedule_parser.add_argument("target", help="Cible à surveiller")
    schedule_parser.add_argument("--interval", type=int, default=3600,
                                  help="Intervalle entre deux scans, en secondes (défaut : 3600)")
    schedule_parser.add_argument("--full", action="store_true", help="Scan complet au lieu du top 100.")
    schedule_parser.add_argument("--no-service-detection", action="store_true")
    schedule_parser.add_argument("--email-to", default=None,
                                  help="Adresse email d'alerte en cas de changement détecté.")
    schedule_parser.add_argument("--smtp-host", default="smtp.gmail.com")
    schedule_parser.add_argument("--smtp-port", type=int, default=587)
    schedule_parser.set_defaults(func=cmd_schedule)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
