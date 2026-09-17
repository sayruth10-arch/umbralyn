"""
history.py
Stocke chaque scan dans une base SQLite locale et permet de comparer
deux scans (détection de nouveaux ports, ports fermés, changements de service).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .scanner import ScanResult, Host, Port


DB_PATH = Path("data/umbralyn.db")


def _connect(db_path: Path = DB_PATH) -> sqlite3.Connection:
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            started_at TEXT NOT NULL,
            duration_seconds REAL,
            data_json TEXT NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def scan_to_dict(scan: ScanResult) -> dict:
    """Sérialise un scan dans un format JSON portable et versionnable."""
    return {
        "target": scan.target,
        "started_at": scan.started_at.isoformat(),
        "duration_seconds": scan.duration_seconds,
        "raw_nmap_args": scan.raw_nmap_args,
        "hosts": [
            {
                "ip": h.ip,
                "hostname": h.hostname,
                "status": h.status,
                "os_guess": h.os_guess,
                "ports": [
                    {
                        "number": p.number,
                        "protocol": p.protocol,
                        "state": p.state,
                        "service": p.service,
                        "product": p.product,
                        "version": p.version,
                        "script_findings": p.script_findings,
                    }
                    for p in h.ports
                ],
            }
            for h in scan.hosts
        ],
    }


def scan_from_dict(d: dict) -> ScanResult:
    from datetime import datetime

    scan = ScanResult(
        target=d["target"],
        started_at=datetime.fromisoformat(d["started_at"]),
        duration_seconds=d["duration_seconds"],
        raw_nmap_args=d.get("raw_nmap_args", ""),
    )

    for hd in d["hosts"]:
        host = Host(
            ip=hd["ip"],
            hostname=hd["hostname"],
            status=hd["status"],
            os_guess=hd["os_guess"],
        )
        host.ports = [Port(**pd) for pd in hd["ports"]]
        scan.hosts.append(host)

    return scan


def save_scan(scan: ScanResult, db_path: Path = DB_PATH) -> int:
    conn = _connect(db_path)

    cur = conn.execute(
        "INSERT INTO scans (target, started_at, duration_seconds, data_json) VALUES (?, ?, ?, ?)",
        (
            scan.target,
            scan.started_at.isoformat(),
            scan.duration_seconds,
            json.dumps(scan_to_dict(scan)),
        ),
    )

    conn.commit()
    scan_id = cur.lastrowid
    conn.close()

    return scan_id


def get_scan(
    scan_id: int,
    db_path: Path = DB_PATH,
) -> Optional[ScanResult]:
    conn = _connect(db_path)

    row = conn.execute(
        "SELECT data_json FROM scans WHERE id = ?",
        (scan_id,),
    ).fetchone()

    conn.close()

    if row is None:
        return None

    return scan_from_dict(json.loads(row[0]))


def latest_scans_for_target(
    target: str,
    limit: int = 2,
    db_path: Path = DB_PATH,
) -> List[ScanResult]:
    conn = _connect(db_path)

    rows = conn.execute(
        """
        SELECT data_json
        FROM scans
        WHERE target = ?
        ORDER BY started_at DESC
        LIMIT ?
        """,
        (target, limit),
    ).fetchall()

    conn.close()

    return [
        scan_from_dict(json.loads(row[0]))
        for row in rows
    ]


def load_scan_json(path: str | Path) -> ScanResult:
    """Charge un export JSON Umbralyn sans effectuer de scan réseau."""
    return scan_from_dict(
        json.loads(
            Path(path).read_text(encoding="utf-8")
        )
    )


def save_scan_json(
    scan: ScanResult,
    path: str | Path,
    cves: Optional[Dict[str, list]] = None,
) -> Path:
    """Exporte le résultat du scan avec les CVE associées si disponibles."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)

    data = scan_to_dict(scan)

    if cves:
        data["cves"] = cves

    output.write_text(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    return output


def list_scans(
    target: Optional[str] = None,
    db_path: Path = DB_PATH,
) -> List[dict]:
    conn = _connect(db_path)

    if target:
        rows = conn.execute(
            """
            SELECT id, target, started_at
            FROM scans
            WHERE target = ?
            ORDER BY started_at DESC
            """,
            (target,),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT id, target, started_at
            FROM scans
            ORDER BY started_at DESC
            """
        ).fetchall()

    conn.close()

    return [
        {
            "id": row[0],
            "target": row[1],
            "started_at": row[2],
        }
        for row in rows
    ]


# --- Comparaison entre deux scans ---


@dataclass
class DiffEntry:
    host_ip: str
    kind: str  # "new_port", "closed_port", "service_changed", "new_host", "host_down"
    detail: str


def compare_scans(
    old: ScanResult,
    new: ScanResult,
) -> List[DiffEntry]:
    diffs: List[DiffEntry] = []

    old_hosts = {
        host.ip: host
        for host in old.hosts_up
    }

    new_hosts = {
        host.ip: host
        for host in new.hosts_up
    }

    for ip in new_hosts.keys() - old_hosts.keys():
        diffs.append(
            DiffEntry(
                ip,
                "new_host",
                f"Nouvel hôte actif détecté : {ip}",
            )
        )

    for ip in old_hosts.keys() - new_hosts.keys():
        diffs.append(
            DiffEntry(
                ip,
                "host_down",
                f"Hôte {ip} n'est plus actif (ou hors ligne)",
            )
        )

    for ip in old_hosts.keys() & new_hosts.keys():
        # La clé contient le numéro ET le protocole afin d'éviter
        # de confondre TCP/80 et UDP/80.
        old_ports = {
            (port.number, port.protocol): port
            for port in old_hosts[ip].open_ports
        }

        new_ports = {
            (port.number, port.protocol): port
            for port in new_hosts[ip].open_ports
        }

        for port_key in new_ports.keys() - old_ports.keys():
            port = new_ports[port_key]

            diffs.append(
                DiffEntry(
                    ip,
                    "new_port",
                    f"Nouveau port ouvert : "
                    f"{port.number}/{port.protocol} ({port.service})",
                )
            )

        for port_key in old_ports.keys() - new_ports.keys():
            port = old_ports[port_key]

            diffs.append(
                DiffEntry(
                    ip,
                    "closed_port",
                    f"Port fermé depuis le dernier scan : "
                    f"{port.number}/{port.protocol} ({port.service})",
                )
            )

        for port_key in old_ports.keys() & new_ports.keys():
            old_port = old_ports[port_key]
            new_port = new_ports[port_key]

            if old_port.banner != new_port.banner:
                diffs.append(
                    DiffEntry(
                        ip,
                        "service_changed",
                        f"Port {new_port.number}/{new_port.protocol} : "
                        f"service modifié "
                        f"({old_port.banner} → {new_port.banner})",
                    )
                )

    return diffs
