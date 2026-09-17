import json
from datetime import datetime

from umbralyn.history import (
    compare_scans,
    save_scan_json,
    scan_from_dict,
    scan_to_dict,
)

from umbralyn.scanner import Host, Port, ScanResult


def make_scan(ports: list[int]) -> ScanResult:
    scan = ScanResult(
        target="192.168.1.0/24",
        started_at=datetime(2026, 1, 1),
        duration_seconds=1,
    )
    host = Host(
        ip="192.168.1.10",
        hostname="server",
        status="up",
        os_guess="Linux",
    )
    host.ports = [
        Port(
            number=p,
            protocol="tcp",
            state="open",
            service="http",
            product="nginx",
            version="1.24",
        )
        for p in ports
    ]
    scan.hosts.append(host)
    return scan


def test_scan_round_trip_preserves_ports_and_scripts() -> None:
    scan = make_scan([80])
    scan.hosts[0].ports[0].script_findings = ["http-test: safe result"]

    rebuilt = scan_from_dict(scan_to_dict(scan))

    assert rebuilt.hosts[0].open_ports[0].script_findings == [
        "http-test: safe result"
    ]


def test_compare_detects_new_port() -> None:
    diffs = compare_scans(make_scan([80]), make_scan([80, 443]))

    assert [(item.kind, item.host_ip) for item in diffs] == [
        ("new_port", "192.168.1.10")
    ]


def test_save_scan_json_preserves_cves(tmp_path) -> None:
    scan = make_scan([80])
    output = tmp_path / "scan.json"

    cves = {
        "192.168.1.10:80": [
            {
                "id": "CVE-TEST-0001",
                "severity": "high",
                "summary": "Test CVE export",
            }
        ]
    }

    save_scan_json(scan, output, cves=cves)

    data = json.loads(output.read_text(encoding="utf-8"))

    assert data["cves"] == cves
