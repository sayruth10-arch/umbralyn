"""
report.py
Génère un rapport HTML (et PDF optionnel) à partir d'un ScanResult,
de sa liste de Findings, et optionnellement des CVE associées,
des scores de risque par hôte, et d'un diff avec un scan précédent.
"""

from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .scanner import ScanResult
from .risk_analysis import Finding, summarize
from .scoring import HostScore, score_all_hosts, global_score
from .history import DiffEntry

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def render_html(
    scan: ScanResult,
    findings: List[Finding],
    cves: Optional[Dict[str, list]] = None,
    diffs: Optional[List[DiffEntry]] = None,
) -> str:
    cves = cves or {}
    host_scores = score_all_hosts(scan, findings, cves)
    scores_by_ip = {s.host_ip: s for s in host_scores}

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html")
    return template.render(
        scan=scan,
        findings=findings,
        summary=summarize(scan, findings),
        generated_at=datetime.now().strftime("%d/%m/%Y %H:%M"),
        cves=cves,
        host_scores=host_scores,
        scores_by_ip=scores_by_ip,
        global_risk_score=global_score(host_scores),
        diffs=diffs or [],
    )


def save_html(
    scan: ScanResult,
    findings: List[Finding],
    out_path: str,
    cves: Optional[Dict[str, list]] = None,
    diffs: Optional[List[DiffEntry]] = None,
) -> Path:
    html = render_html(scan, findings, cves, diffs)
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return path


def save_pdf(
    scan: ScanResult,
    findings: List[Finding],
    out_path: str,
    cves: Optional[Dict[str, list]] = None,
    diffs: Optional[List[DiffEntry]] = None,
) -> Path:
    """Nécessite le paquet 'weasyprint' (pip install weasyprint)."""
    try:
        from weasyprint import HTML
    except ImportError as e:
        raise RuntimeError(
            "L'export PDF nécessite weasyprint : pip install weasyprint"
        ) from e

    html = render_html(scan, findings, cves, diffs)
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html, base_url=str(TEMPLATE_DIR)).write_pdf(str(path))
    return path
