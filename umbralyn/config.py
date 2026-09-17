"""Configuration centralisée d'Umbralyn, chargée depuis YAML et l'environnement."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


DEFAULT_CONFIG_PATH = Path("config.yaml")


@dataclass(frozen=True)
class ScanConfig:
    service_detection: bool = True
    os_detection: bool = False
    nse: bool = False
    timeout_seconds: int = 600


@dataclass(frozen=True)
class AppConfig:
    target_network: str | None = None
    scan: ScanConfig = field(default_factory=ScanConfig)
    database_path: Path = Path("data/umbralyn.db")
    reports_dir: Path = Path("reports")
    risk_alert_threshold: int = 70


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def load_config(path: str | Path | None = None) -> AppConfig:
    """Charge la configuration. Les variables UMBRALYN_* ont priorité sur YAML."""
    config_path = Path(path or os.environ.get("UMBRALYN_CONFIG", DEFAULT_CONFIG_PATH))
    data: dict[str, Any] = {}
    if config_path.exists():
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        data = _mapping(loaded)

    scan = _mapping(data.get("scan"))
    database = _mapping(data.get("database"))
    report = _mapping(data.get("report"))
    risk = _mapping(data.get("risk"))
    target = _mapping(data.get("target"))
    return AppConfig(
        target_network=os.environ.get("UMBRALYN_TARGET", target.get("network")),
        scan=ScanConfig(
            service_detection=bool(scan.get("service_detection", True)),
            os_detection=bool(scan.get("os_detection", False)),
            nse=bool(scan.get("nse", False)),
            timeout_seconds=int(os.environ.get("UMBRALYN_TIMEOUT", scan.get("timeout_seconds", 600))),
        ),
        database_path=Path(os.environ.get("UMBRALYN_DATABASE_PATH", database.get("path", "data/umbralyn.db"))),
        reports_dir=Path(os.environ.get("UMBRALYN_REPORTS_DIR", report.get("directory", "reports"))),
        risk_alert_threshold=int(os.environ.get("UMBRALYN_ALERT_THRESHOLD", risk.get("alert_threshold", 70))),
    )
