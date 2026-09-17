import pytest

from umbralyn.config import load_config


def test_default_config_is_valid() -> None:
    config = load_config(None)

    assert config.target_network is None
    assert config.scan.timeout_seconds == 600
    assert config.scan.service_detection is True
    assert config.scan.os_detection is False
    assert config.scan.nse is False
    assert config.risk_alert_threshold == 70
    assert str(config.database_path) == "data/umbralyn.db"
    assert str(config.reports_dir) == "reports"


def test_environment_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("UMBRALYN_TARGET", "192.168.1.0/24")
    monkeypatch.setenv("UMBRALYN_TIMEOUT", "300")
    monkeypatch.setenv("UMBRALYN_NSE", "true")
    monkeypatch.setenv("UMBRALYN_OS_DETECTION", "true")
    monkeypatch.setenv("UMBRALYN_ALERT_THRESHOLD", "80")

    config = load_config(None)

    assert config.target_network == "192.168.1.0/24"
    assert config.scan.timeout_seconds == 300
    assert config.scan.nse is True
    assert config.scan.os_detection is True
    assert config.risk_alert_threshold == 80


def test_invalid_timeout_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("UMBRALYN_TIMEOUT", "0")

    with pytest.raises(ValueError):
        load_config(None)


def test_invalid_boolean_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("UMBRALYN_NSE", "maybe")

    with pytest.raises(ValueError):
        load_config(None)
