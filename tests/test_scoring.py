from umbralyn.risk_analysis import Finding
from umbralyn.scoring import score_host


def test_score_is_capped_and_explained() -> None:
    findings = [Finding("10.0.0.1", 23, "Telnet", "Plaintext", "high") for _ in range(4)]
    result = score_host("10.0.0.1", findings)
    assert result.score == 100
    assert len(result.breakdown) == 4
