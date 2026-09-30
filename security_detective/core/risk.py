from __future__ import annotations

from dataclasses import dataclass

from .models import Finding, Severity


_SEVERITY_WEIGHT = {
    Severity.INFORMATIONAL: 0.05,
    Severity.LOW: 0.20,
    Severity.MEDIUM: 0.45,
    Severity.HIGH: 0.70,
    Severity.CRITICAL: 0.95,
}


@dataclass(frozen=True, slots=True)
class RiskScore:
    score: float
    priority: str


def calculate_risk(
    finding: Finding,
    *,
    exposure: float = 0.5,
    asset_criticality: float = 0.5,
) -> RiskScore:
    """Calculate a bounded score; confidence is deliberately independent of severity."""
    for name, value in (("exposure", exposure), ("asset_criticality", asset_criticality)):
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"{name} must be between 0 and 1")

    severity = _SEVERITY_WEIGHT[finding.severity]
    score = (
        severity * 0.30
        + finding.confidence * 0.20
        + finding.exploitability * 0.20
        + finding.impact * 0.15
        + exposure * 0.10
        + asset_criticality * 0.05
    ) * 100

    priority = "critical" if score >= 85 else "high" if score >= 65 else "medium" if score >= 40 else "low"
    return RiskScore(round(score, 2), priority)
