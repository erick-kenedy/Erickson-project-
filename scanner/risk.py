"""
NetGuard risk scoring engine.

Converts security findings into a normalized 0-100 risk score.
"""

from __future__ import annotations

from typing import Any


# Base severity weights.
SEVERITY_WEIGHTS = {
    "Critical": 100,
    "High": 75,
    "Medium": 50,
    "Low": 25,
    "Info": 0,
}


# Confidence multipliers.
CONFIDENCE_MULTIPLIERS = {
    "High": 1.00,
    "Medium": 0.80,
    "Low": 0.60,
}


# Maximum contribution from a single finding.
MAX_FINDING_SCORE = 100


def normalize_severity(value: Any) -> str:
    """Return a valid severity level."""

    if not isinstance(value, str):
        return "Info"

    value = value.strip().title()

    if value not in SEVERITY_WEIGHTS:
        return "Info"

    return value


def normalize_confidence(value: Any) -> str:
    """Return a valid confidence level."""

    if not isinstance(value, str):
        return "Medium"

    value = value.strip().title()

    if value not in CONFIDENCE_MULTIPLIERS:
        return "Medium"

    return value


def finding_score(finding: dict[str, Any]) -> float:
    """
    Calculate the contribution of one finding.

    Severity determines the base risk.
    Confidence adjusts how strongly the finding contributes.
    """

    severity = normalize_severity(
        finding.get("risk", "Info")
    )

    confidence = normalize_confidence(
        finding.get("confidence", "Medium")
    )

    base_score = SEVERITY_WEIGHTS[severity]

    adjusted_score = (
        base_score
        * CONFIDENCE_MULTIPLIERS[confidence]
    )

    return min(
        adjusted_score,
        MAX_FINDING_SCORE,
    )


def calculate_raw_score(
    findings: list[dict[str, Any]],
) -> float:
    """Calculate the combined weighted score."""

    if not findings:
        return 0.0

    total = sum(
        finding_score(finding)
        for finding in findings
    )

    return total


def calculate_normalized_score(
    findings: list[dict[str, Any]],
) -> int:
    """
    Convert findings into a 0-100 score.

    The score is based on the average weighted severity,
    with additional findings increasing the score gradually.
    """

    if not findings:
        return 0

    raw_score = calculate_raw_score(findings)

    average_score = raw_score / len(findings)

    # Additional findings increase overall exposure,
    # but repeated findings are subject to diminishing impact.
    count_factor = min(
        1.0 + (len(findings) - 1) * 0.08,
        1.75,
    )

    normalized = average_score * count_factor

    return max(
        0,
        min(
            100,
            round(normalized),
        ),
    )


def risk_level(score_value: int) -> str:
    """Convert a numerical score into a risk level."""

    if score_value >= 80:
        return "Critical"

    if score_value >= 60:
        return "High"

    if score_value >= 30:
        return "Medium"

    if score_value > 0:
        return "Low"

    return "Info"


def score(
    findings: list[dict[str, Any]],
) -> tuple[int, str]:
    """
    Return:

        (normalized_score, risk_level)
    """

    if not findings:
        return 0, "Info"

    normalized = calculate_normalized_score(
        findings
    )

    return (
        normalized,
        risk_level(normalized),
    )


def risk_summary(
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return useful statistics for the dashboard."""

    total_score, overall_level = score(findings)

    summary = {
        "total": len(findings),
        "score": total_score,
        "level": overall_level,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:

        severity = normalize_severity(
            finding.get("risk", "Info")
        )

        key = severity.lower()

        if key in summary:
            summary[key] += 1

    return summary