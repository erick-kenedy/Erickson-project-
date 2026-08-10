"""
NetGuard Security Scanner
Defensive network and data security assessment package.
"""

# Risk scoring utilities
RISK_SCORE = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 2,
    "Info": 0,
}


def score(findings):
    """Calculate a numeric risk score and level from a list of findings.

    Each finding is expected to be a dict with at least a "risk" key whose
    value is one of the keys in RISK_SCORE.
    """
    total = sum(RISK_SCORE.get(f.get("risk", "Info"), 0) for f in findings)

    if total >= 20:
        level = "Critical"
    elif total >= 12:
        level = "High"
    elif total >= 5:
        level = "Medium"
    elif total > 0:
        level = "Low"
    else:
        level = "Secure"

    return total, level
