from scanners import VulnerabilityFinding


def calculate_security_score(findings: list[VulnerabilityFinding]) -> int:
    """
    score = max(0, 100 - 20*C - 10*H - 5*M - 2*L)
    """
    critical = sum(1 for f in findings if f.severity == "Critical")
    high = sum(1 for f in findings if f.severity == "High")
    medium = sum(1 for f in findings if f.severity == "Medium")
    low = sum(1 for f in findings if f.severity == "Low")

    score = 100 - (20 * critical + 10 * high + 5 * medium + 2 * low)
    return max(0, score)


def risk_level_from_score(score: int) -> str:
    if score >= 90:
        return "Excellent"
    elif score >= 75:
        return "Good"
    elif score >= 50:
        return "Average"
    elif score >= 25:
        return "Poor"
    else:
        return "Critical Risk"