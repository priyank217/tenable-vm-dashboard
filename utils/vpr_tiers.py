"""VPR-based severity tiers (dashboard reporting)."""

VPR_MIN = 0.1

# 9.0–10 Critical | 7.0–8.9 High | 4.0–6.9 Medium | 0.1–3.9 Low
VPR_TIERS = ("critical", "high", "medium", "low")


def vpr_tier(score: float | None) -> str | None:
    if score is None or score < VPR_MIN:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def vpr_tier_sql(column: str = "vpr_score") -> str:
    return f"""
    CASE
      WHEN {column} >= 9.0 THEN 'critical'
      WHEN {column} >= 7.0 THEN 'high'
      WHEN {column} >= 4.0 THEN 'medium'
      WHEN {column} >= 0.1 THEN 'low'
      ELSE NULL
    END
    """
