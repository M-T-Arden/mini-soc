from core.models import Alert, SeverityLevel


def score_alert(base_score: int, asset_criticality: int = 1, context_boost: int = 0) -> SeverityLevel:
    total = base_score * asset_criticality + context_boost
    if total >= 80:
        return SeverityLevel.CRITICAL
    if total >= 60:
        return SeverityLevel.HIGH
    if total >= 30:
        return SeverityLevel.MEDIUM
    return SeverityLevel.LOW


def alert_score_from_rule(rule_weight: int, event_context: int = 0, asset_criticality: int = 1):
    return score_alert(rule_weight, asset_criticality, event_context)
