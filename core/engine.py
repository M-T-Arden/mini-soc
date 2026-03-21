from typing import List, Tuple

from core.rule_loader import load_rules_from_yaml
from core.models import Alert, LogEvent
from core.dedup import dedup_alerts
from core.scoring import alert_score_from_rule

RULE_CONFIG = "config/rules.yml"


def run_detection(logs: List[LogEvent]) -> Tuple[List[Alert], List[Alert]]:
    rules = load_rules_from_yaml(RULE_CONFIG)
    raw_alerts: List[Alert] = []
    for rule in rules:
        rule_alerts = rule.detect(logs)
        for alert in rule_alerts:
            score = alert_score_from_rule(rule.weight, event_context=0, asset_criticality=1)
            # update severity based on computed score
            alert.severity = score
            raw_alerts.append(alert)
    deduped_alerts = dedup_alerts(raw_alerts)
    return raw_alerts, deduped_alerts
