import json
from datetime import datetime
from pathlib import Path
from typing import List

from core.models import Alert, Incident


def build_incident(alerts: List[Alert], input_path: str) -> Incident:
    now = datetime.utcnow()
    observables = []
    timeline = []
    for idx, alert in enumerate(alerts, start=1):
        observables.append({
            "id": f"obs-{idx}",
            "type": "ip" if alert.src_ip else "user",
            "value": str(alert.src_ip or alert.user),
            "source": alert.rule,
        })
        timeline.append(
            {
                "id": f"event-{idx}",
                "timestamp": alert.timestamp.isoformat() if alert.timestamp else now.isoformat(),
                "description": alert.message,
                "rule": alert.rule,
                "severity": alert.severity.value,
            }
        )

    return Incident(
        incident_id=f"incident-{now.strftime('%Y%m%d%H%M%S')}",
        input_file=str(input_path),
        generated_at=now,
        alerts=alerts,
        timeline=timeline,
        observables=observables,
        recommendations=[
            "Investigate the top severity alerts first.",
            "Confirm the user session and IP activity.",
            "Check related logs for lateral movement.",
        ],
    )


def save_incident(incident: Incident, output_path: Path):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(incident.dict(), f, indent=2, ensure_ascii=False, default=str)
