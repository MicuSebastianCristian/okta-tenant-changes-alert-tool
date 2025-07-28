from __future__ import annotations
from datetime import datetime, timezone
from typing import Any

class EvaluatedFinding:
    def __init__(self, severity: str, category: str, details: list[dict[str, Any]]):
        self.severity = severity
        self.category = category
        self.details = details
        self.detected_at = datetime.now(timezone.utc).isoformat()

    def to_payload(self, tenant: str, snapshot_name: str | None = None) -> dict[str, Any]:
        payload = {
            "tenant": tenant,
            "severity": self.severity,
            "detectedAt": self.detected_at,
            "category": self.category,
            "details": self.details,
            "nextSteps": "Review and remediate or promote baseline.",
        }
        if snapshot_name:
            payload["snapshotName"] = snapshot_name
        return payload