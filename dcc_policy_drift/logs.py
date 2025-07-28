from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, List
import csv, io


class LogFinding:
    def __init__(self, time: str, user: str, app: str, issue: str, severity: str, raw: dict[str, Any]):
        self.time = time
        self.user = user
        self.app = app
        self.issue = issue
        self.severity = severity
        self.raw = raw

    def to_payload(self, org_url: str) -> dict[str, Any]:
        return {
            "tenant": org_url,
            "severity": self.severity.upper(),
            "detectedAt": self.time,
            "category": "Login Outlier",
            "details": {
                "user": self.user,
                "app": self.app,
                "issue": self.issue,
            },
            "raw": self.raw,
        }


class LogsAnalyzer:
    """Analyze Okta log events for MFA-less logins and other outliers."""

    def __init__(self, mfa_required_apps: set[str] | None = None):
        self.mfa_required_apps = mfa_required_apps or set()

    def analyze(
        self,
        events: list[dict[str, Any]],
        users_without_mfa: set[str] | None = None,
        severity_map: dict[str, str] | None = None,
    ) -> List[LogFinding]:

        from .rules import RULES
        sev_map = severity_map or {rid: r["default_severity"] for rid, r in RULES.items()}

        findings: list[LogFinding] = []
        for ev in events:
            outcome = ev.get("outcome", {}).get("result")
            if outcome != "SUCCESS":
                continue

            auth_ctx = ev.get("authenticationContext", {})
            mfa_required = auth_ctx.get("authenticationStep") == 2 or auth_ctx.get("authenticator", {}).get("type") == "mfa"

            # Extract helper fields for additional rules
            auth_type = auth_ctx.get("authenticator", {}).get("type")
            device_assurance = (
                ev.get("debugContext", {})
                .get("debugData", {})
                .get("device.assurance")
            )

            user = ev.get("actor", {}).get("alternateId") or ev.get("actor", {}).get("displayName")
            app_id = ev.get("target", [{}])[0].get("id", "unknown")
            app_name = ev.get("target", [{}])[0].get("displayName", "Unknown App")
            timestamp = ev.get("published")

            # Rule 1: Login without MFA when step==1
            if not mfa_required:
                severity = sev_map.get("LOGIN_NO_MFA_MANDATORY_APP") if app_id in self.mfa_required_apps else sev_map.get("LOGIN_NO_MFA")
                findings.append(LogFinding(timestamp, user, app_name, "Login without MFA", severity, ev))

            # Rule 2: user with no factors but login occurred
            if users_without_mfa and user in users_without_mfa:
                findings.append(
                    LogFinding(
                        timestamp,
                        user,
                        app_name,
                        "User has no MFA factors",
                        sev_map.get("NO_FACTORS", "low"),
                        ev,
                    )
                )

            # Rule 3: Device assurance unknown with weak OTP factors (LOW severity)
            if device_assurance == "UNKNOWN" and auth_type in ("sms_otp", "email_otp"):
                findings.append(
                    LogFinding(
                        timestamp,
                        user,
                        app_name,
                        "Login from untrusted device using SMS/Email OTP",
                        sev_map.get("UNKNOWN_DEVICE_SMS_EMAIL_OTP", "low"),
                        ev,
                    )
                )
                
        return findings


def csv_to_events(file_obj) -> list[dict[str, Any]]:
    """Convert CSV bytes or file-like object into list[dict] shaped like Okta API events."""
    raw = file_obj.read() if hasattr(file_obj, "read") else file_obj
    if isinstance(raw, bytes):
        data = raw.decode("utf-8", errors="ignore")
    else:
        data = raw
    reader = csv.DictReader(io.StringIO(data))
    events: list[dict[str, Any]] = []
    for row in reader:
        ev = {
            "published": row.get("timestamp"),
            "outcome": {"result": row.get("outcome.result")},
            "actor": {
                "id": row.get("actor.id"),
                "type": row.get("actor.type"),
                "alternateId": row.get("actor.alternate_id"),
                "displayName": row.get("actor.display_name"),
            },
            "authenticationContext": {
                "authenticationStep": int(row.get("authentication_context.authentication_step") or 0),
                "authenticator": {"type": row.get("authentication_context.authenticator.type")},
            },
            "debugContext": {
                "debugData": {
                    "device.assurance": row.get("debug_context.debug_data.device.assurance"),
                }
            },
            "eventType": row.get("event_type"),
            "target": [
                {
                    "id": row.get("target0.id"),
                    "displayName": row.get("target0.display_name"),
                }
            ]
        }
        events.append(ev)
    return events 