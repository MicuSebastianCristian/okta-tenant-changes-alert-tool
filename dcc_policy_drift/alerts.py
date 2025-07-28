from __future__ import annotations

import json
import logging
import smtplib
from email.mime.text import MIMEText
from typing import Any

import requests

from .config import settings

logger = logging.getLogger(__name__)


class AlertDispatcher:
    """Dispatches alerts to configured channels."""

    def __init__(self, *, slack_high_severity_only: bool = True):
        """Initialize the alert dispatcher.
        
        Args:
            slack_high_severity_only: If True, only send HIGH severity alerts to Slack
        """
        self.slack_high_severity_only = slack_high_severity_only

    def dispatch(self, payload: dict[str, Any]) -> None:
        severity = payload["severity"]
        subject = f"[Okta Drift] {severity}: {payload['category']}"
        text = json.dumps(payload, indent=2, default=str)

        if settings.smtp_host and settings.smtp_to and settings.smtp_from:
            self._send_email(subject, text)
        
        # Apply severity filtering for Slack
        if settings.slack_webhook_url and (not self.slack_high_severity_only or severity.upper() == "HIGH"):
            self._post_webhook(settings.slack_webhook_url, payload)
            logger.info("HIGH severity alert sent to Slack: %s", payload.get('category'))
        else:
            logger.debug("Skipping Slack notification for %s severity: %s",
                       severity, payload.get('category'))
        
        if settings.teams_webhook_url:
            self._post_webhook(settings.teams_webhook_url, payload)

    # ---------------- helpers ----------------
    def _send_email(self, subject: str, body: str) -> None:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = settings.smtp_from
        msg["To"] = settings.smtp_to
        try:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as smtp:
                if settings.smtp_username and settings.smtp_password:
                    smtp.starttls()
                    smtp.login(settings.smtp_username, settings.smtp_password)
                smtp.send_message(msg)
                logger.info("Alert email sent to %s", settings.smtp_to)
        except Exception as exc:
            logger.error("Failed to send alert email: %s", exc)

    def _post_webhook(self, url: str, payload: dict[str, Any]) -> None:
        # Slack Incoming Webhooks require a top-level "text" or "blocks" field.
        # Detect Slack URL heuristically and wrap the payload accordingly.
        if "hooks.slack.com" in url:
            body = {
                "text": f"```{json.dumps(payload, indent=2, default=str)}```"
            }
        else:
            body = json.loads(json.dumps(payload, default=str))  # ensure serializable

        try:
            resp = requests.post(url, json=body, timeout=10)
            resp.raise_for_status()
            logger.info("Alert posted to webhook %s", url)
        except Exception as exc:
            logger.error("Failed posting alert to webhook %s: %s", url, exc) 