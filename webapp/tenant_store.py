from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Any

import yaml

from dcc_policy_drift.snapshot import extract_org_id


class TenantStore:
    """Lightweight YAML-backed store for tenant connection details."""

    def __init__(self, path: Path):
        self.path = path
        self.tenants: List[Dict[str, Any]] = []
        self._load()

    # -------------------------------------------------------------
    # Persistence helpers
    # -------------------------------------------------------------

    def _load(self) -> None:
        if self.path.exists():
            self.tenants = yaml.safe_load(self.path.read_text()) or []
        else:
            self.tenants = []

        # Backfill missing keys for older records
        from dcc_policy_drift.rules import RULES
        default_sev = {rid: r["default_severity"] for rid, r in RULES.items()}

        for t in self.tenants:
            if "rule_severities" not in t:
                t["rule_severities"] = default_sev.copy()
            else:
                # ensure all rule ids present
                for rid, r in RULES.items():
                    t["rule_severities"].setdefault(rid, r["default_severity"])

            if "slack_high_severity_only" not in t:
                t["slack_high_severity_only"] = True

    def _save(self) -> None:
        self.path.write_text(yaml.safe_dump(self.tenants, sort_keys=False))

    # -------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------

    def list(self) -> List[Dict[str, Any]]:
        return self.tenants

    def get(self, tenant_id: str) -> Dict[str, Any] | None:
        return next((t for t in self.tenants if t["id"] == tenant_id), None)

    def add(
        self,
        name: str,
        environment: str,
        org_url: str,
        token: str,
        slack_url: str | None = None,
        slack_high_severity_only: bool = True,
    ) -> Dict[str, Any]:
        """Add a new tenant.

        Args:
            name: Friendly tenant name.
            environment: DEV/STAGING/PRODUCTION.
            org_url: Okta org base URL.
            token: Okta API token.
            slack_url: Optional Slack Incoming Webhook URL used for alerts.
        """

        tenant_id = extract_org_id(org_url)
        if self.get(tenant_id):
            raise ValueError(f"Tenant '{tenant_id}' already exists.")
        from dcc_policy_drift.rules import RULES
        default_sev = {rid: r["default_severity"] for rid, r in RULES.items()}

        tenant = {
            "id": tenant_id,
            "name": name,
            "env": environment,
            "org_url": org_url,
            "token": token,
            "slack_url": slack_url,
            "slack_high_severity_only": slack_high_severity_only,
            "rule_severities": default_sev,
        }
        self.tenants.append(tenant)
        self._save()
        return tenant

    # -------------------------------------------------------------
    # Update & delete
    # -------------------------------------------------------------

    def update(self, tenant_id: str, **fields) -> Dict[str, Any]:
        """Update an existing tenant with new field values."""
        tenant = self.get(tenant_id)
        if not tenant:
            raise KeyError("Tenant not found")
        # Only update known keys
        for key in ("name", "env", "org_url", "token", "slack_url", "slack_high_severity_only", "rule_severities"):
            if key in fields and fields[key] is not None:
                tenant[key] = fields[key]
        self._save()
        return tenant

    def delete(self, tenant_id: str) -> None:
        """Remove tenant from store."""
        idx = next((i for i, t in enumerate(self.tenants) if t["id"] == tenant_id), None)
        if idx is None:
            raise KeyError("Tenant not found")
        self.tenants.pop(idx)
        self._save() 

    # Extra helpers for MFA-required apps
    def set_mfa_required(self, tenant_id: str, app_id: str, required: bool):
        t = self.get(tenant_id)
        if not t:
            raise ValueError("Tenant not found")
        apps = set(t.get("mfa_required_apps", []))
        if required:
            apps.add(app_id)
        else:
            apps.discard(app_id)
        t["mfa_required_apps"] = list(apps)
        self._save() 