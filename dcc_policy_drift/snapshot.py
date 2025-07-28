from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List

from .config import settings
from .okta_client import OktaClient

SNAPSHOT_VERSION = 1


def take_snapshot(client: OktaClient) -> dict[str, Any]:

    POLICY_TYPES = [
        "OKTA_SIGN_ON",  # sign-on policies
        "MFA_ENROLL",    # MFA enrollment
        "SESSION",       # session lifetime policies
        "ACCESS_POLICY", # application access policies
        "PASSWORD",      # password policies
        "IDP_DISCOVERY", # IdP routing rules
    ]

    policies: List[dict[str, Any]] = []
    for p_type in POLICY_TYPES:
        policies.extend(client.get_policies(p_type))

    rules = collect_policy_rules(client, policies)

    snapshot = {
        "snapshotId": str(uuid.uuid4()),
        "orgId": extract_org_id(client.base_url),
        "takenAt": datetime.now(timezone.utc).isoformat(),
        "version": SNAPSHOT_VERSION,
        "policies": policies,
        "policyRules": rules,
        "apps": client.get_apps(),
        "idps": client.get_idps(),
    }
    return snapshot


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------


def collect_policy_rules(client: OktaClient, policies: List[dict[str, Any]]) -> List[dict[str, Any]]:
    """Return combined list of rules for given policies.

    We first look for rules in the `_embedded` object (when `expand=rules` is supported).
    For any policy where rules are missing, we fall back to an explicit
    `/api/v1/policies/{id}/rules` call.
    """

    all_rules: List[dict[str, Any]] = []
    for policy in policies:
        embedded = policy.get("_embedded", {})
        if "rules" in embedded and embedded["rules"]:
            for r in embedded["rules"]:
                r = dict(r)  # shallow copy
                r["policyId"] = policy["id"]
                all_rules.append(r)
        else:
            # Fallback – explicit fetch (costly but required to capture rule changes)
            try:
                for r in client.get_policy_rules(policy["id"]):
                    r = dict(r)
                    r["policyId"] = policy["id"]
                    all_rules.append(r)
            except Exception as exc:  # pragma: no cover
                # Log and continue; better to miss a rule than break entire snapshot
                import logging

                logging.getLogger(__name__).warning(
                    "Failed to fetch rules for policy %s: %s", policy.get("id"), exc
                )
    return all_rules


def store_snapshot(snapshot: dict[str, Any], directory: Path | None = None, name: str | None = None) -> Path:
    """Persist snapshot to JSON.

    If *name* provided, use it (spaces converted to underscore, lower-cased) instead of the random UUID.
    """
    directory = directory or settings.snapshot_dir
    directory.mkdir(parents=True, exist_ok=True)
    if name:
        safe_name = name.strip().replace(" ", "_").lower()
    else:
        # Default naming: YYYY-MM-DD_<snapshotId>
        date_part = snapshot["takenAt"][:10]  # ISO date
        safe_name = f"{date_part}_{snapshot['snapshotId']}"
    file_path = directory / f"{safe_name}.json"
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2)
    return file_path


def extract_org_id(org_url: str) -> str:
    # Okta org URL format: https://dev-123456.okta.com
    # We'll use subdomain without okta.com
    return org_url.split("//")[1].split(".")[0] 