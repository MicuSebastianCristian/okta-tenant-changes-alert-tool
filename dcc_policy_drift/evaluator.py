from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, List, Dict, Optional

from .diff import DiffResult
from .models import EvaluatedFinding
from .okta_client import OktaClient
from dcc_policy_drift.rules import RULES

logger = logging.getLogger(__name__)


class DriftType:
    """Constants for drift types that trigger HIGH severity alerts."""
    APP_DELETION = "APP_DELETION"
    POLICY_CREATED = "POLICY_CREATED"
    POLICY_DELETED = "POLICY_DELETED"
    SMS_FACTOR_ADDED = "SMS_FACTOR_ADDED"
    SMS_AUTH_RULE_ADDED = "SMS_AUTH_RULE_ADDED"


class DriftEvaluator:
    """Evaluator for detecting drift scenarios."""

    def __init__(self):
        self.high_severity_drift_types = {
            DriftType.APP_DELETION,
            DriftType.POLICY_CREATED,
            DriftType.POLICY_DELETED,
            DriftType.SMS_FACTOR_ADDED,
            DriftType.SMS_AUTH_RULE_ADDED
        }

    def evaluate_drift(
        self,
        diff: DiffResult,
        base_snapshot: dict[str, Any],
        current_snapshot: dict[str, Any],
        severity_map: dict[str, str] | None = None,
    ) -> List[EvaluatedFinding]:
        """Evaluate diff with enhanced detection for HIGH severity scenarios."""
        if diff.is_empty():
            return []

        sev_map = severity_map or {rid: r["default_severity"] for rid, r in RULES.items()}
        findings: List[EvaluatedFinding] = []

        # Process each change in the diff
        for change in diff.changes:
            action = change.get("action")
            obj_type = change.get("object")
            obj_id = change.get("id")

            # Check for app deletion
            if obj_type == "app" and action == "deleted":
                finding = self._create_app_deletion_finding(obj_id, base_snapshot)
                if finding:
                    findings.append(finding)

            # Check for policy creation/deletion
            elif obj_type == "policy":
                if action == "added":
                    finding = self._create_policy_created_finding(obj_id, current_snapshot)
                    if finding:
                        findings.append(finding)
                elif action == "deleted":
                    finding = self._create_policy_deleted_finding(obj_id, base_snapshot)
                    if finding:
                        findings.append(finding)
                elif action == "modified":
                    # Check for SMS factor addition in policy modification
                    sms_finding = self._check_sms_factor_addition(obj_id, base_snapshot,
                                                                 current_snapshot, change)
                    if sms_finding:
                        findings.append(sms_finding)

            # Check for policy rule modifications
            elif obj_type == "policyRule" and action in ["added", "modified"]:
                sms_rule_finding = self._check_sms_auth_rule(obj_id, base_snapshot,
                                                            current_snapshot, change)
                if sms_rule_finding:
                    findings.append(sms_rule_finding)

        # If no specific findings from enhanced evaluator, fall back to basic
        if not findings and diff.changes:
            findings.append(
                EvaluatedFinding(
                    severity=sev_map.get("POLICY_DRIFT", "low").upper(),
                    category="Policy Drift",
                    details=diff.changes,
                )
            )

        return findings

    def _create_app_deletion_finding(self, app_id: str, base_snapshot: dict[str, Any]) -> Optional[EvaluatedFinding]:
        """Create finding for app deletion."""
        deleted_app = self._find_object_by_id(base_snapshot.get("apps", []), app_id)
        if not deleted_app:
            return None

        details = [{
            "driftType": DriftType.APP_DELETION,
            "action": "deleted",
            "resourceType": "application",
            "resourceId": app_id,
            "resourceName": deleted_app.get("label", "Unknown App"),
            "signOnMode": deleted_app.get("signOnMode", "Unknown"),
            "status": deleted_app.get("status", "Unknown"),
            "message": f"Application '{deleted_app.get('label', app_id)}' has been deleted"
        }]

        return EvaluatedFinding(
            severity="HIGH",
            category="Application Deletion",
            details=details
        )

    def _create_policy_created_finding(self, policy_id: str, current_snapshot: dict[str, Any]) -> Optional[EvaluatedFinding]:
        """Create finding for policy creation."""
        created_policy = self._find_object_by_id(current_snapshot.get("policies", []), policy_id)
        if not created_policy:
            return None

        details = [{
            "driftType": DriftType.POLICY_CREATED,
            "action": "added",
            "resourceType": "policy",
            "resourceId": policy_id,
            "resourceName": created_policy.get("name", "Unknown Policy"),
            "policyType": created_policy.get("type", "Unknown"),
            "status": created_policy.get("status", "Unknown"),
            "message": f"New {created_policy.get('type', 'Unknown')} policy '{created_policy.get('name', policy_id)}' has been created"
        }]

        return EvaluatedFinding(
            severity="HIGH",
            category="Policy Creation",
            details=details
        )

    def _create_policy_deleted_finding(self, policy_id: str, base_snapshot: dict[str, Any]) -> Optional[EvaluatedFinding]:
        """Create finding for policy deletion."""
        deleted_policy = self._find_object_by_id(base_snapshot.get("policies", []), policy_id)
        if not deleted_policy:
            return None

        details = [{
            "driftType": DriftType.POLICY_DELETED,
            "action": "deleted",
            "resourceType": "policy",
            "resourceId": policy_id,
            "resourceName": deleted_policy.get("name", "Unknown Policy"),
            "policyType": deleted_policy.get("type", "Unknown"),
            "system": deleted_policy.get("system", False),
            "message": f"{deleted_policy.get('type', 'Unknown')} policy '{deleted_policy.get('name', policy_id)}' has been deleted"
        }]

        return EvaluatedFinding(
            severity="HIGH",
            category="Policy Deletion",
            details=details
        )

    def _check_sms_factor_addition(self, policy_id: str, base_snapshot: dict[str, Any],
                                 current_snapshot: dict[str, Any], change: dict[str, Any]) -> Optional[EvaluatedFinding]:
        """Check if SMS factor was added to a policy."""
        base_policy = self._find_object_by_id(base_snapshot.get("policies", []), policy_id)
        current_policy = self._find_object_by_id(current_snapshot.get("policies", []), policy_id)

        if not base_policy or not current_policy:
            return None

        # Check for SMS factor in MFA_ENROLL policies
        if current_policy.get("type") == "MFA_ENROLL":
            base_factors = base_policy.get("settings", {}).get("factors", {})
            current_factors = current_policy.get("settings", {}).get("factors", {})

            # Check if okta_sms was added or enabled
            base_sms = base_factors.get("okta_sms", {})
            current_sms = current_factors.get("okta_sms", {})

            if self._is_sms_factor_enabled(current_sms) and not self._is_sms_factor_enabled(base_sms):
                return self._create_sms_factor_finding(current_policy, "factors", base_sms, current_sms)

        # Check for SMS in authenticators (newer policy format)
        base_authenticators = base_policy.get("settings", {}).get("authenticators", [])
        current_authenticators = current_policy.get("settings", {}).get("authenticators", [])

        base_sms_auth = self._find_authenticator(base_authenticators, "okta_sms")
        current_sms_auth = self._find_authenticator(current_authenticators, "okta_sms")

        if current_sms_auth and not base_sms_auth:
            return self._create_sms_factor_finding(current_policy, "authenticators", None, current_sms_auth)

        return None

    def _check_sms_auth_rule(self, rule_id: str, base_snapshot: dict[str, Any],
                           current_snapshot: dict[str, Any], change: dict[str, Any]) -> Optional[EvaluatedFinding]:
        """Check if SMS authentication was added to a policy rule."""
        current_rule = self._find_rule_by_id(current_snapshot.get("policyRules", []), rule_id)
        if not current_rule:
            return None

        # Get the policy this rule belongs to
        policy_id = current_rule.get("policyId")
        policy = self._find_object_by_id(current_snapshot.get("policies", []), policy_id)
        if not policy:
            return None

        # Check if this is a new rule with SMS
        if change.get("action") == "added":
            if self._rule_contains_sms(current_rule):
                return self._create_sms_rule_finding(current_rule, policy, "added")

        # Check if SMS was added to an existing rule
        elif change.get("action") == "modified":
            base_rule = self._find_rule_by_id(base_snapshot.get("policyRules", []), rule_id)
            if base_rule and not self._rule_contains_sms(base_rule) and self._rule_contains_sms(current_rule):
                return self._create_sms_rule_finding(current_rule, policy, "modified")

        return None

    def _is_sms_factor_enabled(self, sms_factor: dict[str, Any]) -> bool:
        """Check if SMS factor is enabled."""
        if not sms_factor:
            return False
        enroll = sms_factor.get("enroll", {})
        return enroll.get("self") in ["OPTIONAL", "REQUIRED"]

    def _find_authenticator(self, authenticators: List[dict[str, Any]], key: str) -> Optional[dict[str, Any]]:
        """Find authenticator by key."""
        for auth in authenticators:
            if auth.get("key") == key:
                return auth
        return None

    def _rule_contains_sms(self, rule: dict[str, Any]) -> bool:
        """Check if a policy rule contains SMS authentication requirements."""
        actions = rule.get("actions", {})

        # Check sign-on actions for SMS
        signon = actions.get("signon", {})
        if "sms" in str(signon).lower():
            return True

        # Check app sign-on actions
        app_signon = actions.get("appSignOn", {})
        verification = app_signon.get("verificationMethod", {})

        # Check constraints for SMS-related requirements
        constraints = verification.get("constraints", [])
        for constraint in constraints:
            if "sms" in str(constraint).lower():
                return True

        return False

    def _create_sms_factor_finding(self, policy: dict[str, Any], factor_type: str,
                                 base_state: Any, current_state: Any) -> EvaluatedFinding:
        """Create finding for SMS factor addition."""
        details = [{
            "driftType": DriftType.SMS_FACTOR_ADDED,
            "action": "modified",
            "resourceType": "policy",
            "resourceId": policy.get("id"),
            "resourceName": policy.get("name", "Unknown Policy"),
            "policyType": policy.get("type"),
            "factorType": factor_type,
            "previousState": self._format_factor_state(base_state),
            "currentState": self._format_factor_state(current_state),
            "message": f"SMS authentication factor has been added to policy '{policy.get('name')}'"
        }]

        return EvaluatedFinding(
            severity="HIGH",
            category="SMS Authentication Added",
            details=details
        )

    def _create_sms_rule_finding(self, rule: dict[str, Any], policy: dict[str, Any],
                               action: str) -> EvaluatedFinding:
        """Create finding for SMS authentication in policy rule."""
        details = [{
            "driftType": DriftType.SMS_AUTH_RULE_ADDED,
            "action": action,
            "resourceType": "policyRule",
            "resourceId": rule.get("id"),
            "resourceName": rule.get("name", "Unknown Rule"),
            "policyId": policy.get("id"),
            "policyName": policy.get("name", "Unknown Policy"),
            "policyType": policy.get("type"),
            "message": f"SMS authentication has been {'added to' if action == 'modified' else 'configured in new'} rule '{rule.get('name')}' in policy '{policy.get('name')}'"
        }]

        return EvaluatedFinding(
            severity="HIGH",
            category="SMS Authentication Rule Added",
            details=details
        )

    def _format_factor_state(self, state: Any) -> str:
        """Format factor state for display."""
        if not state:
            return "NOT_CONFIGURED"
        if isinstance(state, dict):
            enroll = state.get("enroll", {})
            return enroll.get("self", "NOT_CONFIGURED")
        return str(state)

    def _find_object_by_id(self, objects: List[dict[str, Any]], obj_id: str) -> Optional[dict[str, Any]]:
        """Find object in list by ID."""
        for obj in objects:
            if obj.get("id") == obj_id:
                return obj
        return None

    def _find_rule_by_id(self, rules: List[dict[str, Any]], rule_id: str) -> Optional[dict[str, Any]]:
        """Find rule in list by ID."""
        for rule in rules:
            if rule.get("id") == rule_id:
                return rule
        return None


def evaluate_mfa_less(client: OktaClient, since_ts: str, severity_map: dict[str, str] | None = None) -> List[EvaluatedFinding]:
    from dcc_policy_drift.rules import RULES as _RULES
    sev_map = severity_map or {rid: r["default_severity"] for rid, r in _RULES.items()}
    try:
        anomalies = client.get_mfa_less_logins(since_ts)
    except RuntimeError as exc:
        # Gracefully handle Okta rate limiting on the System Log endpoint
        logger.warning("MFA-less detection skipped due to error: %s", exc)
        return []
    if not anomalies:
        return []
    return [
        EvaluatedFinding(
            severity=sev_map.get("MFA_LESS_SUCCESS", "low").upper(),
            category="MFA-less Success",
            details=anomalies,
        )
    ]