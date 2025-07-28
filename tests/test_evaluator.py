import unittest
from dcc_policy_drift.evaluator import DriftEvaluator
from dcc_policy_drift.diff import DiffResult

class TestDriftEvaluator(unittest.TestCase):
    def setUp(self):
        self.evaluator = DriftEvaluator()

    def test_app_deletion(self):
        base_snapshot = {
            "apps": [
                {"id": "1", "label": "Test App", "signOnMode": "SAML_2_0", "status": "ACTIVE"}
            ]
        }
        diff = DiffResult(
            changes=[
                {
                    "action": "deleted",
                    "object": "app",
                    "id": "1"
                }
            ]
        )
        findings = self.evaluator.evaluate_drift(diff, base_snapshot, {})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "Application Deletion")
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[0].details[0]["driftType"], "APP_DELETION")

    def test_policy_creation(self):
        current_snapshot = {
            "policies": [
                {"id": "1", "name": "Test Policy", "type": "MFA_ENROLL", "status": "ACTIVE"}
            ]
        }
        diff = DiffResult(
            changes=[
                {
                    "action": "added",
                    "object": "policy",
                    "id": "1"
                }
            ]
        )
        findings = self.evaluator.evaluate_drift(diff, {}, current_snapshot)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "Policy Creation")
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[0].details[0]["driftType"], "POLICY_CREATED")

    def test_policy_deletion(self):
        base_snapshot = {
            "policies": [
                {"id": "1", "name": "Test Policy", "type": "MFA_ENROLL", "system": False}
            ]
        }
        diff = DiffResult(
            changes=[
                {
                    "action": "deleted",
                    "object": "policy",
                    "id": "1"
                }
            ]
        )
        findings = self.evaluator.evaluate_drift(diff, base_snapshot, {})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "Policy Deletion")
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[0].details[0]["driftType"], "POLICY_DELETED")

    def test_sms_factor_added(self):
        base_snapshot = {
            "policies": [
                {
                    "id": "1",
                    "name": "Test Policy",
                    "type": "MFA_ENROLL",
                    "settings": {"factors": {"okta_sms": {"enroll": {"self": "DISABLED"}}}},
                }
            ]
        }
        current_snapshot = {
            "policies": [
                {
                    "id": "1",
                    "name": "Test Policy",
                    "type": "MFA_ENROLL",
                    "settings": {"factors": {"okta_sms": {"enroll": {"self": "REQUIRED"}}}},
                }
            ]
        }
        diff = DiffResult(
            changes=[
                {
                    "action": "modified",
                    "object": "policy",
                    "id": "1"
                }
            ]
        )
        findings = self.evaluator.evaluate_drift(
            diff, base_snapshot, current_snapshot
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "SMS Authentication Added")
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[0].details[0]["driftType"], "SMS_FACTOR_ADDED")

    def test_sms_auth_rule_added(self):
        current_snapshot = {
            "policies": [
                {"id": "p1", "name": "Test Policy", "type": "MFA_ENROLL"}
            ],
            "policyRules": [
                {
                    "id": "r1",
                    "policyId": "p1",
                    "name": "Test Rule",
                    "actions": {"signon": {"access": "ALLOW", "requireFactor": True, "factors": [{"provider": "OKTA", "factorType": "sms"}]}},
                }
            ]
        }
        diff = DiffResult(
            changes=[
                {
                    "action": "added",
                    "object": "policyRule",
                    "id": "r1"
                }
            ]
        )
        findings = self.evaluator.evaluate_drift(diff, {}, current_snapshot)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "SMS Authentication Rule Added")
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[0].details[0]["driftType"], "SMS_AUTH_RULE_ADDED")

    def test_empty_diff(self):
        diff = DiffResult(changes=[])
        findings = self.evaluator.evaluate_drift(diff, {}, {})
        self.assertEqual(len(findings), 0)

    def test_generic_drift(self):
        diff = DiffResult(
            changes=[
                {
                    "change_type": "value_changed",
                    "path": "some.other.path",
                    "old_value": "a",
                    "new_value": "b",
                }
            ]
        )
        findings = self.evaluator.evaluate_drift(diff, {}, {})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "Policy Drift")


if __name__ == "__main__":
    unittest.main()