# Rule definitions and defaults
RULES = {
    "LOGIN_NO_MFA_MANDATORY_APP": {
        "title": "Login without MFA to mandatory application",
        "default_severity": "low",
        "description": "Successful auth to an app marked as mandatory without MFA challenge.",
    },
    "LOGIN_NO_MFA": {
        "title": "Login without MFA",
        "default_severity": "low",
        "description": "Successful auth to any application without MFA challenge.",
    },
    "NO_FACTORS": {
        "title": "User has no MFA factors",
        "default_severity": "low",
        "description": "User logged-in successfully but has no enrolled MFA factors.",
    },
    "UNKNOWN_DEVICE_SMS_EMAIL_OTP": {
        "title": "Untrusted device with SMS/Email OTP",
        "default_severity": "low",
        "description": "device.assurance == UNKNOWN and authenticator is SMS or Email OTP.",
    },
}

RULES.update({
    "POLICY_DRIFT": {
        "title": "General Policy Drift (fallback)",
        "default_severity": "low",
        "description": "Any diff between baseline and current snapshot that is not caught by a specific rule.",
    },
    "APPLICATION_DELETION": {
        "title": "Application deleted",
        "default_severity": "low",
        "description": "An application present in baseline no longer exists in the tenant.",
    },
    "POLICY_CREATED": {
        "title": "Policy created",
        "default_severity": "low",
        "description": "A brand-new policy was added (sign-on, MFA enrol, etc.).",
    },
    "POLICY_DELETED": {
        "title": "Policy deleted",
        "default_severity": "low",
        "description": "An existing policy has been removed.",
    },
    "SMS_FACTOR_ADDED": {
        "title": "SMS factor enabled",
        "default_severity": "low",
        "description": "SMS authentication factor was enabled in an MFA Enrol policy.",
    },
    "SMS_AUTH_RULE_ADDED": {
        "title": "SMS authenticator added to rule",
        "default_severity": "low",
        "description": "A policy rule was created/updated to allow SMS authenticator.",
    },
    "MFA_LESS_SUCCESS": {
        "title": "MFA-less successful login (API)",
        "default_severity": "low",
        "description": "System Log event: user.session.start with factors == NONE (API-based check).",
    },
}) 