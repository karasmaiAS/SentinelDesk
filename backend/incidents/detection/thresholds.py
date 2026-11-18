RULE_DEFINITIONS = (
    {
        "identifier": "multiple_failed_logins",
        "name": "Multiple failed login attempts",
        "description": (
            "Detect repeated sign-in failures against one account or from one IP."
        ),
        "threshold": 5,
        "window_seconds": 300,
        "severity": "high",
        "suppression_seconds": 300,
    },
    {
        "identifier": "successful_login_after_failures",
        "name": "Successful login after repeated failures",
        "description": (
            "Detect a successful sign-in following repeated failures for the "
            "same account and, when available, source IP."
        ),
        "threshold": 5,
        "window_seconds": 300,
        "severity": "high",
        "suppression_seconds": 300,
    },
    {
        "identifier": "repeated_suspicious_login_activity",
        "name": "Repeated suspicious login activity",
        "description": (
            "Detect one source IP generating failures against multiple accounts."
        ),
        "threshold": 3,
        "window_seconds": 300,
        "severity": "high",
        "suppression_seconds": 600,
    },
    {
        "identifier": "repeated_unauthorized_activity",
        "name": "Repeated unauthorized activity",
        "description": (
            "Detect repeated API permission-denied events from one account or IP."
        ),
        "threshold": 3,
        "window_seconds": 600,
        "severity": "high",
        "suppression_seconds": 600,
    },
    {
        "identifier": "repeated_incident_reports",
        "name": "Repeated incident reports",
        "description": (
            "Flag repeated reports from one account in the same category for "
            "analyst review; this is not proof that reports are duplicates."
        ),
        "threshold": 3,
        "window_seconds": 3600,
        "severity": "medium",
        "suppression_seconds": 3600,
    },
)
