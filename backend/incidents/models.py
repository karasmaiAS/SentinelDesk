import uuid

from django.conf import settings
from django.db import models
from django.db.models import Q


class Incident(models.Model):
    class Severity(models.TextChoices):
        CRITICAL = "critical", "Critical"
        HIGH = "high", "High"
        MEDIUM = "medium", "Medium"
        LOW = "low", "Low"

    class Status(models.TextChoices):
        OPEN = "open", "Open"
        UNDER_INVESTIGATION = "under_investigation", "Under investigation"
        PENDING = "pending", "Pending"
        RESOLVED = "resolved", "Resolved"
        CLOSED = "closed", "Closed"

    class Category(models.TextChoices):
        PHISHING = "phishing", "Phishing"
        MALWARE = "malware", "Malware"
        UNAUTHORIZED_ACCESS = "unauthorized_access", "Unauthorized access"
        SUSPICIOUS_LOGIN = "suspicious_login", "Suspicious login"
        DATA_BREACH = "data_breach", "Data breach"
        SOCIAL_ENGINEERING = "social_engineering", "Social engineering"
        DENIAL_OF_SERVICE = "denial_of_service", "Denial of service"
        OTHER = "other", "Other"

    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    title = models.CharField(max_length=160)
    description = models.TextField()
    category = models.CharField(max_length=32, choices=Category.choices)
    severity = models.CharField(
        max_length=16,
        choices=Severity.choices,
        default=Severity.MEDIUM,
    )
    status = models.CharField(
        max_length=24,
        choices=Status.choices,
        default=Status.OPEN,
    )
    reporter = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="reported_incidents",
    )
    assigned_analyst = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_incidents",
        limit_choices_to={"is_staff": True},
    )
    evidence_reference = models.CharField(max_length=500, blank=True)
    resolution_summary = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at",)
        constraints = [
            models.CheckConstraint(
                condition=Q(severity__in=["critical", "high", "medium", "low"]),
                name="incident_valid_severity",
            ),
            models.CheckConstraint(
                condition=Q(
                    status__in=[
                        "open",
                        "under_investigation",
                        "pending",
                        "resolved",
                        "closed",
                    ]
                ),
                name="incident_valid_status",
            ),
            models.CheckConstraint(
                condition=Q(
                    category__in=[
                        "phishing",
                        "malware",
                        "unauthorized_access",
                        "suspicious_login",
                        "data_breach",
                        "social_engineering",
                        "denial_of_service",
                        "other",
                    ]
                ),
                name="incident_valid_category",
            ),
        ]

    def __str__(self):
        return self.title

    def clean(self):
        super().clean()
        if (
            self.status in (self.Status.RESOLVED, self.Status.CLOSED)
            and not self.resolution_summary.strip()
        ):
            from django.core.exceptions import ValidationError

            raise ValidationError(
                {"resolution_summary": "Resolved incidents need a resolution summary."}
            )


class InvestigationNote(models.Model):
    incident = models.ForeignKey(
        Incident,
        on_delete=models.PROTECT,
        related_name="investigation_notes",
    )
    analyst = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="investigation_notes",
        limit_choices_to={"is_staff": True},
    )
    content = models.TextField(max_length=10000)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("created_at",)

    def __str__(self):
        return f"Note for {self.incident_id} by {self.analyst}"


class LoginAttempt(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="login_attempts",
    )
    username = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    successful = models.BooleanField(default=False)
    attempted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-attempted_at",)
        indexes = [
            models.Index(fields=("ip_address", "attempted_at")),
            models.Index(fields=("username", "attempted_at")),
        ]

    def __str__(self):
        return f"{self.username} at {self.attempted_at}"


class SecurityAlert(models.Model):
    class AlertType(models.TextChoices):
        REPEATED_FAILED_LOGINS = "repeated_failed_logins", "Repeated failed logins"
        SUSPICIOUS_LOGIN = "suspicious_login", "Suspicious login activity"
        MULTIPLE_AUTH_FAILURES = "multiple_auth_failures", "Multiple authentication failures"
        OTHER = "other", "Other"

    class Severity(models.TextChoices):
        CRITICAL = "critical", "Critical"
        HIGH = "high", "High"
        MEDIUM = "medium", "Medium"
        LOW = "low", "Low"

    class Status(models.TextChoices):
        OPEN = "open", "Open"
        INVESTIGATING = "investigating", "Investigating"
        RESOLVED = "resolved", "Resolved"

    title = models.CharField(max_length=160)
    description = models.TextField()
    alert_type = models.CharField(max_length=32, choices=AlertType.choices)
    severity = models.CharField(max_length=16, choices=Severity.choices)
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.OPEN,
    )
    related_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="security_alerts",
    )
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return self.title


class ActivityLog(models.Model):
    class Action(models.TextChoices):
        LOGIN_SUCCESS = "login_success", "Successful login"
        LOGIN_FAILURE = "login_failure", "Failed login"
        INCIDENT_SUBMITTED = "incident_submitted", "Incident submitted"
        INCIDENT_UPDATED = "incident_updated", "Incident updated"
        STATUS_CHANGED = "status_changed", "Incident status changed"
        SEVERITY_CHANGED = "severity_changed", "Incident severity changed"
        ASSIGNMENT_CHANGED = "assignment_changed", "Analyst assignment changed"
        NOTE_ADDED = "note_added", "Investigation note added"
        ACCOUNT_UPDATED = "account_updated", "Account updated"
        ROLE_CHANGED = "role_changed", "User role changed"
        ALERT_CREATED = "alert_created", "Security alert created"
        ALERT_UPDATED = "alert_updated", "Security alert updated"
        OTHER = "other", "Other"

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="sentineldesk_activity",
    )
    incident = models.ForeignKey(
        Incident,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="activity_entries",
    )
    action = models.CharField(max_length=32, choices=Action.choices)
    description = models.CharField(max_length=500)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [models.Index(fields=("-created_at", "action"))]

    def __str__(self):
        return self.get_action_display()
