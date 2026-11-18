import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q
from django.utils import timezone
from django.core.validators import MaxValueValidator, MinValueValidator

from .evidence import (
    PrivateEvidenceStorage,
    evidence_content_type,
    evidence_upload_path,
    validate_evidence_file,
)
from .indicators import normalize_indicator

INCIDENT_TITLE_MAX_LENGTH = 200
INCIDENT_DESCRIPTION_MAX_LENGTH = 5000
INCIDENT_TITLE_REQUIRED_ERROR = "Incident title is required."
INCIDENT_TITLE_NUMERIC_ERROR = (
    "Incident title cannot contain only numbers. Include at least one letter."
)
INCIDENT_TITLE_SPECIAL_ERROR = (
    "Incident title cannot contain only special characters. Include at least one letter."
)
INCIDENT_TITLE_LETTER_ERROR = "Incident title must contain at least one letter."


def has_alphabetic_letter(value):
    return any(character.isalpha() for character in value or "")


def incident_title_error(value):
    normalized = (value or "").strip()
    if not normalized:
        return INCIDENT_TITLE_REQUIRED_ERROR
    if has_alphabetic_letter(normalized):
        return None
    if all(character.isdigit() for character in normalized):
        return INCIDENT_TITLE_NUMERIC_ERROR
    if all(not character.isalnum() for character in normalized):
        return INCIDENT_TITLE_SPECIAL_ERROR
    return INCIDENT_TITLE_LETTER_ERROR


def validate_incident_title(value):
    error = incident_title_error(value)
    if error:
        raise ValidationError(error)


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
    title = models.CharField(
        max_length=INCIDENT_TITLE_MAX_LENGTH,
        error_messages={
            "max_length": "Incident title must be 200 characters or fewer.",
        },
    )
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
        title_error = incident_title_error(self.title)
        if title_error:
            existing_title = (
                type(self).objects.filter(pk=self.pk)
                .values_list("title", flat=True)
                .first()
                if self.pk
                else None
            )
            if existing_title != self.title:
                raise ValidationError({"title": title_error})
        if len(self.description or "") > INCIDENT_DESCRIPTION_MAX_LENGTH:
            existing_description = (
                type(self).objects.filter(pk=self.pk)
                .values_list("description", flat=True)
                .first()
                if self.pk
                else None
            )
            if existing_description != self.description:
                raise ValidationError(
                    {
                        "description": (
                            "Incident description must be 5,000 characters or fewer."
                        )
                    }
                )
        if (
            self.status in (self.Status.RESOLVED, self.Status.CLOSED)
            and not self.resolution_summary.strip()
        ):
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


class IndicatorOfCompromise(models.Model):
    class Type(models.TextChoices):
        IPV4 = "ipv4", "IPv4 address"
        DOMAIN = "domain", "Domain"
        URL = "url", "URL"
        MD5 = "md5", "MD5"
        SHA1 = "sha1", "SHA-1"
        SHA256 = "sha256", "SHA-256"

    class Risk(models.TextChoices):
        CRITICAL = "critical", "Critical"
        HIGH = "high", "High"
        MEDIUM = "medium", "Medium"
        LOW = "low", "Low"
        UNKNOWN = "unknown", "Unknown"

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        CLOSED = "closed", "Closed"
        FALSE_POSITIVE = "false_positive", "False positive"

    class MatchStatus(models.TextChoices):
        UNCHECKED = "unchecked", "Not checked"
        MATCHED = "matched", "Known match"
        UNMATCHED = "unmatched", "No exact match"
        INCONCLUSIVE = "inconclusive", "Inconclusive"

    incident = models.ForeignKey(
        Incident,
        on_delete=models.PROTECT,
        related_name="indicators",
    )
    indicator_type = models.CharField(max_length=8, choices=Type.choices)
    value = models.CharField(max_length=2048)
    normalized_value = models.CharField(max_length=2048, editable=False)
    description = models.TextField(blank=True)
    source = models.CharField(max_length=160)
    confidence = models.PositiveSmallIntegerField(
        default=50,
        validators=(MinValueValidator(0), MaxValueValidator(100)),
    )
    risk = models.CharField(
        max_length=16,
        choices=Risk.choices,
        default=Risk.UNKNOWN,
    )
    date_identified = models.DateTimeField(default=timezone.now)
    notes = models.TextField(blank=True)
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.ACTIVE,
    )
    added_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="added_indicators",
    )
    match_status = models.CharField(
        max_length=16,
        choices=MatchStatus.choices,
        default=MatchStatus.UNCHECKED,
    )
    last_checked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-date_identified", "-pk")
        constraints = [
            models.UniqueConstraint(
                fields=("incident", "indicator_type", "normalized_value"),
                name="unique_normalized_indicator",
            ),
        ]
        indexes = [
            models.Index(fields=("incident", "indicator_type")),
            models.Index(fields=("indicator_type", "normalized_value")),
        ]

    def clean(self):
        super().clean()
        try:
            self.normalized_value = normalize_indicator(
                self.indicator_type,
                self.value,
            )
        except ValidationError as error:
            raise error

    def __str__(self):
        return f"{self.get_indicator_type_display()}: {self.value}"


class ThreatIntelRecord(models.Model):
    indicator_type = models.CharField(
        max_length=8,
        choices=IndicatorOfCompromise.Type.choices,
    )
    value = models.CharField(max_length=2048)
    normalized_value = models.CharField(max_length=2048, editable=False)
    source = models.CharField(max_length=160)
    confidence = models.PositiveSmallIntegerField(
        default=50,
        validators=(MinValueValidator(0), MaxValueValidator(100)),
    )
    classification = models.CharField(max_length=120)
    notes = models.TextField(blank=True)
    last_updated = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_threat_intel_records",
    )

    class Meta:
        ordering = ("-last_updated",)
        constraints = [
            models.UniqueConstraint(
                fields=("indicator_type", "normalized_value", "source"),
                name="unique_threat_intel_source_record",
            ),
        ]
        indexes = [
            models.Index(fields=("indicator_type", "normalized_value")),
        ]

    def clean(self):
        super().clean()
        self.normalized_value = normalize_indicator(
            self.indicator_type,
            self.value,
        )

    def __str__(self):
        return f"{self.source}: {self.value}"


class InvestigationEvidence(models.Model):
    class Classification(models.TextChoices):
        INTERNAL = "internal", "Internal"
        RESTRICTED = "restricted", "Restricted"

    evidence_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    incident = models.ForeignKey(
        Incident,
        on_delete=models.PROTECT,
        related_name="evidence_items",
    )
    file = models.FileField(
        upload_to=evidence_upload_path,
        storage=PrivateEvidenceStorage(),
        max_length=255,
    )
    original_filename = models.CharField(max_length=255, editable=False)
    content_type = models.CharField(max_length=100, blank=True)
    file_size = models.PositiveBigIntegerField(default=0, editable=False)
    description = models.TextField()
    classification = models.CharField(
        max_length=16,
        choices=Classification.choices,
        default=Classification.INTERNAL,
    )
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="uploaded_investigation_evidence",
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-uploaded_at",)

    def clean(self):
        super().clean()
        if self.file:
            self.original_filename, self.file_size = validate_evidence_file(self.file)
            self.content_type = evidence_content_type(self.original_filename)

    def __str__(self):
        return f"{self.original_filename} for incident {self.incident_id}"


class InvestigationFinding(models.Model):
    class Disposition(models.TextChoices):
        CONFIRMED = "confirmed", "Confirmed incident"
        BENIGN = "benign", "Benign activity"
        INCONCLUSIVE = "inconclusive", "Inconclusive"
        OTHER = "other", "Other"

    incident = models.OneToOneField(
        Incident,
        on_delete=models.PROTECT,
        related_name="investigation_finding",
    )
    summary = models.TextField(blank=True)
    findings = models.TextField(blank=True)
    identified_indicators = models.TextField(blank=True)
    evidence_reviewed = models.TextField(blank=True)
    actions_performed = models.TextField(blank=True)
    recommended_remediation = models.TextField(blank=True)
    final_disposition = models.CharField(
        max_length=16,
        choices=Disposition.choices,
        blank=True,
    )
    is_finalized = models.BooleanField(default=False)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_investigation_findings",
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="updated_investigation_findings",
    )
    finalized_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="finalized_investigation_findings",
    )
    finalized_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-updated_at",)

    def clean(self):
        super().clean()
        if self.is_finalized:
            missing = [
                field
                for field in (
                    "summary",
                    "findings",
                    "evidence_reviewed",
                    "actions_performed",
                    "recommended_remediation",
                    "final_disposition",
                )
                if not getattr(self, field).strip()
            ]
            if missing:
                raise ValidationError(
                    {
                        field: "This field is required to finalize the investigation."
                        for field in missing
                    }
                )
            if self.incident_id and self.incident.status not in (
                Incident.Status.RESOLVED,
                Incident.Status.CLOSED,
            ):
                raise ValidationError(
                    {
                        "is_finalized": (
                            "Resolve or close the incident before finalizing findings."
                        )
                    }
                )
            if not self.finalized_by_id:
                raise ValidationError(
                    {"finalized_by": "The user finalizing the findings is required."}
                )

    def __str__(self):
        return f"Findings for incident {self.incident_id}"


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
        UNAUTHORIZED_ACTIVITY = "unauthorized_activity", "Repeated unauthorized activity"
        REPEATED_INCIDENT_REPORTS = "repeated_incident_reports", "Repeated incident reports"
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
    related_incident = models.ForeignKey(
        Incident,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="security_alerts",
    )
    detection_rule = models.ForeignKey(
        "DetectionRule",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="generated_alerts",
    )
    auto_generated = models.BooleanField(default=False)
    dedupe_key = models.CharField(max_length=200, blank=True, db_index=True)
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
        LOGOUT = "logout", "User logout"
        ACCESS_DENIED = "access_denied", "Unauthorized access attempt"
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
        IOC_DISCOVERED = "ioc_discovered", "Indicator discovered"
        IOC_UPDATED = "ioc_updated", "Indicator updated"
        IOC_CHECKED = "ioc_checked", "Indicator threat-intelligence check"
        EVIDENCE_ADDED = "evidence_added", "Investigation evidence added"
        FINDINGS_UPDATED = "findings_updated", "Investigation findings updated"
        THREAT_INTEL_UPDATED = "threat_intel_updated", "Threat-intelligence record updated"
        DETECTION_RULE_UPDATED = "detection_rule_updated", "Detection rule updated"
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


class DetectionRule(models.Model):
    identifier = models.SlugField(max_length=64, unique=True)
    name = models.CharField(max_length=120)
    description = models.CharField(max_length=500)
    enabled = models.BooleanField(default=True)
    threshold = models.PositiveIntegerField(default=5)
    window_seconds = models.PositiveIntegerField(default=300)
    severity = models.CharField(
        max_length=16,
        choices=SecurityAlert.Severity.choices,
        default=SecurityAlert.Severity.HIGH,
    )
    suppression_seconds = models.PositiveIntegerField(default=300)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("identifier",)

    def __str__(self):
        return self.name


class DetectionEvent(models.Model):
    event_key = models.CharField(max_length=120, unique=True)
    event_type = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [models.Index(fields=("event_type", "created_at"))]

    def __str__(self):
        return f"{self.event_type}: {self.event_key}"
