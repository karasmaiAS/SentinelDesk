from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction

from accounts.roles import can_investigate, is_administrator, is_analyst

from .models import ActivityLog, Incident, InvestigationNote, LoginAttempt, SecurityAlert

STATUS_TRANSITIONS = {
    Incident.Status.OPEN: {Incident.Status.UNDER_INVESTIGATION},
    Incident.Status.UNDER_INVESTIGATION: {
        Incident.Status.PENDING,
        Incident.Status.RESOLVED,
    },
    Incident.Status.PENDING: {
        Incident.Status.UNDER_INVESTIGATION,
        Incident.Status.RESOLVED,
    },
    Incident.Status.RESOLVED: {Incident.Status.CLOSED},
    Incident.Status.CLOSED: set(),
}


def request_ip(request):
    if request is None:
        return None
    return request.META.get("REMOTE_ADDR")


def log_activity(*, action, description, actor=None, incident=None, request=None):
    return ActivityLog.objects.create(
        actor=actor,
        incident=incident,
        action=action,
        description=description[:500],
        source_ip=request_ip(request),
    )


def create_incident(*, reporter, data, request=None):
    incident = Incident(
        reporter=reporter,
        title=data["title"],
        description=data["description"],
        category=data["category"],
        severity=data["severity"],
        evidence_reference=data.get("evidence_reference", ""),
    )
    incident.full_clean()
    with transaction.atomic():
        incident.save()
        log_activity(
            action=ActivityLog.Action.INCIDENT_SUBMITTED,
            description=f"Incident {incident.public_id} submitted.",
            actor=reporter,
            incident=incident,
            request=request,
        )
    return incident


def update_incident(*, actor, incident, changes, request=None):
    if not is_administrator(actor) and not can_investigate(actor, incident):
        raise PermissionDenied("You are not authorized to update this incident.")

    allowed = {"status", "severity", "resolution_summary"}
    if set(changes) - allowed:
        raise ValidationError("Unsupported incident fields.")
    if "severity" in changes and not is_administrator(actor):
        raise PermissionDenied("Only administrators can change incident severity.")

    old_status = incident.status
    old_severity = incident.severity
    new_status = changes.get("status", old_status)
    if new_status not in Incident.Status.values:
        raise ValidationError({"status": "Select a valid incident status."})
    if new_status != old_status and new_status not in STATUS_TRANSITIONS[old_status]:
        raise ValidationError(
            {"status": f"Cannot move an incident from {old_status} to {new_status}."}
        )
    if new_status == Incident.Status.RESOLVED and not (
        changes.get("resolution_summary", incident.resolution_summary).strip()
    ):
        raise ValidationError(
            {"resolution_summary": "Provide a resolution summary before resolving."}
        )

    for field, value in changes.items():
        setattr(incident, field, value)
    incident.full_clean()

    with transaction.atomic():
        incident.save()
        if incident.status != old_status:
            log_activity(
                action=ActivityLog.Action.STATUS_CHANGED,
                description=f"Status changed from {old_status} to {incident.status}.",
                actor=actor,
                incident=incident,
                request=request,
            )
        if incident.severity != old_severity:
            log_activity(
                action=ActivityLog.Action.SEVERITY_CHANGED,
                description=f"Severity changed from {old_severity} to {incident.severity}.",
                actor=actor,
                incident=incident,
                request=request,
            )
        if set(changes) - {"status", "severity"}:
            log_activity(
                action=ActivityLog.Action.INCIDENT_UPDATED,
                description="Incident resolution information updated.",
                actor=actor,
                incident=incident,
                request=request,
            )
    return incident


@transaction.atomic
def assign_incident(*, actor, incident, analyst, request=None):
    if not is_administrator(actor):
        raise PermissionDenied("Only administrators can assign incidents.")
    if analyst is not None and not (
        analyst.is_active and is_analyst(analyst)
    ):
        raise ValidationError({"analyst": "Choose an active security analyst."})

    previous_analyst = incident.assigned_analyst
    if previous_analyst == analyst:
        return incident
    previous_status = incident.status
    incident.assigned_analyst = analyst
    if analyst and incident.status == Incident.Status.OPEN:
        incident.status = Incident.Status.UNDER_INVESTIGATION
    incident.full_clean()
    incident.save()
    previous_name = previous_analyst.username if previous_analyst else "unassigned"
    next_name = analyst.username if analyst else "unassigned"
    log_activity(
        action=ActivityLog.Action.ASSIGNMENT_CHANGED,
        description=f"Assignment changed from {previous_name} to {next_name}.",
        actor=actor,
        incident=incident,
        request=request,
    )
    if incident.status != previous_status:
        log_activity(
            action=ActivityLog.Action.STATUS_CHANGED,
            description=(
                f"Status changed from {previous_status} to {incident.status} "
                "when an analyst was assigned."
            ),
            actor=actor,
            incident=incident,
            request=request,
        )
    return incident


@transaction.atomic
def add_investigation_note(*, actor, incident, content, request=None):
    if not can_investigate(actor, incident):
        raise PermissionDenied("Only the assigned analyst or an administrator can add notes.")
    note = InvestigationNote(
        incident=incident,
        analyst=actor,
        content=content.strip(),
    )
    note.full_clean()
    note.save()
    log_activity(
        action=ActivityLog.Action.NOTE_ADDED,
        description=f"Investigation note added to incident {incident.public_id}.",
        actor=actor,
        incident=incident,
        request=request,
    )
    return note


@transaction.atomic
def create_security_alert(
    *,
    actor=None,
    title,
    description,
    alert_type,
    severity,
    related_user=None,
    related_incident=None,
    source_ip=None,
    detection_rule=None,
    dedupe_key="",
    auto_generated=False,
    event_time=None,
    request=None,
):
    alert = SecurityAlert(
        title=title,
        description=description,
        alert_type=alert_type,
        severity=severity,
        related_user=related_user,
        related_incident=related_incident,
        detection_rule=detection_rule,
        dedupe_key=dedupe_key,
        auto_generated=auto_generated,
        source_ip=source_ip,
    )
    alert.full_clean()
    alert.save()
    log_activity(
        action=ActivityLog.Action.ALERT_CREATED,
        description=f"Security alert created: {alert.title}.",
        actor=actor,
        request=request,
    )
    return alert


@transaction.atomic
def update_security_alert_status(*, actor, alert, status, request=None):
    if not is_administrator(actor):
        raise PermissionDenied("Only administrators can update security alerts.")
    if status not in SecurityAlert.Status.values:
        raise ValidationError({"status": "Select a valid alert status."})
    previous_status = alert.status
    if status == previous_status:
        return alert
    alert.status = status
    alert.full_clean()
    alert.save(update_fields=("status", "updated_at"))
    log_activity(
        action=ActivityLog.Action.ALERT_UPDATED,
        description=(
            f"Alert {alert.title} status changed from "
            f"{previous_status} to {status}."
        ),
        actor=actor,
        request=request,
    )
    return alert


def record_login_attempt(*, username, user=None, successful, request=None):
    ip_address = request_ip(request)
    attempt = LoginAttempt.objects.create(
        username=username[:150],
        user=user,
        ip_address=ip_address,
        successful=successful,
    )
    action = (
        ActivityLog.Action.LOGIN_SUCCESS
        if successful
        else ActivityLog.Action.LOGIN_FAILURE
    )
    log_activity(
        action=action,
        description=(
            f"Successful login for {username[:150]}."
            if successful
            else f"Failed login for {username[:150]}."
        ),
        actor=user if successful else None,
        request=request,
    )
    return attempt
