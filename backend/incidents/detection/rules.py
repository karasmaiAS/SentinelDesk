from datetime import timedelta

from django.utils import timezone

from incidents.models import (
    ActivityLog,
    DetectionRule,
    Incident,
    LoginAttempt,
    SecurityAlert,
)


def _window_start(event_time, seconds):
    return event_time - timedelta(seconds=seconds)


def failed_login_counts(attempt, rule):
    event_time = attempt.attempted_at or timezone.now()
    attempts = LoginAttempt.objects.filter(
        successful=False,
        attempted_at__gte=_window_start(event_time, rule.window_seconds),
        attempted_at__lte=event_time,
    )
    matching = []
    account_triggered = False
    if attempt.username:
        account_attempts = attempts.filter(username__iexact=attempt.username)
        account_count = account_attempts.count()
        if account_count >= rule.threshold:
            account_triggered = True
            matched_attempt = (
                account_attempts.exclude(user__isnull=True)
                .select_related("user")
                .first()
            )
            matching.append(
                {
                    "scope": f"account:{attempt.username.casefold()}",
                    "count": account_count,
                    "related_user": attempt.user
                    or (matched_attempt.user if matched_attempt else None),
                    "source_ip": attempt.ip_address,
                    "account": attempt.username,
                }
            )
    if attempt.ip_address and not account_triggered:
        ip_attempts = attempts.filter(ip_address=attempt.ip_address)
        ip_count = ip_attempts.count()
        if ip_count >= rule.threshold:
            matching.append(
                {
                    "scope": f"ip:{attempt.ip_address}",
                    "count": ip_count,
                    "related_user": attempt.user,
                    "source_ip": attempt.ip_address,
                    "account": attempt.username or "unknown account",
                }
            )
    return matching


def preceding_login_failures(attempt, rule):
    event_time = attempt.attempted_at or timezone.now()
    attempts = LoginAttempt.objects.filter(
        successful=False,
        username__iexact=attempt.username,
        attempted_at__gte=_window_start(event_time, rule.window_seconds),
        attempted_at__lt=event_time,
    )
    if attempt.ip_address:
        attempts = attempts.filter(ip_address=attempt.ip_address)
    return attempts.count()


def suspicious_ip_failures(attempt, rule):
    if not attempt.ip_address:
        return 0, 0
    event_time = attempt.attempted_at or timezone.now()
    attempts = LoginAttempt.objects.filter(
        successful=False,
        ip_address=attempt.ip_address,
        attempted_at__gte=_window_start(event_time, rule.window_seconds),
        attempted_at__lte=event_time,
    )
    return attempts.count(), attempts.values("username").distinct().count()


def unauthorized_activity_count(entry, rule):
    event_time = entry.created_at or timezone.now()
    entries = ActivityLog.objects.filter(
        action=ActivityLog.Action.ACCESS_DENIED,
        created_at__gte=_window_start(event_time, rule.window_seconds),
        created_at__lte=event_time,
    )
    if entry.actor_id:
        entries = entries.filter(actor_id=entry.actor_id)
        scope = f"user:{entry.actor_id}"
    elif entry.source_ip:
        entries = entries.filter(source_ip=entry.source_ip)
        scope = f"ip:{entry.source_ip}"
    else:
        return 0, ""
    if entry.source_ip:
        entries = entries.filter(source_ip=entry.source_ip)
    return entries.count(), scope


def repeated_incident_count(incident, rule):
    incidents = Incident.objects.filter(
        reporter_id=incident.reporter_id,
        category=incident.category,
        created_at__gte=_window_start(
            incident.created_at or timezone.now(),
            rule.window_seconds,
        ),
    )
    return incidents.count()


def alert_type_for_rule(identifier):
    mapping = {
        "multiple_failed_logins": SecurityAlert.AlertType.REPEATED_FAILED_LOGINS,
        "successful_login_after_failures": SecurityAlert.AlertType.SUSPICIOUS_LOGIN,
        "repeated_suspicious_login_activity": SecurityAlert.AlertType.MULTIPLE_AUTH_FAILURES,
        "repeated_unauthorized_activity": SecurityAlert.AlertType.UNAUTHORIZED_ACTIVITY,
        "repeated_incident_reports": SecurityAlert.AlertType.REPEATED_INCIDENT_REPORTS,
    }
    return mapping[identifier]


def get_enabled_rule(identifier):
    return DetectionRule.objects.filter(identifier=identifier, enabled=True).first()
