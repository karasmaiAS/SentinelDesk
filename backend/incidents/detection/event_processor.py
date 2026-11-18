import logging
from datetime import timedelta

from django.db import IntegrityError, transaction
from django.utils import timezone

from incidents.models import (
    ActivityLog,
    DetectionEvent,
    Incident,
    LoginAttempt,
    SecurityAlert,
)

from .rules import (
    alert_type_for_rule,
    failed_login_counts,
    get_enabled_rule,
    preceding_login_failures,
    repeated_incident_count,
    suspicious_ip_failures,
    unauthorized_activity_count,
)


logger = logging.getLogger(__name__)


def _claim_event(event_type, event_key):
    try:
        event, created = DetectionEvent.objects.get_or_create(
            event_key=event_key,
            defaults={"event_type": event_type},
        )
    except IntegrityError:
        event = DetectionEvent.objects.get(event_key=event_key)
        created = False
    return event, created or event.processed_at is None


def _emit_alert(
    *,
    rule,
    dedupe_key,
    title,
    description,
    related_user=None,
    source_ip=None,
    related_incident=None,
):
    with transaction.atomic():
        rule = type(rule).objects.select_for_update().get(pk=rule.pk)
        duplicate = SecurityAlert.objects.filter(
            detection_rule=rule,
            dedupe_key=dedupe_key,
            created_at__gte=timezone.now()
            - timedelta(seconds=rule.suppression_seconds),
        ).exists()
        if duplicate:
            return None
        from incidents.services import create_security_alert

        return create_security_alert(
            actor=None,
            title=title[:160],
            description=(
                f"{description} Detection rule: {rule.identifier}."
            )[:2000],
            alert_type=alert_type_for_rule(rule.identifier),
            severity=rule.severity,
            related_user=related_user,
            related_incident=related_incident,
            source_ip=source_ip,
            detection_rule=rule,
            dedupe_key=dedupe_key,
            auto_generated=True,
        )


def _process_rule(rule_name, event_key, processor):
    try:
        processor()
        return True
    except Exception:
        logger.exception(
            "Detection rule %s failed while processing event %s.",
            rule_name,
            event_key,
        )
        return False


def _process_login_attempt_rules(attempt):
    succeeded = True
    if not attempt.successful:
        rule = get_enabled_rule("multiple_failed_logins")
        if rule:
            def detect_multiple_failures():
                for match in failed_login_counts(attempt, rule):
                    _emit_alert(
                        rule=rule,
                        dedupe_key=match["scope"],
                        title="Multiple failed login attempts",
                        description=(
                            f"{match['count']} failed sign-in attempts for "
                            f"{match['account']} were recorded within "
                            f"{rule.window_seconds} seconds. This is a review "
                            "signal, not confirmation of account compromise."
                        ),
                        related_user=match["related_user"],
                        source_ip=match["source_ip"],
                    )

            if not _process_rule(rule.identifier, attempt.pk, detect_multiple_failures):
                succeeded = False

        suspicious_rule = get_enabled_rule("repeated_suspicious_login_activity")
        if suspicious_rule and attempt.ip_address:
            def detect_multiple_accounts():
                attempt_count, account_count = suspicious_ip_failures(
                    attempt,
                    suspicious_rule,
                )
                if account_count >= suspicious_rule.threshold:
                    _emit_alert(
                        rule=suspicious_rule,
                        dedupe_key=f"ip:{attempt.ip_address}",
                        title="Repeated login failures across multiple accounts",
                        description=(
                            f"Source IP {attempt.ip_address} generated "
                            f"{attempt_count} failed sign-in attempts against "
                            f"{account_count} account names within "
                            f"{suspicious_rule.window_seconds} seconds."
                        ),
                        related_user=attempt.user,
                        source_ip=attempt.ip_address,
                    )

            if not _process_rule(
                suspicious_rule.identifier,
                attempt.pk,
                detect_multiple_accounts,
            ):
                succeeded = False
        return succeeded

    rule = get_enabled_rule("successful_login_after_failures")
    if rule:
        def detect_success_after_failures():
            failure_count = preceding_login_failures(attempt, rule)
            if failure_count >= rule.threshold:
                scope = f"account:{attempt.username.casefold()}"
                if attempt.ip_address:
                    scope += f":ip:{attempt.ip_address}"
                _emit_alert(
                    rule=rule,
                    dedupe_key=scope,
                    title="Successful login after repeated failures",
                    description=(
                        f"Account {attempt.username} signed in successfully after "
                        f"{failure_count} preceding failed attempts within "
                        f"{rule.window_seconds} seconds."
                    ),
                    related_user=attempt.user,
                    source_ip=attempt.ip_address,
                )

        return _process_rule(rule.identifier, attempt.pk, detect_success_after_failures)
    return True


def process_login_attempt(attempt):
    event, created = _claim_event("login_attempt", f"login_attempt:{attempt.pk}")
    if not created:
        return event
    if _process_login_attempt_rules(attempt):
        event.processed_at = timezone.now()
        event.save(update_fields=("processed_at",))
    return event


def process_unauthorized_activity(entry):
    event, created = _claim_event("unauthorized_activity", f"activity_log:{entry.pk}")
    if not created:
        return event
    rule = get_enabled_rule("repeated_unauthorized_activity")
    succeeded = True
    if rule:
        def detect_repeated_denials():
            count, scope = unauthorized_activity_count(entry, rule)
            if count >= rule.threshold:
                _emit_alert(
                    rule=rule,
                    dedupe_key=scope,
                    title="Repeated unauthorized application access",
                    description=(
                        f"{count} permission-denied API actions were recorded "
                        f"for {scope} within {rule.window_seconds} seconds."
                    ),
                    related_user=entry.actor,
                    source_ip=entry.source_ip,
                    related_incident=entry.incident,
                )

        succeeded = _process_rule(rule.identifier, entry.pk, detect_repeated_denials)
    if succeeded:
        event.processed_at = timezone.now()
        event.save(update_fields=("processed_at",))
    return event


def process_incident_report(incident):
    event, created = _claim_event("incident_report", f"incident:{incident.pk}")
    if not created:
        return event
    rule = get_enabled_rule("repeated_incident_reports")
    succeeded = True
    if rule:
        def detect_repeated_reports():
            count = repeated_incident_count(incident, rule)
            if count >= rule.threshold:
                _emit_alert(
                    rule=rule,
                    dedupe_key=(
                        f"reporter:{incident.reporter_id}:category:{incident.category}"
                    ),
                    title="Repeated incident reports for analyst review",
                    description=(
                        f"Reporter {incident.reporter.get_username()} submitted "
                        f"{count} reports in category {incident.category} within "
                        f"{rule.window_seconds} seconds. Reports are grouped by "
                        "reporter and category only; this does not establish that "
                        "they are duplicates."
                    ),
                    related_user=incident.reporter,
                    related_incident=incident,
                )

        succeeded = _process_rule(rule.identifier, incident.pk, detect_repeated_reports)
    if succeeded:
        event.processed_at = timezone.now()
        event.save(update_fields=("processed_at",))
    return event


def retry_pending_detection_events(*, limit=100):
    handlers = {
        "login_attempt": (LoginAttempt, process_login_attempt),
        "incident_report": (Incident, process_incident_report),
        "unauthorized_activity": (ActivityLog, process_unauthorized_activity),
    }
    pending = DetectionEvent.objects.filter(
        processed_at__isnull=True
    ).order_by("created_at", "pk")[:limit]
    attempted = 0
    completed = 0
    for event in pending:
        handler = handlers.get(event.event_type)
        if handler is None:
            logger.error(
                "Cannot retry detection event %s with unknown type %s.",
                event.pk,
                event.event_type,
            )
            continue
        model, processor = handler
        try:
            source_id = int(event.event_key.rsplit(":", 1)[1])
            source = model.objects.get(pk=source_id)
        except (ValueError, IndexError, model.DoesNotExist):
            logger.exception(
                "Cannot find source record for pending detection event %s.",
                event.pk,
            )
            continue
        attempted += 1
        processor(source)
        event.refresh_from_db()
        if event.processed_at is not None:
            completed += 1
    return {"attempted": attempted, "completed": completed}
