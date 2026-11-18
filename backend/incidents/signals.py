import logging

from django.db.models.signals import post_save
from django.dispatch import receiver

from .detection.event_processor import (
    process_incident_report,
    process_login_attempt,
    process_unauthorized_activity,
)
from .models import ActivityLog, Incident, LoginAttempt


logger = logging.getLogger(__name__)


def _process_without_blocking_event_save(processor, instance, event_name):
    try:
        processor(instance)
    except Exception:
        logger.exception(
            "Detection processing failed for recorded %s event %s.",
            event_name,
            instance.pk,
        )


@receiver(post_save, sender=LoginAttempt)
def detect_login_attempt(sender, instance, created, **kwargs):
    if created:
        _process_without_blocking_event_save(
            process_login_attempt,
            instance,
            "login attempt",
        )


@receiver(post_save, sender=Incident)
def detect_incident_submission(sender, instance, created, **kwargs):
    if created:
        _process_without_blocking_event_save(
            process_incident_report,
            instance,
            "incident report",
        )


@receiver(post_save, sender=ActivityLog)
def detect_unauthorized_activity(sender, instance, created, **kwargs):
    if created and instance.action == ActivityLog.Action.ACCESS_DENIED:
        _process_without_blocking_event_save(
            process_unauthorized_activity,
            instance,
            "permission-denied activity",
        )
