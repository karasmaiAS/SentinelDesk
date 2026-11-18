from django.db import transaction
from django.utils import timezone

from .models import ActivityLog, IndicatorOfCompromise, ThreatIntelRecord
from .services import log_activity


def get_indicator_matches(indicator):
    records = ThreatIntelRecord.objects.filter(
        indicator_type=indicator.indicator_type,
        normalized_value=indicator.normalized_value,
    ).order_by("-confidence", "source")
    return {
        "status": indicator.match_status,
        "checked_at": indicator.last_checked_at,
        "explanation": _match_explanation(indicator.match_status),
        "matches": [
            {
                "indicator_type": record.indicator_type,
                "source": record.source,
                "confidence": record.confidence,
                "classification": record.classification,
                "last_updated": record.last_updated,
                "notes": record.notes,
            }
            for record in records
        ],
    }


def _match_explanation(status):
    explanations = {
        IndicatorOfCompromise.MatchStatus.UNCHECKED: (
            "This indicator has not been checked against local threat-intelligence records."
        ),
        IndicatorOfCompromise.MatchStatus.MATCHED: (
            "An exact match was found in the listed local threat-intelligence records."
        ),
        IndicatorOfCompromise.MatchStatus.UNMATCHED: (
            "No exact match was found in the available local records; this does not establish that the indicator is safe."
        ),
        IndicatorOfCompromise.MatchStatus.INCONCLUSIVE: (
            "No local threat-intelligence records are available, so the result is inconclusive."
        ),
    }
    return explanations[status]


@transaction.atomic
def check_indicator(indicator, *, actor, request=None):
    previous_status = indicator.match_status
    was_checked = indicator.last_checked_at is not None
    records = ThreatIntelRecord.objects.filter(
        indicator_type=indicator.indicator_type,
        normalized_value=indicator.normalized_value,
    )
    if records.exists():
        indicator.match_status = IndicatorOfCompromise.MatchStatus.MATCHED
    elif ThreatIntelRecord.objects.exists():
        indicator.match_status = IndicatorOfCompromise.MatchStatus.UNMATCHED
    else:
        indicator.match_status = IndicatorOfCompromise.MatchStatus.INCONCLUSIVE
    indicator.last_checked_at = timezone.now()
    indicator.save(update_fields=("match_status", "last_checked_at", "updated_at"))
    if not was_checked or previous_status != indicator.match_status:
        log_activity(
            action=ActivityLog.Action.IOC_CHECKED,
            description=(
                f"Threat-intelligence check for {indicator.indicator_type} "
                f"{indicator.value}: {indicator.get_match_status_display()}."
            ),
            actor=actor,
            incident=indicator.incident,
            request=request,
        )
    return get_indicator_matches(indicator)
