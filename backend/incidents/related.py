from django.core.exceptions import PermissionDenied

from accounts.roles import is_administrator, is_analyst

from .models import Incident, IndicatorOfCompromise, SecurityAlert


def suggest_related_incidents(*, incident, user, limit=10):
    if not is_administrator(user) and not is_analyst(user):
        raise PermissionDenied("Related incidents are not available to this role.")

    candidates = Incident.objects.exclude(pk=incident.pk)
    if not is_administrator(user):
        candidates = candidates.filter(assigned_analyst=user)
    candidate_ids = set(candidates.values_list("pk", flat=True))
    suggestions = {}

    def add_reason(incident_id, reason, shared_indicator=None):
        if incident_id not in candidate_ids:
            return
        suggestion = suggestions.setdefault(
            incident_id,
            {"reasons": [], "shared_indicators": []},
        )
        if reason not in suggestion["reasons"]:
            suggestion["reasons"].append(reason)
        if shared_indicator and shared_indicator not in suggestion["shared_indicators"]:
            suggestion["shared_indicators"].append(shared_indicator)

    indicators = list(
        incident.indicators.values("indicator_type", "normalized_value", "value")
    )
    for indicator in indicators:
        related = IndicatorOfCompromise.objects.filter(
            indicator_type=indicator["indicator_type"],
            normalized_value=indicator["normalized_value"],
        ).exclude(incident=incident)
        if not is_administrator(user):
            related = related.filter(incident__assigned_analyst=user)
        shared = {
            "indicator_type": indicator["indicator_type"],
            "value": indicator["value"],
        }
        for related_incident_id in related.values_list("incident_id", flat=True):
            add_reason(
                related_incident_id,
                f"Shares an exact {indicator['indicator_type']} indicator.",
                shared,
            )

    category_label = incident.get_category_display()
    for related_incident_id in candidates.filter(
        category=incident.category
    ).values_list("pk", flat=True)[:5]:
        add_reason(
            related_incident_id,
            f"Has the same incident category: {category_label}.",
        )

    related_accounts = SecurityAlert.objects.filter(
        related_incident=incident,
        related_user__isnull=False,
    ).values_list("related_user_id", flat=True)
    for account_id in related_accounts:
        matching_alerts = SecurityAlert.objects.filter(
            related_user_id=account_id,
            related_incident__in=candidate_ids,
        ).exclude(related_incident__isnull=True)
        for related_incident_id in matching_alerts.values_list(
            "related_incident_id",
            flat=True,
        ).distinct():
            add_reason(related_incident_id, "Shares an account referenced by alerts.")

    incident_map = {
        row.pk: row
        for row in candidates.filter(pk__in=suggestions).select_related(
            "assigned_analyst"
        )
    }
    results = []
    for incident_id, suggestion in suggestions.items():
        related_incident = incident_map.get(incident_id)
        if related_incident is None:
            continue
        results.append(
            {
                "incident_id": related_incident.pk,
                "title": related_incident.title,
                "category": related_incident.category,
                "category_display": related_incident.get_category_display(),
                "severity": related_incident.severity,
                "status": related_incident.status,
                "reasons": suggestion["reasons"],
                "shared_indicators": suggestion["shared_indicators"],
                "relationship": "Possible relationship; analyst review required.",
            }
        )
    return sorted(
        results,
        key=lambda item: (
            -len(item["shared_indicators"]),
            -len(item["reasons"]),
            item["incident_id"],
        ),
    )[:limit]
