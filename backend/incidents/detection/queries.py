from django.db.models import Count, Q

from accounts.roles import is_administrator, is_analyst
from incidents.models import DetectionRule, SecurityAlert


def get_detection_overview(user=None):
    if user is not None and is_analyst(user) and not is_administrator(user):
        alerts = SecurityAlert.objects.filter(auto_generated=True).filter(
            Q(related_incident__isnull=True)
            | Q(related_incident__assigned_analyst=user)
        )
    else:
        alerts = SecurityAlert.objects.filter(auto_generated=True)
    severities = {
        value: alerts.filter(severity=value).count()
        for value, _ in SecurityAlert.Severity.choices
    }
    top_rules = (
        DetectionRule.objects.annotate(
            alert_count=Count(
                "generated_alerts",
                filter=Q(generated_alerts__auto_generated=True),
            )
        )
        .filter(alert_count__gt=0)
        .order_by("-alert_count", "identifier")[:5]
    )
    return {
        "total_generated_alerts": alerts.count(),
        "alerts_by_severity": severities,
        "enabled_rules": DetectionRule.objects.filter(enabled=True).count(),
        "total_rules": DetectionRule.objects.count(),
        "most_triggered_rules": [
            {
                "identifier": rule.identifier,
                "name": rule.name,
                "alert_count": rule.alert_count,
            }
            for rule in top_rules
        ],
    }
