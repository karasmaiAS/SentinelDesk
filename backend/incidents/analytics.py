from datetime import datetime, time, timedelta

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.db.models import Count, Min, Q
from django.db.models.functions import TruncDay, TruncMonth, TruncWeek
from django.utils import timezone

from accounts.roles import active_analysts, is_administrator, is_analyst

from .models import ActivityLog, Incident, InvestigationNote, SecurityAlert


MAX_ANALYTICS_RANGE_DAYS = 3660
GRANULARITIES = ("daily", "weekly", "monthly")


def default_analytics_dates():
    end_date = timezone.localdate()
    return end_date - timedelta(days=29), end_date


def validate_analytics_dates(start_date, end_date):
    if start_date > end_date:
        raise ValueError("The start date must be on or before the end date.")
    if (end_date - start_date).days + 1 > MAX_ANALYTICS_RANGE_DAYS:
        raise ValueError(
            f"Choose a date range of {MAX_ANALYTICS_RANGE_DAYS} days or less."
        )


def _range_bounds(start_date, end_date):
    current_timezone = timezone.get_current_timezone()
    start_at = timezone.make_aware(
        datetime.combine(start_date, time.min),
        current_timezone,
    )
    end_at = timezone.make_aware(
        datetime.combine(end_date + timedelta(days=1), time.min),
        current_timezone,
    )
    return start_at, end_at


def _period_expression(field_name, granularity):
    truncation = {
        "daily": TruncDay,
        "weekly": TruncWeek,
        "monthly": TruncMonth,
    }[granularity]
    return truncation(field_name, tzinfo=timezone.get_current_timezone())


def _period_key(value, granularity):
    if hasattr(value, "hour"):
        value = timezone.localtime(value).date()
    if granularity == "weekly":
        return value - timedelta(days=value.weekday())
    if granularity == "monthly":
        return value.replace(day=1)
    return value


def _period_keys(start_date, end_date, granularity):
    if granularity == "daily":
        cursor = start_date
        advance = lambda current: current + timedelta(days=1)
    elif granularity == "weekly":
        cursor = start_date - timedelta(days=start_date.weekday())
        advance = lambda current: current + timedelta(days=7)
    else:
        cursor = start_date.replace(day=1)

        def advance(current):
            year = current.year + int(current.month == 12)
            month = 1 if current.month == 12 else current.month + 1
            return current.replace(year=year, month=month, day=1)

    periods = []
    while cursor <= end_date:
        periods.append(cursor)
        cursor = advance(cursor)
    return periods


def _range_queryset(queryset, field_name, start_at, end_at):
    return queryset.filter(
        **{
            f"{field_name}__gte": start_at,
            f"{field_name}__lt": end_at,
        }
    )


def _counts_by_period(
    queryset,
    field_name,
    start_at,
    end_at,
    start_date,
    end_date,
    granularity,
    *,
    distinct_field=None,
):
    count = Count(
        distinct_field or "pk",
        distinct=distinct_field is not None,
    )
    rows = (
        _range_queryset(queryset, field_name, start_at, end_at)
        .annotate(bucket=_period_expression(field_name, granularity))
        .values("bucket")
        .annotate(total=count)
        .order_by("bucket")
    )
    counts = {
        _period_key(row["bucket"], granularity): row["total"]
        for row in rows
    }
    if not any(counts.values()):
        return []
    return [
        {"period": bucket.isoformat(), "count": counts.get(bucket, 0)}
        for bucket in _period_keys(start_date, end_date, granularity)
    ]


def _dimension_trends(
    queryset,
    field_name,
    dimension,
    choices,
    start_at,
    end_at,
    start_date,
    end_date,
    granularity,
):
    rows = (
        _range_queryset(queryset, field_name, start_at, end_at)
        .annotate(bucket=_period_expression(field_name, granularity))
        .values(dimension, "bucket")
        .annotate(total=Count("pk"))
    )
    counts = {
        (row[dimension], _period_key(row["bucket"], granularity)): row["total"]
        for row in rows
    }
    if not counts:
        return []
    buckets = _period_keys(start_date, end_date, granularity)
    return [
        {
            "key": value,
            "label": label,
            "values": [counts.get((value, bucket), 0) for bucket in buckets],
        }
        for value, label in choices
    ]


def _counts_by_choice(queryset, field_name, choices):
    counts = dict(
        queryset.values(field_name)
        .annotate(total=Count("pk"))
        .values_list(field_name, "total")
    )
    return {value: counts.get(value, 0) for value, _ in choices}


def _first_event_times(queryset):
    return dict(
        queryset.values("incident_id")
        .annotate(first_event_at=Min("created_at"))
        .values_list("incident_id", "first_event_at")
    )


def _time_metric(created_at_by_id, first_event_by_id):
    now = timezone.now()
    durations = [
        (event_at - created_at_by_id[incident_id]).total_seconds()
        for incident_id, event_at in first_event_by_id.items()
        if incident_id in created_at_by_id
        and created_at_by_id[incident_id] <= event_at <= now
    ]
    return {
        "average_seconds": (
            round(sum(durations) / len(durations), 1) if durations else None
        ),
        "sample_size": len(durations),
    }


def _workload_analytics(user, incidents):
    if is_administrator(user):
        analysts = active_analysts()
        can_view_unassigned = True
    else:
        analysts = get_user_model().objects.filter(pk=user.pk)
        can_view_unassigned = False

    workload = []
    for analyst in analysts:
        assigned = Incident.objects.filter(assigned_analyst=analyst)
        counts = assigned.aggregate(
            total=Count("pk"),
            open=Count("pk", filter=Q(status=Incident.Status.OPEN)),
            under_investigation=Count(
                "pk",
                filter=Q(status=Incident.Status.UNDER_INVESTIGATION),
            ),
            pending=Count("pk", filter=Q(status=Incident.Status.PENDING)),
            resolved=Count("pk", filter=Q(status=Incident.Status.RESOLVED)),
            closed=Count("pk", filter=Q(status=Incident.Status.CLOSED)),
            active=Count(
                "pk",
                filter=~Q(
                    status__in=(Incident.Status.RESOLVED, Incident.Status.CLOSED)
                ),
            ),
        )
        workload.append(
            {
                "analyst_id": analyst.pk,
                "username": analyst.get_username(),
                "assigned_incidents": counts["total"],
                "open_incidents": counts["open"],
                "under_investigation_incidents": counts["under_investigation"],
                "pending_incidents": counts["pending"],
                "resolved_incidents": counts["resolved"],
                "closed_incidents": counts["closed"],
                "active_incidents": counts["active"],
            }
        )

    total_active_assigned = sum(row["active_incidents"] for row in workload)
    for row in workload:
        row["active_workload_percent"] = (
            round(row["active_incidents"] * 100 / total_active_assigned, 1)
            if total_active_assigned
            else 0
        )

    if can_view_unassigned:
        unassigned = incidents.filter(assigned_analyst__isnull=True)
        unassigned_count = unassigned.count()
        unassigned_active_count = unassigned.exclude(
            status__in=(Incident.Status.RESOLVED, Incident.Status.CLOSED)
        ).count()
    else:
        unassigned_count = None
        unassigned_active_count = None

    return {
        "analysts": workload,
        "unassigned_incidents": unassigned_count,
        "unassigned_active_incidents": unassigned_active_count,
        "workload_scope": "current assignments",
    }


def get_security_analytics(*, user, start_date, end_date, granularity="daily"):
    validate_analytics_dates(start_date, end_date)
    if granularity not in GRANULARITIES:
        raise ValueError("Select daily, weekly, or monthly aggregation.")
    if not is_administrator(user) and not is_analyst(user):
        raise PermissionDenied("Security analytics are not available to this role.")

    incidents = (
        Incident.objects.all()
        if is_administrator(user)
        else Incident.objects.filter(assigned_analyst=user)
    )
    start_at, end_at = _range_bounds(start_date, end_date)
    period_incidents = _range_queryset(incidents, "created_at", start_at, end_at)
    incident_totals = incidents.aggregate(
        total=Count("pk"),
        open=Count("pk", filter=Q(status=Incident.Status.OPEN)),
        under_investigation=Count(
            "pk",
            filter=Q(status=Incident.Status.UNDER_INVESTIGATION),
        ),
        pending=Count("pk", filter=Q(status=Incident.Status.PENDING)),
        resolved=Count("pk", filter=Q(status=Incident.Status.RESOLVED)),
        closed=Count("pk", filter=Q(status=Incident.Status.CLOSED)),
        critical=Count("pk", filter=Q(severity=Incident.Severity.CRITICAL)),
        high=Count("pk", filter=Q(severity=Incident.Severity.HIGH)),
        medium=Count("pk", filter=Q(severity=Incident.Severity.MEDIUM)),
        low=Count("pk", filter=Q(severity=Incident.Severity.LOW)),
        unresolved=Count(
            "pk",
            filter=~Q(status__in=(Incident.Status.RESOLVED, Incident.Status.CLOSED)),
        ),
    )
    period_incident_statistics = {
        "total": period_incidents.count(),
        "by_status": _counts_by_choice(
            period_incidents, "status", Incident.Status.choices
        ),
        "by_severity": _counts_by_choice(
            period_incidents, "severity", Incident.Severity.choices
        ),
        "by_category": _counts_by_choice(
            period_incidents, "category", Incident.Category.choices
        ),
    }

    if is_administrator(user):
        alerts = SecurityAlert.objects.all()
    else:
        alerts = SecurityAlert.objects.filter(
            Q(related_incident__isnull=True)
            | Q(related_incident__assigned_analyst=user)
        )
    period_alerts = _range_queryset(alerts, "created_at", start_at, end_at)
    alert_statistics = {
        "total_alerts": alerts.count(),
        "generated_alerts": alerts.filter(auto_generated=True).count(),
        "manual_alerts": alerts.filter(auto_generated=False).count(),
        "by_severity": _counts_by_choice(
            alerts, "severity", SecurityAlert.Severity.choices
        ),
        "by_type": _counts_by_choice(
            alerts, "alert_type", SecurityAlert.AlertType.choices
        ),
        "by_status": _counts_by_choice(
            alerts, "status", SecurityAlert.Status.choices
        ),
        "created_in_period": period_alerts.count(),
        "generated_in_period": period_alerts.filter(auto_generated=True).count(),
        "manual_in_period": period_alerts.filter(auto_generated=False).count(),
        "period": {
            "total": period_alerts.count(),
            "by_severity": _counts_by_choice(
                period_alerts, "severity", SecurityAlert.Severity.choices
            ),
            "by_type": _counts_by_choice(
                period_alerts, "alert_type", SecurityAlert.AlertType.choices
            ),
            "by_status": _counts_by_choice(
                period_alerts, "status", SecurityAlert.Status.choices
            ),
        },
    }

    incident_ids = period_incidents.values_list("pk", flat=True)
    created_at_by_id = dict(period_incidents.values_list("pk", "created_at"))
    activity = ActivityLog.objects.filter(incident_id__in=incident_ids)
    assignment_times = _first_event_times(
        activity.filter(action=ActivityLog.Action.ASSIGNMENT_CHANGED).exclude(
            description__endswith="to unassigned."
        )
    )
    investigation_times = _first_event_times(
        InvestigationNote.objects.filter(incident_id__in=incident_ids)
    )
    resolution_events = activity.filter(
        action=ActivityLog.Action.STATUS_CHANGED,
        description__endswith="to resolved.",
    )
    resolution_times = _first_event_times(resolution_events)
    resolved_trend = _counts_by_period(
        resolution_events,
        "created_at",
        start_at,
        end_at,
        start_date,
        end_date,
        granularity,
        distinct_field="incident_id",
    )

    priority_alerts = (
        alerts.filter(
            severity__in=(SecurityAlert.Severity.CRITICAL, SecurityAlert.Severity.HIGH)
        )
        .select_related("detection_rule")
        .order_by("-created_at")[:10]
    )
    recent_incidents = incidents.select_related("reporter").order_by("-created_at")[:8]
    most_triggered_rules = (
        period_alerts.filter(auto_generated=True, detection_rule__isnull=False)
        .values("detection_rule__identifier", "detection_rule__name")
        .annotate(alert_count=Count("pk"))
        .order_by("-alert_count", "detection_rule__identifier")[:5]
    )
    unresolved_count = incident_totals["unresolved"]

    incident_trends = {
        "counts": _counts_by_period(
            incidents,
            "created_at",
            start_at,
            end_at,
            start_date,
            end_date,
            granularity,
        ),
        "new_vs_resolved": {
            "new": _counts_by_period(
                incidents,
                "created_at",
                start_at,
                end_at,
                start_date,
                end_date,
                granularity,
            ),
            "resolved": resolved_trend,
        },
        "by_severity": _dimension_trends(
            incidents,
            "created_at",
            "severity",
            Incident.Severity.choices,
            start_at,
            end_at,
            start_date,
            end_date,
            granularity,
        ),
        "by_category": _dimension_trends(
            incidents,
            "created_at",
            "category",
            Incident.Category.choices,
            start_at,
            end_at,
            start_date,
            end_date,
            granularity,
        ),
        "by_status": _dimension_trends(
            incidents,
            "created_at",
            "status",
            Incident.Status.choices,
            start_at,
            end_at,
            start_date,
            end_date,
            granularity,
        ),
    }
    alert_trends = {
        "counts": _counts_by_period(
            alerts,
            "created_at",
            start_at,
            end_at,
            start_date,
            end_date,
            granularity,
        ),
        "by_severity": _dimension_trends(
            alerts,
            "created_at",
            "severity",
            SecurityAlert.Severity.choices,
            start_at,
            end_at,
            start_date,
            end_date,
            granularity,
        ),
    }

    return {
        "filters": {
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "granularity": granularity,
        },
        "incident_statistics": {
            "total_incidents": incident_totals["total"],
            "open_incidents": incident_totals["open"],
            "under_investigation_incidents": incident_totals[
                "under_investigation"
            ],
            "pending_incidents": incident_totals["pending"],
            "resolved_incidents": incident_totals["resolved"],
            "closed_incidents": incident_totals["closed"],
            "active_incidents": incident_totals["unresolved"],
            "unresolved_incidents": unresolved_count,
            "critical_incidents": incident_totals["critical"],
            "high_severity_incidents": incident_totals["high"],
            "medium_severity_incidents": incident_totals["medium"],
            "low_severity_incidents": incident_totals["low"],
            "by_status": _counts_by_choice(
                incidents, "status", Incident.Status.choices
            ),
            "by_severity": _counts_by_choice(
                incidents, "severity", Incident.Severity.choices
            ),
            "by_category": _counts_by_choice(
                incidents, "category", Incident.Category.choices
            ),
            "period": period_incident_statistics,
        },
        "alert_statistics": alert_statistics,
        "incident_trends": incident_trends,
        "alert_trends": alert_trends,
        "response_performance": {
            "average_time_to_assignment": _time_metric(
                created_at_by_id, assignment_times
            ),
            "average_time_to_first_investigation_activity": _time_metric(
                created_at_by_id, investigation_times
            ),
            "average_time_to_resolution": _time_metric(
                created_at_by_id, resolution_times
            ),
            "unresolved_incidents": unresolved_count,
            "unresolved_in_period": period_incidents.exclude(
                status__in=(Incident.Status.RESOLVED, Incident.Status.CLOSED)
            ).count(),
            "overdue_incidents": None,
            "overdue_unavailable_reason": (
                "No incident deadline or service-level target is configured."
            ),
            "metric_definitions": {
                "average_time_to_assignment": (
                    "Incident creation to its first logged assignment change."
                ),
                "average_time_to_first_investigation_activity": (
                    "Incident creation to its first investigation note."
                ),
                "average_time_to_resolution": (
                    "Incident creation to its first logged transition to Resolved."
                ),
                "cohort": "Incidents created within the selected date range.",
            },
        },
        "analyst_workload": _workload_analytics(user, incidents),
        "most_triggered_rules": [
            {
                "identifier": row["detection_rule__identifier"],
                "name": row["detection_rule__name"],
                "alert_count": row["alert_count"],
            }
            for row in most_triggered_rules
        ],
        "recent_priority_alerts": [
            {
                "id": alert.pk,
                "title": alert.title,
                "severity": alert.severity,
                "severity_display": alert.get_severity_display(),
                "alert_type": alert.alert_type,
                "alert_type_display": alert.get_alert_type_display(),
                "status": alert.status,
                "auto_generated": alert.auto_generated,
                "detection_rule_identifier": (
                    alert.detection_rule.identifier if alert.detection_rule else None
                ),
                "created_at": alert.created_at.isoformat(),
            }
            for alert in priority_alerts
        ],
        "recent_incidents": [
            {
                "id": incident.pk,
                "title": incident.title,
                "severity": incident.severity,
                "severity_display": incident.get_severity_display(),
                "status": incident.status,
                "status_display": incident.get_status_display(),
                "category": incident.category,
                "category_display": incident.get_category_display(),
                "reporter_username": incident.reporter.get_username(),
                "created_at": incident.created_at.isoformat(),
            }
            for incident in recent_incidents
        ],
    }
