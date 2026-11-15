from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.core.exceptions import ValidationError
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.core.paginator import Paginator
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from accounts.roles import can_investigate, is_administrator, is_analyst
from incidents.models import Incident
from incidents.models import ActivityLog, SecurityAlert
from incidents.services import (
    add_investigation_note,
    assign_incident,
    update_incident,
    update_security_alert_status,
)
from incidents.staff_forms import (
    IncidentAssignmentForm,
    InvestigationNoteForm,
    SecurityAlertStatusForm,
    StaffIncidentUpdateForm,
)

from .design_tokens import get_design_tokens


def home(request):
    if request.user.is_authenticated:
        if request.user.is_staff:
            return redirect("core:admin_dashboard")
        return redirect("incidents:dashboard")
    return redirect("accounts:login")


@login_required
def soc_dashboard(request):
    if not is_administrator(request.user) and not is_analyst(request.user):
        raise PermissionDenied

    incidents = Incident.objects.all()
    if not is_administrator(request.user):
        incidents = incidents.filter(assigned_analyst=request.user)
    severity_counts = dict(
        incidents.values("severity")
        .annotate(total=Count("id"))
        .values_list("severity", "total")
    )
    category_counts = dict(
        incidents.values("category")
        .annotate(total=Count("id"))
        .values_list("category", "total")
    )

    today = timezone.localdate()
    start_date = today - timedelta(days=6)
    daily_counts = dict(
        incidents.filter(created_at__date__range=(start_date, today))
        .annotate(day=TruncDate("created_at"))
        .values("day")
        .annotate(total=Count("id"))
        .values_list("day", "total")
    )
    trend_days = [start_date + timedelta(days=offset) for offset in range(7)]
    colors = get_design_tokens()["colors"]
    user_model = get_user_model()

    context = {
        "total_incidents": incidents.count(),
        "open_incidents": incidents.exclude(
            status__in=(Incident.Status.RESOLVED, Incident.Status.CLOSED)
        ).count(),
        "critical_incidents": incidents.filter(
            severity=Incident.Severity.CRITICAL
        ).count(),
        "resolved_incidents": incidents.filter(
            status=Incident.Status.RESOLVED
        ).count(),
        "active_users": (
            user_model.objects.filter(is_active=True).count()
            if is_administrator(request.user)
            else None
        ),
        "open_alerts": SecurityAlert.objects.filter(
            status__in=(SecurityAlert.Status.OPEN, SecurityAlert.Status.INVESTIGATING)
        ).count(),
        "recent_activity": ActivityLog.objects.select_related(
            "actor", "incident"
        ).filter(
            incident__in=incidents
        )[:6],
        "recent_incidents": incidents.select_related(
            "reporter", "assigned_analyst"
        )[:8],
        "severity_chart": {
            "labels": [label for _, label in Incident.Severity.choices],
            "values": [
                severity_counts.get(value, 0)
                for value, _ in Incident.Severity.choices
            ],
            "colors": [
                colors[value]
                for value, _ in Incident.Severity.choices
            ],
        },
        "category_chart": {
            "labels": [label for _, label in Incident.Category.choices],
            "values": [
                category_counts.get(value, 0)
                for value, _ in Incident.Category.choices
            ],
            "color": colors["secondary"],
        },
        "trend_chart": {
            "labels": [day.strftime("%b %d").replace(" 0", " ") for day in trend_days],
            "values": [daily_counts.get(day, 0) for day in trend_days],
            "color": colors["primary"],
        },
    }
    return render(request, "core/soc_dashboard.html", context)


@login_required
def incident_monitoring(request):
    if not is_administrator(request.user) and not is_analyst(request.user):
        raise PermissionDenied

    incidents = Incident.objects.select_related("reporter", "assigned_analyst")
    if not is_administrator(request.user):
        incidents = incidents.filter(assigned_analyst=request.user)
    search_query = request.GET.get("q", "").strip()
    if search_query:
        incidents = incidents.filter(
            Q(title__icontains=search_query)
            | Q(description__icontains=search_query)
            | Q(reporter__username__icontains=search_query)
        )

    selected_category = request.GET.get("category", "")
    if selected_category not in Incident.Category.values:
        selected_category = ""
    if selected_category:
        incidents = incidents.filter(category=selected_category)

    selected_severity = request.GET.get("severity", "")
    if selected_severity not in Incident.Severity.values:
        selected_severity = ""
    if selected_severity:
        incidents = incidents.filter(severity=selected_severity)

    selected_status = request.GET.get("status", "")
    if selected_status not in Incident.Status.values:
        selected_status = ""
    if selected_status:
        incidents = incidents.filter(status=selected_status)

    filter_query = request.GET.copy()
    filter_query.pop("page", None)
    page_obj = Paginator(incidents, 25).get_page(request.GET.get("page"))
    return render(
        request,
        "core/incident_monitoring.html",
        {
            "page_obj": page_obj,
            "search_query": search_query,
            "selected_category": selected_category,
            "selected_severity": selected_severity,
            "selected_status": selected_status,
            "category_choices": Incident.Category.choices,
            "severity_choices": Incident.Severity.choices,
            "status_choices": Incident.Status.choices,
            "filter_query": filter_query.urlencode(),
        },
    )


@login_required
def monitored_incident_detail(request, pk):
    if not is_administrator(request.user) and not is_analyst(request.user):
        raise PermissionDenied

    incidents = Incident.objects.select_related("reporter", "assigned_analyst")
    if not is_administrator(request.user):
        incidents = incidents.filter(assigned_analyst=request.user)
    incident = get_object_or_404(
        incidents,
        pk=pk,
    )

    update_form = StaffIncidentUpdateForm(
        actor=request.user,
        incident=incident,
        initial={
            "status": incident.status,
            "severity": incident.severity,
            "resolution_summary": incident.resolution_summary,
        },
    )
    assignment_form = IncidentAssignmentForm(
        initial={"analyst": incident.assigned_analyst}
    )
    note_form = InvestigationNoteForm()
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "update":
            update_form = StaffIncidentUpdateForm(
                request.POST,
                actor=request.user,
                incident=incident,
            )
            if update_form.is_valid():
                try:
                    update_incident(
                        actor=request.user,
                        incident=incident,
                        changes=update_form.get_changes(),
                        request=request,
                    )
                except ValidationError as error:
                    update_form.add_error(None, error)
                else:
                    messages.success(request, "Incident updated.")
                    return redirect(
                        "core:monitored_incident_detail",
                        pk=incident.pk,
                    )
        elif action == "assign" and is_administrator(request.user):
            assignment_form = IncidentAssignmentForm(request.POST)
            if assignment_form.is_valid():
                try:
                    assign_incident(
                        actor=request.user,
                        incident=incident,
                        analyst=assignment_form.cleaned_data["analyst"],
                        request=request,
                    )
                except ValidationError as error:
                    assignment_form.add_error("analyst", error)
                else:
                    messages.success(request, "Incident assignment updated.")
                    return redirect(
                        "core:monitored_incident_detail",
                        pk=incident.pk,
                    )
        elif action == "assign":
            raise PermissionDenied
        elif action == "note":
            note_form = InvestigationNoteForm(request.POST)
            if note_form.is_valid():
                try:
                    add_investigation_note(
                        actor=request.user,
                        incident=incident,
                        content=note_form.cleaned_data["content"],
                        request=request,
                    )
                except PermissionDenied:
                    raise
                except ValidationError as error:
                    note_form.add_error(None, error)
                else:
                    messages.success(request, "Investigation note added.")
                    return redirect(
                        "core:monitored_incident_detail",
                        pk=incident.pk,
                    )

    return render(
        request,
        "core/monitored_incident_detail.html",
        {
            "incident": incident,
            "update_form": update_form,
            "assignment_form": assignment_form,
            "note_form": note_form,
            "can_assign": is_administrator(request.user),
            "can_investigate": can_investigate(request.user, incident),
            "notes": incident.investigation_notes.select_related("analyst"),
        },
    )


@login_required
def security_alerts(request):
    if not is_administrator(request.user) and not is_analyst(request.user):
        raise PermissionDenied

    if request.method == "POST":
        if not is_administrator(request.user):
            raise PermissionDenied
        alert_id = request.POST.get("alert_id")
        if not alert_id or not alert_id.isdecimal():
            raise PermissionDenied
        alert = get_object_or_404(SecurityAlert, pk=alert_id)
        form = SecurityAlertStatusForm(request.POST)
        if form.is_valid():
            try:
                update_security_alert_status(
                    actor=request.user,
                    alert=alert,
                    status=form.cleaned_data["status"],
                    request=request,
                )
            except ValidationError as error:
                messages.error(request, "; ".join(error.messages))
            else:
                messages.success(request, "Security alert updated.")
                return redirect("core:security_alerts")

    alerts = SecurityAlert.objects.select_related("related_user")
    return render(
        request,
        "core/security_alerts.html",
        {
            "alerts": alerts[:100],
            "can_manage": is_administrator(request.user),
            "alert_status_choices": SecurityAlert.Status.choices,
        },
    )


@login_required
def activity_logs(request):
    if not is_administrator(request.user) and not is_analyst(request.user):
        raise PermissionDenied

    entries = ActivityLog.objects.select_related("actor", "incident")
    if not is_administrator(request.user):
        entries = entries.filter(incident__assigned_analyst=request.user)
    return render(
        request,
        "core/activity_logs.html",
        {"entries": entries[:100]},
    )
