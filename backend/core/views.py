from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.core.exceptions import ValidationError
from django.db import transaction
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import FileResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from accounts.roles import can_investigate, is_administrator, is_analyst
from incidents.detection.queries import get_detection_overview
from incidents.analytics import default_analytics_dates, get_security_analytics
from incidents.intelligence import check_indicator, get_indicator_matches
from incidents.models import (
    ActivityLog,
    DetectionRule,
    Incident,
    IndicatorOfCompromise,
    InvestigationEvidence,
    InvestigationFinding,
    SecurityAlert,
)
from incidents.related import suggest_related_incidents
from incidents.services import log_activity
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

from .forms import (
    AnalyticsFilterForm,
    DetectionRuleForm,
    InvestigationEvidenceForm,
    InvestigationFindingForm,
    IndicatorOfCompromiseForm,
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
    filter_form = AnalyticsFilterForm(
        request.GET if request.GET else None,
        initial={"period": "30", "granularity": "daily"},
    )
    if request.GET:
        if not filter_form.is_valid():
            return render(
                request,
                "core/soc_dashboard.html",
                {
                    "filter_form": filter_form,
                    "analytics": None,
                    "can_manage_detection_rules": is_administrator(request.user),
                },
                status=400,
            )
        start_date = filter_form.cleaned_data["start_date"]
        end_date = filter_form.cleaned_data["end_date"]
        granularity = filter_form.cleaned_data["granularity"]
    else:
        start_date, end_date = default_analytics_dates()
        granularity = "daily"
    analytics = get_security_analytics(
        user=request.user,
        start_date=start_date,
        end_date=end_date,
        granularity=granularity,
    )
    user_model = get_user_model()
    incident_statistics = analytics["incident_statistics"]
    colors = get_design_tokens()["colors"]
    trend_start = end_date - timedelta(days=6)
    daily_trends = {
        row["period"]: row["count"]
        for row in analytics["incident_trends"]["counts"]
    }
    trend_days = [
        trend_start + timedelta(days=offset)
        for offset in range(7)
    ]

    context = {
        "analytics": analytics,
        "filter_form": filter_form,
        "total_incidents": incident_statistics["total_incidents"],
        "open_incidents": incident_statistics["open_incidents"],
        "critical_incidents": incident_statistics["critical_incidents"],
        "resolved_incidents": incident_statistics["resolved_incidents"],
        "open_alerts": (
            SecurityAlert.objects.filter(
                status__in=(
                    SecurityAlert.Status.OPEN,
                    SecurityAlert.Status.INVESTIGATING,
                )
            )
            .filter(
                Q(related_incident__isnull=True)
                | Q(related_incident__assigned_analyst=request.user)
            )
            .count()
            if is_analyst(request.user)
            else SecurityAlert.objects.filter(
                status__in=(
                    SecurityAlert.Status.OPEN,
                    SecurityAlert.Status.INVESTIGATING,
                )
            ).count()
        ),
        "detection_overview": get_detection_overview(request.user),
        "active_users": (
            user_model.objects.filter(is_active=True).count()
            if is_administrator(request.user)
            else None
        ),
        "can_manage_detection_rules": is_administrator(request.user),
        "severity_chart": {
            "labels": [label for _, label in Incident.Severity.choices],
            "values": [
                incident_statistics["by_severity"].get(value, 0)
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
                incident_statistics["by_category"].get(value, 0)
                for value, _ in Incident.Category.choices
            ],
            "color": colors["secondary"],
        },
        "trend_chart": {
            "labels": [day.strftime("%b %d").replace(" 0", " ") for day in trend_days],
            "values": [
                daily_trends.get(day.isoformat(), 0)
                for day in trend_days
            ],
            "color": colors["primary"],
        },
        "recent_activity": ActivityLog.objects.select_related(
            "actor", "incident"
        ).filter(
            incident__in=incidents
        )[:6],
        "recent_incidents": incidents.select_related(
            "reporter", "assigned_analyst"
        )[:8],
    }
    return render(request, "core/soc_dashboard.html", context)


@login_required
def detection_rules(request):
    if not is_administrator(request.user):
        raise PermissionDenied

    selected_rule = None
    selected_form = None
    if request.method == "POST":
        rule_id = request.POST.get("rule_id", "")
        selected_rule = get_object_or_404(DetectionRule, pk=rule_id)
        selected_form = DetectionRuleForm(request.POST, instance=selected_rule)
        if selected_form.is_valid():
            with transaction.atomic():
                selected_form.save()
                log_activity(
                    action=ActivityLog.Action.DETECTION_RULE_UPDATED,
                    description=f"Detection rule {selected_rule.identifier} configuration updated.",
                    actor=request.user,
                    request=request,
                )
            messages.success(request, f"Updated detection rule: {selected_rule.name}.")
            return redirect("core:detection_rules")

    rules = DetectionRule.objects.all()
    rule_rows = [
        {
            "rule": rule,
            "form": (
                selected_form
                if selected_rule and selected_rule.pk == rule.pk
                else DetectionRuleForm(instance=rule)
            ),
        }
        for rule in rules
    ]
    return render(request, "core/detection_rules.html", {"rule_rows": rule_rows})


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
    ioc_form = IndicatorOfCompromiseForm()
    evidence_form = InvestigationEvidenceForm()
    try:
        finding = incident.investigation_finding
    except InvestigationFinding.DoesNotExist:
        finding = None
    finding_form = InvestigationFindingForm(instance=finding)
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
        elif action == "ioc":
            ioc_form = IndicatorOfCompromiseForm(request.POST)
            if ioc_form.is_valid():
                indicator = ioc_form.save(commit=False)
                indicator.incident = incident
                indicator.added_by = request.user
                try:
                    indicator.full_clean()
                    indicator.save()
                except ValidationError as error:
                    ioc_form.add_error(None, error)
                else:
                    log_activity(
                        action=ActivityLog.Action.IOC_DISCOVERED,
                        description=(
                            f"{indicator.get_indicator_type_display()} indicator "
                            f"discovered: {indicator.value}."
                        ),
                        actor=request.user,
                        incident=incident,
                        request=request,
                    )
                    check_indicator(
                        indicator,
                        actor=request.user,
                        request=request,
                    )
                    messages.success(request, "Indicator added to the investigation.")
                    return redirect(
                        "core:monitored_incident_detail",
                        pk=incident.pk,
                    )
        elif action == "ioc_check":
            indicator = get_object_or_404(
                IndicatorOfCompromise,
                pk=request.POST.get("ioc_id"),
                incident=incident,
            )
            result = check_indicator(
                indicator,
                actor=request.user,
                request=request,
            )
            messages.info(request, result["explanation"])
            return redirect(
                "core:monitored_incident_detail",
                pk=incident.pk,
            )
        elif action == "evidence":
            evidence_form = InvestigationEvidenceForm(
                request.POST,
                request.FILES,
            )
            if evidence_form.is_valid():
                evidence = evidence_form.save(commit=False)
                evidence.incident = incident
                evidence.uploaded_by = request.user
                try:
                    evidence.full_clean()
                    evidence.save()
                except ValidationError as error:
                    evidence_form.add_error(
                        None,
                        ValidationError("; ".join(error.messages)),
                    )
                else:
                    log_activity(
                        action=ActivityLog.Action.EVIDENCE_ADDED,
                        description=(
                            f"Evidence uploaded: {evidence.original_filename} "
                            f"({evidence.file_size} bytes)."
                        ),
                        actor=request.user,
                        incident=incident,
                        request=request,
                    )
                    messages.success(request, "Investigation evidence uploaded.")
                    return redirect(
                        "core:monitored_incident_detail",
                        pk=incident.pk,
                    )
        elif action in ("findings", "finalize_findings"):
            if finding and finding.is_finalized:
                raise PermissionDenied(
                    "Finalized investigation findings are read-only."
                )
            finding_form = InvestigationFindingForm(
                request.POST,
                instance=finding,
            )
            if finding_form.is_valid():
                finding = finding_form.save(commit=False)
                finding.incident = incident
                if finding.pk is None:
                    finding.created_by = request.user
                finding.updated_by = request.user
                finalize = (
                    action == "finalize_findings"
                    or finding_form.cleaned_data["finalize"]
                )
                if finalize:
                    finding.is_finalized = True
                    finding.finalized_by = request.user
                    finding.finalized_at = timezone.now()
                try:
                    finding.full_clean()
                    finding.save()
                except ValidationError as error:
                    finding_form.add_error(
                        None,
                        ValidationError("; ".join(error.messages)),
                    )
                    if finding.pk is None:
                        finding = None
                    else:
                        finding.refresh_from_db()
                else:
                    log_activity(
                        action=ActivityLog.Action.FINDINGS_UPDATED,
                        description=(
                            "Investigation findings finalized."
                            if finalize
                            else "Investigation findings saved."
                        ),
                        actor=request.user,
                        incident=incident,
                        request=request,
                    )
                    messages.success(
                        request,
                        (
                            "Investigation findings finalized."
                            if finalize
                            else "Investigation findings saved."
                        ),
                    )
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
            "ioc_form": ioc_form,
            "evidence_form": evidence_form,
            "evidence_items": incident.evidence_items.all(),
            "finding": finding,
            "finding_form": finding_form,
            "finding_fields": (
                [
                    ("Summary", finding.summary),
                    ("Findings", finding.findings),
                    ("Identified indicators", finding.identified_indicators),
                    ("Evidence reviewed", finding.evidence_reviewed),
                    ("Actions performed", finding.actions_performed),
                    ("Recommended remediation", finding.recommended_remediation),
                ]
                if finding
                else []
            ),
            "related_suggestions": suggest_related_incidents(
                incident=incident,
                user=request.user,
            ),
            "indicator_rows": [
                {
                    "indicator": indicator,
                    "match_result": get_indicator_matches(indicator),
                }
                for indicator in incident.indicators.all()
            ],
            "can_assign": is_administrator(request.user),
            "can_investigate": can_investigate(request.user, incident),
            "notes": incident.investigation_notes.select_related("analyst"),
            "timeline": incident.activity_entries.select_related("actor").order_by(
                "created_at"
            ),
            "related_alerts": SecurityAlert.objects.filter(
                related_incident=incident
            )
            .select_related("detection_rule")
            .order_by("-created_at"),
        },
    )


@login_required
def evidence_download(request, evidence_id):
    evidence = get_object_or_404(
        InvestigationEvidence.objects.select_related("incident"),
        pk=evidence_id,
    )
    if not is_administrator(request.user) and not is_analyst(request.user):
        raise PermissionDenied
    if not can_investigate(request.user, evidence.incident):
        raise PermissionDenied("You cannot access evidence for this incident.")
    response = FileResponse(
        evidence.file.open("rb"),
        as_attachment=True,
        filename=evidence.original_filename,
        content_type=evidence.content_type,
    )
    response["X-Content-Type-Options"] = "nosniff"
    response["Cache-Control"] = "private, no-store"
    return response


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

    alerts = SecurityAlert.objects.select_related(
        "related_user",
        "related_incident",
        "detection_rule",
    )
    if is_analyst(request.user):
        alerts = alerts.filter(
            Q(related_incident__isnull=True)
            | Q(related_incident__assigned_analyst=request.user)
        )
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
