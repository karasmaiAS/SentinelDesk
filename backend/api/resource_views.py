from django.contrib.auth import get_user_model
from django.http import FileResponse
from django.utils.dateparse import parse_date
from django.db import transaction
from django.db.models import Count, Q
from rest_framework import generics, status
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.roles import can_investigate, is_administrator, is_analyst
from incidents.analytics import get_security_analytics
from incidents.models import (
    ActivityLog,
    DetectionRule,
    IndicatorOfCompromise,
    Incident,
    InvestigationEvidence,
    InvestigationFinding,
    InvestigationNote,
    SecurityAlert,
)
from incidents.intelligence import check_indicator, get_indicator_matches
from incidents.related import suggest_related_incidents

from .pagination import ApiPageNumberPagination, ApiResponseMixin
from incidents.detection.queries import get_detection_overview
from incidents.services import log_activity
from .serializers import (
    ActivityLogSerializer,
    AnalyticsQuerySerializer,
    AnalystSerializer,
    AssignmentSerializer,
    IndicatorOfCompromiseSerializer,
    InvestigationEvidenceSerializer,
    InvestigationFindingSerializer,
    InvestigationNoteSerializer,
    SecurityAlertSerializer,
    SecurityAlertStatusSerializer,
    DetectionRuleSerializer,
)


def _accessible_incident(request, incident_id):
    queryset = Incident.objects.select_related("reporter", "assigned_analyst")
    if is_administrator(request.user):
        pass
    elif is_analyst(request.user):
        queryset = queryset.filter(assigned_analyst=request.user)
    else:
        queryset = queryset.filter(reporter=request.user)
    try:
        return queryset.get(pk=incident_id)
    except Incident.DoesNotExist as error:
        raise NotFound("Incident not found.") from error


class IncidentAssignmentView(APIView):
    def get(self, request, incident_id):
        incident = _accessible_incident(request, incident_id)
        analyst = incident.assigned_analyst
        assignment = (
            {
                "analyst": AnalystSerializer(analyst).data,
                "assigned": True,
            }
            if analyst
            else {"analyst": None, "assigned": False}
        )
        return Response(
            {"data": {"incident_id": incident.pk, "assignment": assignment}}
        )

    def post(self, request, incident_id):
        if not is_administrator(request.user):
            raise PermissionDenied("Only administrators can assign incidents.")
        incident = _accessible_incident(request, incident_id)
        serializer = AssignmentSerializer(
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        incident = serializer.update(incident, serializer.validated_data)
        return Response(
            {
                "data": {
                    "incident_id": incident.pk,
                    "assignment": {
                        "analyst": (
                            AnalystSerializer(incident.assigned_analyst).data
                            if incident.assigned_analyst
                            else None
                        ),
                        "assigned": incident.assigned_analyst_id is not None,
                    },
                }
            },
            status=status.HTTP_200_OK,
        )


class IncidentNotesView(generics.ListCreateAPIView):
    serializer_class = InvestigationNoteSerializer
    pagination_class = ApiPageNumberPagination

    def get_incident(self):
        incident = _accessible_incident(self.request, self.kwargs["incident_id"])
        if not can_investigate(self.request.user, incident):
            raise PermissionDenied(
                "Only the assigned analyst or an administrator can access notes."
            )
        return incident

    def get_queryset(self):
        return InvestigationNote.objects.filter(
            incident=self.get_incident()
        ).select_related("analyst")

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["incident"] = self.get_incident()
        return context

    def list(self, request, *args, **kwargs):
        response = super().list(request, *args, **kwargs)
        return response

    def create(self, request, *args, **kwargs):
        incident = self.get_incident()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        note = serializer.save()
        return Response(
            {"data": self.get_serializer(note).data},
            status=status.HTTP_201_CREATED,
        )


class IncidentIndicatorListView(APIView):
    def get_incident(self, request, incident_id):
        incident = _accessible_incident(request, incident_id)
        if not can_investigate(request.user, incident):
            raise PermissionDenied(
                "Only the assigned analyst or an administrator can access indicators."
            )
        return incident

    def get(self, request, incident_id):
        incident = self.get_incident(request, incident_id)
        indicators = IndicatorOfCompromise.objects.filter(incident=incident)
        indicator_type = request.query_params.get("indicator_type")
        if indicator_type:
            if indicator_type not in IndicatorOfCompromise.Type.values:
                raise ValidationError(
                    {"indicator_type": "Select a valid indicator type."}
                )
            indicators = indicators.filter(indicator_type=indicator_type)
        indicator_status = request.query_params.get("status")
        if indicator_status:
            if indicator_status not in IndicatorOfCompromise.Status.values:
                raise ValidationError({"status": "Select a valid indicator status."})
            indicators = indicators.filter(status=indicator_status)
        search = request.query_params.get("search", "").strip()
        if search:
            indicators = indicators.filter(
                Q(value__icontains=search)
                | Q(description__icontains=search)
                | Q(source__icontains=search)
            )
        paginator = ApiPageNumberPagination()
        page = paginator.paginate_queryset(indicators, request, view=self)
        data = IndicatorOfCompromiseSerializer(
            page,
            many=True,
            context={"request": request},
        ).data
        return paginator.get_paginated_response(data)

    def post(self, request, incident_id):
        incident = self.get_incident(request, incident_id)
        serializer = IndicatorOfCompromiseSerializer(
            data=request.data,
            context={"request": request, "incident": incident},
        )
        serializer.is_valid(raise_exception=True)
        indicator = serializer.save()
        return Response(
            {"data": IndicatorOfCompromiseSerializer(
                indicator,
                context={"request": request},
            ).data},
            status=status.HTTP_201_CREATED,
        )


def _accessible_indicator(request, indicator_id):
    try:
        indicator = IndicatorOfCompromise.objects.select_related("incident").get(
            pk=indicator_id
        )
    except IndicatorOfCompromise.DoesNotExist as error:
        raise NotFound("Indicator not found.") from error
    _accessible_incident(request, indicator.incident_id)
    if not can_investigate(request.user, indicator.incident):
        raise PermissionDenied(
            "Only the assigned analyst or an administrator can access indicators."
        )
    return indicator


class IndicatorDetailView(APIView):
    def get(self, request, ioc_id):
        indicator = _accessible_indicator(request, ioc_id)
        return Response(
            {
                "data": IndicatorOfCompromiseSerializer(
                    indicator,
                    context={"request": request},
                ).data
            }
        )

    def patch(self, request, ioc_id):
        indicator = _accessible_indicator(request, ioc_id)
        serializer = IndicatorOfCompromiseSerializer(
            indicator,
            data=request.data,
            partial=True,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        indicator = serializer.save()
        return Response(
            {
                "data": IndicatorOfCompromiseSerializer(
                    indicator,
                    context={"request": request},
                ).data
            }
        )


class IndicatorMatchView(APIView):
    def get(self, request, ioc_id):
        indicator = _accessible_indicator(request, ioc_id)
        return Response({"data": get_indicator_matches(indicator)})

    def post(self, request, ioc_id):
        indicator = _accessible_indicator(request, ioc_id)
        return Response(
            {
                "data": check_indicator(
                    indicator,
                    actor=request.user,
                    request=request,
                )
            }
        )


class RelatedIncidentsView(APIView):
    def get(self, request, incident_id):
        incident = _accessible_incident(request, incident_id)
        if not can_investigate(request.user, incident):
            raise PermissionDenied(
                "Related incidents are not available to this role."
            )
        return Response(
            {
                "data": {
                    "suggestions": suggest_related_incidents(
                        incident=incident,
                        user=request.user,
                    )
                }
            }
        )


class IncidentEvidenceListView(APIView):
    def get_incident(self, request, incident_id):
        incident = _accessible_incident(request, incident_id)
        if not can_investigate(request.user, incident):
            raise PermissionDenied(
                "Only the assigned analyst or an administrator can access evidence."
            )
        return incident

    def get(self, request, incident_id):
        incident = self.get_incident(request, incident_id)
        evidence = InvestigationEvidence.objects.filter(incident=incident)
        paginator = ApiPageNumberPagination()
        page = paginator.paginate_queryset(evidence, request, view=self)
        data = InvestigationEvidenceSerializer(page, many=True).data
        return paginator.get_paginated_response(data)

    def post(self, request, incident_id):
        incident = self.get_incident(request, incident_id)
        serializer = InvestigationEvidenceSerializer(
            data=request.data,
            context={"request": request, "incident": incident},
        )
        serializer.is_valid(raise_exception=True)
        evidence = serializer.save()
        return Response(
            {"data": InvestigationEvidenceSerializer(evidence).data},
            status=status.HTTP_201_CREATED,
        )


class EvidenceDownloadView(APIView):
    def get(self, request, evidence_id):
        try:
            evidence = InvestigationEvidence.objects.select_related(
                "incident"
            ).get(pk=evidence_id)
        except InvestigationEvidence.DoesNotExist as error:
            raise NotFound("Evidence not found.") from error
        _accessible_incident(request, evidence.incident_id)
        if not can_investigate(request.user, evidence.incident):
            raise PermissionDenied(
                "Only the assigned analyst or an administrator can download evidence."
            )
        response = FileResponse(
            evidence.file.open("rb"),
            as_attachment=True,
            filename=evidence.original_filename,
            content_type=evidence.content_type,
        )
        response["X-Content-Type-Options"] = "nosniff"
        response["Cache-Control"] = "private, no-store"
        return response


class InvestigationFindingView(APIView):
    def get_incident(self, request, incident_id):
        incident = _accessible_incident(request, incident_id)
        if not can_investigate(request.user, incident):
            raise PermissionDenied(
                "Investigation findings are not available to this role."
            )
        return incident

    def get(self, request, incident_id):
        incident = self.get_incident(request, incident_id)
        try:
            finding = incident.investigation_finding
        except InvestigationFinding.DoesNotExist:
            finding = None
        return Response(
            {
                "data": (
                    InvestigationFindingSerializer(finding).data
                    if finding is not None
                    else None
                )
            }
        )

    def patch(self, request, incident_id):
        incident = self.get_incident(request, incident_id)
        try:
            finding = incident.investigation_finding
        except InvestigationFinding.DoesNotExist:
            finding = None
        is_create = finding is None
        serializer = InvestigationFindingSerializer(
            finding,
            data=request.data,
            partial=finding is not None,
            context={"request": request, "incident": incident},
        )
        serializer.is_valid(raise_exception=True)
        finding = serializer.save()
        return Response(
            {"data": InvestigationFindingSerializer(finding).data},
            status=status.HTTP_201_CREATED if is_create else status.HTTP_200_OK,
        )


class AlertQuerysetMixin:
    filter_fields = {
        "severity": SecurityAlert.Severity.values,
        "alert_type": SecurityAlert.AlertType.values,
        "status": SecurityAlert.Status.values,
    }

    def filter_queryset(self, queryset):
        queryset = super().filter_queryset(queryset)
        for field, values in self.filter_fields.items():
            value = self.request.query_params.get(field)
            if value:
                if value not in values:
                    raise ValidationError({field: "Select a valid filter value."})
                queryset = queryset.filter(**{field: value})
        rule_identifier = self.request.query_params.get("detection_rule")
        if rule_identifier:
            if not DetectionRule.objects.filter(
                identifier=rule_identifier
            ).exists():
                raise ValidationError(
                    {"detection_rule": "Select a valid detection rule."}
                )
            queryset = queryset.filter(
                detection_rule__identifier=rule_identifier
            )
        related_incident_id = self.request.query_params.get("related_incident")
        if related_incident_id:
            if not related_incident_id.isdecimal():
                raise ValidationError(
                    {"related_incident": "Enter a valid incident ID."}
                )
            incident = _accessible_incident(
                self.request,
                int(related_incident_id),
            )
            queryset = queryset.filter(related_incident=incident)
        return queryset


class SecurityAlertListView(AlertQuerysetMixin, ApiResponseMixin, generics.ListAPIView):
    serializer_class = SecurityAlertSerializer
    search_fields = ("title", "description")
    ordering_fields = ("created_at", "updated_at", "severity", "status")
    queryset = SecurityAlert.objects.select_related(
        "related_user",
        "related_incident",
        "detection_rule",
    ).all()

    def list(self, request, *args, **kwargs):
        response = super().list(request, *args, **kwargs)
        return response

    def get_queryset(self):
        if not is_administrator(self.request.user) and not is_analyst(
            self.request.user
        ):
            raise PermissionDenied("Security alerts are not available to this role.")
        queryset = super().get_queryset()
        if is_analyst(self.request.user):
            queryset = queryset.filter(
                Q(related_incident__isnull=True)
                | Q(related_incident__assigned_analyst=self.request.user)
            )
        return queryset


class SecurityAlertDetailView(APIView):
    def get_alert(self, alert_id):
        if not is_administrator(self.request.user) and not is_analyst(
            self.request.user
        ):
            raise PermissionDenied("Security alerts are not available to this role.")
        queryset = SecurityAlert.objects.select_related(
            "related_user",
            "related_incident",
            "detection_rule",
        )
        if is_analyst(self.request.user):
            queryset = queryset.filter(
                Q(related_incident__isnull=True)
                | Q(related_incident__assigned_analyst=self.request.user)
            )
        try:
            return queryset.get(pk=alert_id)
        except SecurityAlert.DoesNotExist as error:
            raise NotFound("Security alert not found.") from error

    def get(self, request, alert_id):
        alert = self.get_alert(alert_id)
        return Response({"data": SecurityAlertSerializer(alert).data})

    def patch(self, request, alert_id):
        if not is_administrator(request.user):
            raise PermissionDenied("Only administrators can update alert status.")
        alert = self.get_alert(alert_id)
        serializer = SecurityAlertStatusSerializer(
            alert,
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        updated_alert = serializer.save()
        return Response({"data": SecurityAlertSerializer(updated_alert).data})


class ActivityLogQuerysetMixin:
    def get_queryset(self):
        entries = ActivityLog.objects.select_related(
            "actor",
            "incident",
            "incident__assigned_analyst",
        )
        if is_administrator(self.request.user):
            pass
        elif is_analyst(self.request.user):
            entries = entries.filter(incident__assigned_analyst=self.request.user)
        else:
            raise PermissionDenied("Activity logs are not available to this role.")

        params = self.request.query_params
        action = params.get("action")
        if action:
            if action not in ActivityLog.Action.values:
                raise ValidationError({"action": "Select a valid activity action."})
            entries = entries.filter(action=action)
        incident_id = params.get("incident")
        if incident_id:
            if not incident_id.isdecimal():
                raise ValidationError({"incident": "Enter a valid incident ID."})
            entries = entries.filter(incident_id=int(incident_id))
        for parameter, lookup in (
            ("created_after", "created_at__date__gte"),
            ("created_before", "created_at__date__lte"),
        ):
            value = params.get(parameter)
            if value:
                parsed_date = parse_date(value)
                if parsed_date is None:
                    raise ValidationError(
                        {parameter: "Enter a valid date in YYYY-MM-DD format."}
                    )
                entries = entries.filter(**{lookup: parsed_date})
        return entries


class ActivityLogListView(
    ActivityLogQuerysetMixin,
    ApiResponseMixin,
    generics.ListAPIView,
):
    serializer_class = ActivityLogSerializer
    search_fields = ("description", "actor__username")
    ordering_fields = ("created_at", "action")


class ActivityLogDetailView(ActivityLogQuerysetMixin, generics.RetrieveAPIView):
    serializer_class = ActivityLogSerializer
    lookup_url_kwarg = "log_id"
    lookup_field = "pk"

    def retrieve(self, request, *args, **kwargs):
        response = super().retrieve(request, *args, **kwargs)
        return Response({"data": response.data}, status=response.status_code)


class AnalystListView(generics.ListAPIView):
    serializer_class = AnalystSerializer
    pagination_class = ApiPageNumberPagination

    def get_queryset(self):
        if not is_administrator(self.request.user):
            raise PermissionDenied("Only administrators may retrieve analyst accounts.")
        user_model = get_user_model()
        return (
            user_model.objects.filter(is_active=True, is_staff=True)
            .exclude(is_superuser=True)
            .exclude(groups__name="Administrator")
            .order_by("username")
            .distinct()
        )


class DashboardStatisticsView(APIView):
    def get(self, request):
        if is_administrator(request.user):
            incidents = Incident.objects.all()
            alerts = SecurityAlert.objects.all()
            active_users = get_user_model().objects.filter(is_active=True).count()
        elif is_analyst(request.user):
            incidents = Incident.objects.filter(assigned_analyst=request.user)
            alerts = SecurityAlert.objects.filter(
                Q(related_incident__isnull=True)
                | Q(related_incident__assigned_analyst=request.user)
            )
            active_users = None
        else:
            incidents = Incident.objects.filter(reporter=request.user)
            alerts = None
            active_users = None

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
        counts = {
            "total_incidents": incidents.count(),
            "open_incidents": incidents.filter(status=Incident.Status.OPEN).count(),
            "under_investigation_incidents": incidents.filter(
                status=Incident.Status.UNDER_INVESTIGATION
            ).count(),
            "pending_incidents": incidents.filter(
                status=Incident.Status.PENDING
            ).count(),
            "resolved_incidents": incidents.filter(
                status=Incident.Status.RESOLVED
            ).count(),
            "closed_incidents": incidents.filter(
                status=Incident.Status.CLOSED
            ).count(),
            "active_incidents": incidents.exclude(
                status__in=(Incident.Status.RESOLVED, Incident.Status.CLOSED)
            ).count(),
            "critical_incidents": incidents.filter(
                severity=Incident.Severity.CRITICAL
            ).count(),
            "high_severity_incidents": incidents.filter(
                severity=Incident.Severity.HIGH
            ).count(),
            "medium_severity_incidents": incidents.filter(
                severity=Incident.Severity.MEDIUM
            ).count(),
            "low_severity_incidents": incidents.filter(
                severity=Incident.Severity.LOW
            ).count(),
            "total_security_alerts": alerts.count() if alerts is not None else None,
            "active_users": active_users,
            "assigned_incidents": incidents.filter(
                assigned_analyst__isnull=False
            ).count(),
            "incidents_by_category": {
                value: category_counts.get(value, 0)
                for value, _ in Incident.Category.choices
            },
            "incidents_by_severity": {
                value: severity_counts.get(value, 0)
                for value, _ in Incident.Severity.choices
            },
        }
        return Response({"data": counts})


def _require_security_staff(user):
    if not is_administrator(user) and not is_analyst(user):
        raise PermissionDenied("Detection information is not available to this role.")


class SecurityAnalyticsView(APIView):
    def get(self, request):
        _require_security_staff(request.user)
        serializer = AnalyticsQuerySerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        data = get_security_analytics(
            user=request.user,
            **serializer.validated_data,
        )
        return Response({"data": data})


class DetectionRuleListView(APIView):
    def get(self, request):
        _require_security_staff(request.user)
        rules = DetectionRule.objects.all()
        return Response(
            {"data": {"rules": DetectionRuleSerializer(rules, many=True).data}}
        )


class DetectionRuleDetailView(APIView):
    def patch(self, request, identifier):
        if not is_administrator(request.user):
            raise PermissionDenied("Only administrators can change detection rules.")
        try:
            rule = DetectionRule.objects.get(identifier=identifier)
        except DetectionRule.DoesNotExist as error:
            raise NotFound("Detection rule not found.") from error
        serializer = DetectionRuleSerializer(
            rule,
            data=request.data,
            partial=True,
        )
        serializer.is_valid(raise_exception=True)
        with transaction.atomic():
            rule = serializer.save()
            log_activity(
                action=ActivityLog.Action.DETECTION_RULE_UPDATED,
                description=f"Detection rule {rule.identifier} configuration updated.",
                actor=request.user,
                request=request,
            )
        return Response({"data": DetectionRuleSerializer(rule).data})


class DetectionOverviewView(APIView):
    def get(self, request):
        _require_security_staff(request.user)
        if is_analyst(request.user):
            generated_alerts = SecurityAlert.objects.filter(
                auto_generated=True,
            ).filter(
                Q(related_incident__isnull=True)
                | Q(related_incident__assigned_analyst=request.user)
            )
        else:
            generated_alerts = SecurityAlert.objects.filter(auto_generated=True)
        overview = get_detection_overview(request.user)
        overview["recent_generated_alerts"] = SecurityAlertSerializer(
            generated_alerts.select_related(
                "detection_rule",
                "related_user",
                "related_incident",
            )[:5],
            many=True,
        ).data
        return Response(
            {"data": overview}
        )
