from django.utils.dateparse import parse_date
from rest_framework import generics
from rest_framework.exceptions import PermissionDenied, ValidationError

from accounts.roles import can_investigate, is_administrator, is_analyst
from incidents.models import Incident

from .pagination import ApiResponseMixin
from .serializers import IncidentSerializer


class IncidentQuerysetMixin:
    search_fields = (
        "title",
        "description",
        "reporter__username",
        "reporter__email",
    )
    ordering_fields = ("created_at", "updated_at", "severity", "status", "title")
    ordering = ("-created_at",)

    def get_base_queryset(self):
        incidents = Incident.objects.select_related(
            "reporter",
            "assigned_analyst",
        )
        if is_administrator(self.request.user):
            return incidents
        if is_analyst(self.request.user):
            return incidents.filter(assigned_analyst=self.request.user)
        return incidents.filter(reporter=self.request.user)

    def filter_queryset(self, queryset):
        queryset = super().filter_queryset(queryset)
        params = self.request.query_params
        for field, choices in (
            ("category", Incident.Category.values),
            ("severity", Incident.Severity.values),
            ("status", Incident.Status.values),
        ):
            value = params.get(field)
            if value:
                if value not in choices:
                    raise ValidationError(
                        {field: "Select a valid filter value."}
                    )
                queryset = queryset.filter(**{field: value})

        analyst_id = params.get("assigned_analyst")
        if analyst_id:
            if not is_administrator(self.request.user):
                raise PermissionDenied(
                    "Only administrators can filter by analyst."
                )
            if not analyst_id.isdecimal():
                raise ValidationError(
                    {"assigned_analyst": "Enter a valid user ID."}
                )
            queryset = queryset.filter(assigned_analyst_id=int(analyst_id))

        for parameter, lookup in (
            ("created_after", "created_at__date__gte"),
            ("created_before", "created_at__date__lte"),
        ):
            value = params.get(parameter)
            if value:
                date_value = parse_date(value)
                if date_value is None:
                    raise ValidationError(
                        {parameter: "Enter a valid date in YYYY-MM-DD format."}
                    )
                queryset = queryset.filter(**{lookup: date_value})
        return queryset


class IncidentListCreateView(
    IncidentQuerysetMixin,
    ApiResponseMixin,
    generics.ListCreateAPIView,
):
    serializer_class = IncidentSerializer

    def get_queryset(self):
        return self.get_base_queryset()


class MyIncidentListView(IncidentQuerysetMixin, generics.ListAPIView):
    serializer_class = IncidentSerializer

    def get_queryset(self):
        return Incident.objects.select_related(
            "reporter",
            "assigned_analyst",
        ).filter(reporter=self.request.user)


class AssignedIncidentListView(IncidentQuerysetMixin, generics.ListAPIView):
    serializer_class = IncidentSerializer

    def get_queryset(self):
        if is_administrator(self.request.user):
            return Incident.objects.select_related(
                "reporter",
                "assigned_analyst",
            ).filter(assigned_analyst__isnull=False)
        if is_analyst(self.request.user):
            return Incident.objects.select_related(
                "reporter",
                "assigned_analyst",
            ).filter(assigned_analyst=self.request.user)
        raise PermissionDenied("Only analysts and administrators may view assignments.")


class IncidentDetailView(
    IncidentQuerysetMixin,
    ApiResponseMixin,
    generics.RetrieveUpdateAPIView,
):
    serializer_class = IncidentSerializer

    def get_queryset(self):
        return self.get_base_queryset()

    def perform_update(self, serializer):
        if not can_investigate(self.request.user, serializer.instance):
            raise PermissionDenied(
                "Only the assigned analyst or an administrator can update this incident."
            )
        serializer.save()
