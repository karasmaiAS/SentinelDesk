from django.urls import path

from .incident_views import (
    AssignedIncidentListView,
    IncidentDetailView,
    IncidentListCreateView,
    MyIncidentListView,
)
from .resource_views import (
    ActivityLogDetailView,
    ActivityLogListView,
    AnalystListView,
    DashboardStatisticsView,
    IncidentAssignmentView,
    IncidentNotesView,
    SecurityAlertDetailView,
    SecurityAlertListView,
)
from .views import ApiLoginView, ApiLogoutView, ApiMeView

app_name = "api"

urlpatterns = [
    path("auth/login/", ApiLoginView.as_view(), name="login"),
    path("auth/logout/", ApiLogoutView.as_view(), name="logout"),
    path("auth/me/", ApiMeView.as_view(), name="me"),
    path("incidents/", IncidentListCreateView.as_view(), name="incident-list"),
    path("incidents/my/", MyIncidentListView.as_view(), name="my-incidents"),
    path(
        "incidents/assigned/",
        AssignedIncidentListView.as_view(),
        name="assigned-incidents",
    ),
    path(
        "incidents/<int:pk>/",
        IncidentDetailView.as_view(),
        name="incident-detail",
    ),
    path(
        "incidents/<int:incident_id>/assign/",
        IncidentAssignmentView.as_view(),
        name="incident-assignment",
    ),
    path(
        "incidents/<int:incident_id>/assignments/",
        IncidentAssignmentView.as_view(),
        name="incident-assignments",
    ),
    path(
        "incidents/<int:incident_id>/notes/",
        IncidentNotesView.as_view(),
        name="incident-notes",
    ),
    path("analysts/", AnalystListView.as_view(), name="analysts"),
    path("alerts/", SecurityAlertListView.as_view(), name="alert-list"),
    path(
        "alerts/<int:alert_id>/",
        SecurityAlertDetailView.as_view(),
        name="alert-detail",
    ),
    path("activity-logs/", ActivityLogListView.as_view(), name="activity-log-list"),
    path(
        "activity-logs/<int:log_id>/",
        ActivityLogDetailView.as_view(),
        name="activity-log-detail",
    ),
    path(
        "dashboard/statistics/",
        DashboardStatisticsView.as_view(),
        name="dashboard-statistics",
    ),
]
