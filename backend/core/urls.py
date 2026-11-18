from django.urls import path

from . import views

app_name = "core"

urlpatterns = [
    path("", views.home, name="home"),
    path("admin/", views.soc_dashboard, name="admin_dashboard"),
    path("soc/", views.soc_dashboard, name="soc_dashboard"),
    path("soc/incidents/", views.incident_monitoring, name="incident_monitoring"),
    path(
        "soc/incidents/<int:pk>/",
        views.monitored_incident_detail,
        name="monitored_incident_detail",
    ),
    path("soc/security-alerts/", views.security_alerts, name="security_alerts"),
    path(
        "soc/evidence/<int:evidence_id>/download/",
        views.evidence_download,
        name="evidence_download",
    ),
    path("soc/detection-rules/", views.detection_rules, name="detection_rules"),
    path("soc/activity-logs/", views.activity_logs, name="activity_logs"),
]
