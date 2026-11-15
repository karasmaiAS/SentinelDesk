import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models
from django.db.models import Q


def fill_incident_public_ids(apps, schema_editor):
    Incident = apps.get_model("incidents", "Incident")
    for incident in Incident.objects.filter(public_id__isnull=True).iterator():
        Incident.objects.filter(pk=incident.pk).update(public_id=uuid.uuid4())


def migrate_incident_choices(apps, schema_editor):
    Incident = apps.get_model("incidents", "Incident")
    Incident.objects.filter(status="new").update(status="open")
    Incident.objects.filter(status__in=("in_review", "investigating")).update(
        status="under_investigation"
    )
    Incident.objects.filter(category="account_access").update(
        category="unauthorized_access"
    )
    Incident.objects.filter(category="data_exposure").update(category="data_breach")


class Migration(migrations.Migration):
    dependencies = [
        ("incidents", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="incident",
            name="public_id",
            field=models.UUIDField(blank=True, null=True),
        ),
        migrations.RunPython(fill_incident_public_ids, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="incident",
            name="public_id",
            field=models.UUIDField(
                default=uuid.uuid4,
                editable=False,
                unique=True,
            ),
        ),
        migrations.AddField(
            model_name="incident",
            name="resolution_summary",
            field=models.TextField(blank=True),
        ),
        migrations.AlterField(
            model_name="incident",
            name="reporter",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT,
                related_name="reported_incidents",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AlterField(
            model_name="incident",
            name="category",
            field=models.CharField(
                choices=[
                    ("phishing", "Phishing"),
                    ("malware", "Malware"),
                    ("unauthorized_access", "Unauthorized access"),
                    ("suspicious_login", "Suspicious login"),
                    ("data_breach", "Data breach"),
                    ("social_engineering", "Social engineering"),
                    ("denial_of_service", "Denial of service"),
                    ("other", "Other"),
                ],
                max_length=32,
            ),
        ),
        migrations.AlterField(
            model_name="incident",
            name="status",
            field=models.CharField(
                choices=[
                    ("open", "Open"),
                    ("under_investigation", "Under investigation"),
                    ("pending", "Pending"),
                    ("resolved", "Resolved"),
                    ("closed", "Closed"),
                ],
                default="open",
                max_length=24,
            ),
        ),
        migrations.RunPython(migrate_incident_choices, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="investigationnote",
            name="incident",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT,
                related_name="investigation_notes",
                to="incidents.incident",
            ),
        ),
        migrations.CreateModel(
            name="LoginAttempt",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("username", models.CharField(max_length=150)),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("successful", models.BooleanField(default=False)),
                ("attempted_at", models.DateTimeField(auto_now_add=True)),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="login_attempts",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={"ordering": ("-attempted_at",)},
        ),
        migrations.AddIndex(
            model_name="loginattempt",
            index=models.Index(
                fields=["ip_address", "attempted_at"],
                name="incidents_l_ip_addr_97c879_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="loginattempt",
            index=models.Index(
                fields=["username", "attempted_at"],
                name="incidents_l_username_b4c9f8_idx",
            ),
        ),
        migrations.CreateModel(
            name="SecurityAlert",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("title", models.CharField(max_length=160)),
                ("description", models.TextField()),
                (
                    "alert_type",
                    models.CharField(
                        choices=[
                            ("repeated_failed_logins", "Repeated failed logins"),
                            ("suspicious_login", "Suspicious login activity"),
                            (
                                "multiple_auth_failures",
                                "Multiple authentication failures",
                            ),
                            ("other", "Other"),
                        ],
                        max_length=32,
                    ),
                ),
                (
                    "severity",
                    models.CharField(
                        choices=[
                            ("critical", "Critical"),
                            ("high", "High"),
                            ("medium", "Medium"),
                            ("low", "Low"),
                        ],
                        max_length=16,
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("open", "Open"),
                            ("investigating", "Investigating"),
                            ("resolved", "Resolved"),
                        ],
                        default="open",
                        max_length=16,
                    ),
                ),
                ("source_ip", models.GenericIPAddressField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "related_user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="security_alerts",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={"ordering": ("-created_at",)},
        ),
        migrations.CreateModel(
            name="ActivityLog",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "action",
                    models.CharField(
                        choices=[
                            ("login_success", "Successful login"),
                            ("login_failure", "Failed login"),
                            ("incident_submitted", "Incident submitted"),
                            ("incident_updated", "Incident updated"),
                            ("status_changed", "Incident status changed"),
                            ("severity_changed", "Incident severity changed"),
                            ("assignment_changed", "Analyst assignment changed"),
                            ("note_added", "Investigation note added"),
                            ("account_updated", "Account updated"),
                            ("role_changed", "User role changed"),
                            ("alert_created", "Security alert created"),
                            ("alert_updated", "Security alert updated"),
                            ("other", "Other"),
                        ],
                        max_length=32,
                    ),
                ),
                ("description", models.CharField(max_length=500)),
                ("source_ip", models.GenericIPAddressField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "actor",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="sentineldesk_activity",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "incident",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="activity_entries",
                        to="incidents.incident",
                    ),
                ),
            ],
            options={"ordering": ("-created_at",)},
        ),
        migrations.AddIndex(
            model_name="activitylog",
            index=models.Index(
                fields=["-created_at", "action"],
                name="incidents_a_created_96e346_idx",
            ),
        ),
        migrations.AddConstraint(
            model_name="incident",
            constraint=models.CheckConstraint(
                condition=Q(severity__in=["critical", "high", "medium", "low"]),
                name="incident_valid_severity",
            ),
        ),
        migrations.AddConstraint(
            model_name="incident",
            constraint=models.CheckConstraint(
                condition=Q(
                    status__in=[
                        "open",
                        "under_investigation",
                        "pending",
                        "resolved",
                        "closed",
                    ]
                ),
                name="incident_valid_status",
            ),
        ),
        migrations.AddConstraint(
            model_name="incident",
            constraint=models.CheckConstraint(
                condition=Q(
                    category__in=[
                        "phishing",
                        "malware",
                        "unauthorized_access",
                        "suspicious_login",
                        "data_breach",
                        "social_engineering",
                        "denial_of_service",
                        "other",
                    ]
                ),
                name="incident_valid_category",
            ),
        ),
    ]
