from datetime import timedelta
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from incidents.models import (
    ActivityLog,
    DetectionRule,
    IndicatorOfCompromise,
    Incident,
    InvestigationEvidence,
    InvestigationFinding,
    InvestigationNote,
    LoginAttempt,
    SecurityAlert,
    ThreatIntelRecord,
)
from incidents.services import assign_incident


class ApiAuthenticationTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = get_user_model().objects.create_user(
            username="api-user",
            email="api-user@example.com",
            password="SecureApiPass!327",
            first_name="API",
            last_name="User",
        )

    def test_login_returns_token_and_safe_user_summary(self):
        response = self.client.post(
            reverse("api:login"),
            {"username": "api-user", "password": "SecureApiPass!327"},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            set(response.data["data"]["user"]),
            {"id", "username", "display_name", "role"},
        )
        self.assertEqual(response.data["data"]["user"]["username"], "api-user")
        self.assertEqual(response.data["data"]["user"]["display_name"], "API User")
        self.assertEqual(response.data["data"]["user"]["role"], "Regular User")
        self.assertNotIn("password", response.data["data"]["user"])
        self.assertTrue(
            Token.objects.filter(key=response.data["data"]["token"], user=self.user)
            .exists()
        )
        self.assertTrue(
            LoginAttempt.objects.filter(user=self.user, successful=True).exists()
        )

    def test_invalid_credentials_return_401_and_do_not_log_password(self):
        response = self.client.post(
            reverse("api:login"),
            {"username": "api-user", "password": "IncorrectSecret!"},
            format="json",
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["error"]["code"], "authentication_required")
        self.assertNotIn("IncorrectSecret!", str(response.data))
        self.assertTrue(
            LoginAttempt.objects.filter(
                username="api-user",
                successful=False,
            ).exists()
        )
        self.assertFalse(
            ActivityLog.objects.filter(description__contains="IncorrectSecret!").exists()
        )

    def test_inactive_user_cannot_obtain_token(self):
        self.user.is_active = False
        self.user.save(update_fields=("is_active",))

        response = self.client.post(
            reverse("api:login"),
            {"username": "api-user", "password": "SecureApiPass!327"},
            format="json",
        )

        self.assertEqual(response.status_code, 401)
        self.assertFalse(Token.objects.filter(user=self.user).exists())

    def test_me_requires_authentication_and_returns_current_user(self):
        url = reverse("api:me")
        anonymous_response = self.client.get(url)
        self.assertEqual(anonymous_response.status_code, 401)
        self.assertEqual(
            anonymous_response.data["error"]["code"],
            "authentication_required",
        )

        token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["data"]["user"]["id"], self.user.pk)
        self.assertEqual(
            response.data["data"]["user"]["role"],
            "Regular User",
        )

    def test_token_logout_invalidates_token(self):
        token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")

        response = self.client.post(reverse("api:logout"))

        self.assertEqual(response.status_code, 204)
        self.assertFalse(Token.objects.filter(pk=token.pk).exists())
        self.assertEqual(self.client.get(reverse("api:me")).status_code, 401)


class ApiIncidentTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        user_model = get_user_model()
        self.reporter = user_model.objects.create_user(
            username="reporter",
            password="SecureApiPass!327",
        )
        self.other_reporter = user_model.objects.create_user(
            username="other-reporter",
            password="SecureApiPass!327",
        )
        self.analyst = user_model.objects.create_user(
            username="analyst",
            password="SecureApiPass!327",
            is_staff=True,
        )
        self.admin = user_model.objects.create_superuser(
            username="administrator",
            password="SecureApiPass!327",
        )
        self.own_incident = Incident.objects.create(
            title="Reporter phishing report",
            description="Unexpected link in an email.",
            category=Incident.Category.PHISHING,
            severity=Incident.Severity.MEDIUM,
            reporter=self.reporter,
        )
        self.other_incident = Incident.objects.create(
            title="Other user's report",
            description="Private reporter information.",
            category=Incident.Category.MALWARE,
            reporter=self.other_reporter,
        )
        assign_incident(
            actor=self.admin,
            incident=self.own_incident,
            analyst=self.analyst,
        )

    def authenticate_as(self, user):
        token, _ = Token.objects.get_or_create(user=user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")

    def test_regular_user_incident_lists_are_scoped_and_paginated(self):
        self.authenticate_as(self.reporter)

        list_response = self.client.get(reverse("api:incident-list"))
        my_response = self.client.get(reverse("api:my-incidents"))

        self.assertEqual(list_response.status_code, 200)
        self.assertEqual(list_response.data["data"]["count"], 1)
        self.assertEqual(
            list_response.data["data"]["results"][0]["id"],
            self.own_incident.pk,
        )
        self.assertEqual(my_response.data["data"]["count"], 1)
        self.assertNotContains(
            self.client.get(reverse("api:incident-list")),
            "Other user's report",
        )
        self.assertEqual(
            self.client.get(reverse("api:assigned-incidents")).status_code,
            403,
        )

    def test_incident_detail_hides_another_reporters_incident(self):
        self.authenticate_as(self.reporter)

        response = self.client.get(
            reverse("api:incident-detail", args=[self.other_incident.pk])
        )

        self.assertEqual(response.status_code, 404)

    def test_create_incident_uses_authenticated_reporter_and_audit_service(self):
        self.authenticate_as(self.reporter)

        response = self.client.post(
            reverse("api:incident-list"),
            {
                "title": "API phishing report",
                "description": "Suspicious attachment received.",
                "category": Incident.Category.PHISHING,
                "severity": Incident.Severity.HIGH,
                "evidence_reference": "https://evidence.example/report",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.data["data"]["created_at"].endswith("+08:00"))
        incident = Incident.objects.get(title="API phishing report")
        self.assertEqual(incident.reporter, self.reporter)
        self.assertEqual(incident.status, Incident.Status.OPEN)
        self.assertEqual(incident.severity, Incident.Severity.HIGH)
        self.assertTrue(
            ActivityLog.objects.filter(
                incident=incident,
                action=ActivityLog.Action.INCIDENT_SUBMITTED,
            ).exists()
        )

    def test_create_incident_enforces_title_and_description_limits(self):
        self.authenticate_as(self.reporter)
        endpoint = reverse("api:incident-list")
        base_payload = {
            "category": Incident.Category.OTHER,
            "severity": Incident.Severity.MEDIUM,
        }

        valid_response = self.client.post(
            endpoint,
            {
                **base_payload,
                "title": "T" * 200,
                "description": "D" * 5000,
            },
            format="json",
        )
        self.assertEqual(valid_response.status_code, 201)
        self.assertEqual(len(Incident.objects.get(title="T" * 200).description), 5000)

        long_title = self.client.post(
            endpoint,
            {
                **base_payload,
                "title": "T" * 201,
                "description": "Description within limit.",
            },
            format="json",
        )
        self.assertEqual(long_title.status_code, 400)
        self.assertIn(
            "Incident title must be 200 characters or fewer.",
            str(long_title.data),
        )

        long_description = self.client.post(
            endpoint,
            {
                **base_payload,
                "title": "Description too long",
                "description": "D" * 5001,
            },
            format="json",
        )
        self.assertEqual(long_description.status_code, 400)
        self.assertIn(
            "Incident description must be 5,000 characters or fewer.",
            str(long_description.data),
        )

    def test_create_incident_title_requires_at_least_one_letter(self):
        self.authenticate_as(self.reporter)
        endpoint = reverse("api:incident-list")
        examples = (
            ("Phishing Attack", None),
            ("404 Login Attempts", None),
            ("Suspicious Login!!!", None),
            (
                "123456789",
                "Incident title cannot contain only numbers. Include at least one letter.",
            ),
            (
                "@#$%^&*",
                "Incident title cannot contain only special characters. Include at least one letter.",
            ),
            ("!!!Phishing!!!", None),
            ("   ", "Incident title is required."),
        )

        for title, error_message in examples:
            with self.subTest(title=title):
                response = self.client.post(
                    endpoint,
                    {
                        "title": title,
                        "category": Incident.Category.OTHER,
                        "severity": Incident.Severity.MEDIUM,
                        "description": "A test incident description.",
                    },
                    format="json",
                )
                self.assertEqual(response.status_code, 201 if error_message is None else 400)
                if error_message:
                    self.assertIn(error_message, str(response.data))

    def test_create_rejects_reporter_and_assignment_spoofing(self):
        self.authenticate_as(self.reporter)

        response = self.client.post(
            reverse("api:incident-list"),
            {
                "title": "Spoofed report",
                "description": "Must not use supplied identity or assignment.",
                "category": Incident.Category.OTHER,
                "reporter": self.other_reporter.pk,
                "assigned_analyst": self.analyst.pk,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("reporter", response.data["error"]["fields"])
        self.assertIn("assigned_analyst", response.data["error"]["fields"])
        self.assertFalse(Incident.objects.filter(title="Spoofed report").exists())

    def test_analyst_can_list_assigned_incidents_and_update_status(self):
        self.authenticate_as(self.analyst)
        assigned_response = self.client.get(reverse("api:assigned-incidents"))
        detail_url = reverse("api:incident-detail", args=[self.own_incident.pk])

        update_response = self.client.patch(
            detail_url,
            {"status": Incident.Status.PENDING},
            format="json",
        )

        self.assertEqual(assigned_response.data["data"]["count"], 1)
        self.assertEqual(
            assigned_response.data["data"]["results"][0]["id"],
            self.own_incident.pk,
        )
        self.assertEqual(update_response.status_code, 200)
        self.own_incident.refresh_from_db()
        self.assertEqual(self.own_incident.status, Incident.Status.PENDING)
        self.assertEqual(
            self.client.get(
                reverse("api:incident-detail", args=[self.other_incident.pk])
            ).status_code,
            404,
        )

    def test_analyst_cannot_change_severity_and_regular_user_cannot_update(self):
        detail_url = reverse("api:incident-detail", args=[self.own_incident.pk])
        self.authenticate_as(self.analyst)
        analyst_response = self.client.patch(
            detail_url,
            {"severity": Incident.Severity.CRITICAL},
            format="json",
        )
        self.assertEqual(analyst_response.status_code, 400)

        self.authenticate_as(self.reporter)
        reporter_response = self.client.patch(
            detail_url,
            {"status": Incident.Status.PENDING},
            format="json",
        )
        self.assertEqual(reporter_response.status_code, 403)

    def test_administrator_can_change_severity_and_invalid_transition_is_rejected(self):
        self.authenticate_as(self.admin)
        detail_url = reverse("api:incident-detail", args=[self.other_incident.pk])

        update_response = self.client.patch(
            detail_url,
            {"severity": Incident.Severity.CRITICAL},
            format="json",
        )
        invalid_transition = self.client.patch(
            detail_url,
            {"status": Incident.Status.CLOSED},
            format="json",
        )

        self.assertEqual(update_response.status_code, 200)
        self.assertEqual(invalid_transition.status_code, 400)
        self.other_incident.refresh_from_db()
        self.assertEqual(self.other_incident.severity, Incident.Severity.CRITICAL)
        self.assertEqual(self.other_incident.status, Incident.Status.OPEN)

    def test_incident_search_and_filters_return_validated_results(self):
        self.authenticate_as(self.admin)

        filtered_response = self.client.get(
            reverse("api:incident-list"),
            {
                "search": "phishing",
                "category": Incident.Category.PHISHING,
                "severity": Incident.Severity.MEDIUM,
                "created_after": self.own_incident.created_at.date().isoformat(),
            },
        )
        invalid_response = self.client.get(
            reverse("api:incident-list"),
            {"status": "not-a-status"},
        )

        self.assertEqual(filtered_response.status_code, 200)
        self.assertEqual(filtered_response.data["data"]["count"], 1)
        self.assertEqual(invalid_response.status_code, 400)
        self.assertIn("status", invalid_response.data["error"]["fields"])

    def test_assignment_endpoint_requires_admin_and_valid_active_analyst(self):
        assignment_url = reverse(
            "api:incident-assignment",
            args=[self.other_incident.pk],
        )
        self.authenticate_as(self.reporter)
        denied = self.client.post(
            assignment_url,
            {"analyst_id": self.analyst.pk},
            format="json",
        )
        self.assertEqual(denied.status_code, 403)

        self.authenticate_as(self.admin)
        assigned = self.client.post(
            assignment_url,
            {"analyst_id": self.analyst.pk},
            format="json",
        )
        self.assertEqual(assigned.status_code, 200)
        self.assertEqual(
            assigned.data["data"]["assignment"]["analyst"]["id"],
            self.analyst.pk,
        )
        self.other_incident.refresh_from_db()
        self.assertEqual(self.other_incident.assigned_analyst, self.analyst)
        self.assertTrue(
            ActivityLog.objects.filter(
                incident=self.other_incident,
                action=ActivityLog.Action.ASSIGNMENT_CHANGED,
            ).exists()
        )

        inactive = get_user_model().objects.create_user(
            username="inactive-analyst",
            password="SecureApiPass!327",
            is_staff=True,
            is_active=False,
        )
        invalid = self.client.post(
            assignment_url,
            {"analyst_id": inactive.pk},
            format="json",
        )
        self.assertEqual(invalid.status_code, 400)

    def test_assignment_read_endpoint_returns_current_analyst(self):
        self.authenticate_as(self.reporter)

        response = self.client.get(
            reverse("api:incident-assignments", args=[self.own_incident.pk])
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["data"]["assignment"]["assigned"])
        self.assertEqual(
            response.data["data"]["assignment"]["analyst"]["username"],
            self.analyst.username,
        )

    def test_notes_are_private_and_author_is_authenticated_user(self):
        notes_url = reverse("api:incident-notes", args=[self.own_incident.pk])
        self.authenticate_as(self.reporter)
        forbidden = self.client.get(notes_url)
        self.assertEqual(forbidden.status_code, 403)

        self.authenticate_as(self.analyst)
        empty_note = self.client.post(notes_url, {"content": "   "}, format="json")
        self.assertEqual(empty_note.status_code, 400)
        created = self.client.post(
            notes_url,
            {"content": "Reviewed source headers.", "analyst": self.admin.pk},
            format="json",
        )

        self.assertEqual(created.status_code, 201)
        self.assertEqual(
            created.data["data"]["analyst"],
            self.analyst.pk,
        )
        note = InvestigationNote.objects.get(incident=self.own_incident)
        self.assertEqual(note.analyst, self.analyst)
        notes = self.client.get(notes_url)
        self.assertEqual(notes.status_code, 200)
        self.assertEqual(notes.data["data"]["count"], 1)

    def test_security_alert_list_filters_and_admin_status_update(self):
        alert = SecurityAlert.objects.create(
            title="Repeated failures",
            description="Several failed sign-in attempts.",
            alert_type=SecurityAlert.AlertType.REPEATED_FAILED_LOGINS,
            severity=SecurityAlert.Severity.MEDIUM,
        )
        self.authenticate_as(self.analyst)
        listed = self.client.get(
            reverse("api:alert-list"),
            {
                "severity": SecurityAlert.Severity.MEDIUM,
                "alert_type": SecurityAlert.AlertType.REPEATED_FAILED_LOGINS,
            },
        )
        forbidden_update = self.client.patch(
            reverse("api:alert-detail", args=[alert.pk]),
            {"status": SecurityAlert.Status.INVESTIGATING},
            format="json",
        )
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.data["data"]["count"], 1)
        self.assertEqual(forbidden_update.status_code, 403)

        self.authenticate_as(self.admin)
        updated = self.client.patch(
            reverse("api:alert-detail", args=[alert.pk]),
            {"status": SecurityAlert.Status.INVESTIGATING},
            format="json",
        )
        self.assertEqual(updated.status_code, 200)
        alert.refresh_from_db()
        self.assertEqual(alert.status, SecurityAlert.Status.INVESTIGATING)
        invalid_filter = self.client.get(
            reverse("api:alert-list"),
            {"severity": "urgent"},
        )
        self.assertEqual(invalid_filter.status_code, 400)

    def test_related_alert_filter_checks_incident_access(self):
        own_alert = SecurityAlert.objects.create(
            title="Alert for assigned incident",
            description="Associated with the analyst's incident.",
            alert_type=SecurityAlert.AlertType.OTHER,
            severity=SecurityAlert.Severity.MEDIUM,
            related_incident=self.own_incident,
        )
        other_alert = SecurityAlert.objects.create(
            title="Alert for unassigned incident",
            description="Must not be exposed through the incident workspace.",
            alert_type=SecurityAlert.AlertType.OTHER,
            severity=SecurityAlert.Severity.LOW,
            related_incident=self.other_incident,
        )
        url = reverse("api:alert-list")
        self.authenticate_as(self.analyst)

        visible = self.client.get(url, {"related_incident": self.own_incident.pk})
        hidden = self.client.get(url, {"related_incident": self.other_incident.pk})
        invalid = self.client.get(url, {"related_incident": "not-an-id"})

        self.assertEqual(visible.status_code, 200)
        self.assertEqual(visible.data["data"]["count"], 1)
        self.assertEqual(visible.data["data"]["results"][0]["id"], own_alert.pk)
        self.assertEqual(hidden.status_code, 404)
        self.assertEqual(invalid.status_code, 400)

        self.authenticate_as(self.admin)
        admin_visible = self.client.get(
            url,
            {"related_incident": self.other_incident.pk},
        )
        self.assertEqual(admin_visible.status_code, 200)
        self.assertEqual(
            admin_visible.data["data"]["results"][0]["id"],
            other_alert.pk,
        )

    def test_activity_logs_are_read_only_and_role_scoped(self):
        entry = ActivityLog.objects.create(
            actor=self.analyst,
            incident=self.own_incident,
            action=ActivityLog.Action.NOTE_ADDED,
            description="Investigation note added.",
        )
        list_url = reverse("api:activity-log-list")
        self.authenticate_as(self.analyst)
        analyst_logs = self.client.get(
            list_url,
            {"action": ActivityLog.Action.NOTE_ADDED},
        )
        self.assertEqual(analyst_logs.status_code, 200)
        self.assertEqual(analyst_logs.data["data"]["count"], 1)
        self.assertEqual(
            self.client.get(
                reverse("api:activity-log-detail", args=[entry.pk])
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.post(list_url, {"description": "Injected log"}).status_code,
            405,
        )

        self.authenticate_as(self.reporter)
        self.assertEqual(self.client.get(list_url).status_code, 403)

    def test_statistics_are_database_backed_and_role_scoped(self):
        self.authenticate_as(self.admin)
        admin_stats = self.client.get(reverse("api:dashboard-statistics"))
        self.assertEqual(admin_stats.status_code, 200)
        self.assertEqual(admin_stats.data["data"]["total_incidents"], 2)
        self.assertEqual(admin_stats.data["data"]["assigned_incidents"], 1)
        self.assertEqual(
            admin_stats.data["data"]["incidents_by_category"]["phishing"],
            1,
        )

        self.authenticate_as(self.analyst)
        analyst_stats = self.client.get(reverse("api:dashboard-statistics"))
        self.assertEqual(analyst_stats.data["data"]["total_incidents"], 1)
        self.assertIsNone(analyst_stats.data["data"]["active_users"])

        self.authenticate_as(self.reporter)
        reporter_stats = self.client.get(reverse("api:dashboard-statistics"))
        self.assertEqual(reporter_stats.data["data"]["total_incidents"], 1)
        self.assertIsNone(reporter_stats.data["data"]["total_security_alerts"])

    def test_analyst_dashboard_statistics_hide_unassigned_alerts(self):
        SecurityAlert.objects.create(
            title="Assigned incident alert",
            description="Visible to the current analyst.",
            alert_type=SecurityAlert.AlertType.OTHER,
            severity=SecurityAlert.Severity.HIGH,
            related_incident=self.own_incident,
        )
        SecurityAlert.objects.create(
            title="Other analyst alert",
            description="Must stay hidden from the assigned analyst.",
            alert_type=SecurityAlert.AlertType.OTHER,
            severity=SecurityAlert.Severity.LOW,
            related_incident=self.other_incident,
        )

        self.authenticate_as(self.analyst)
        response = self.client.get(reverse("api:dashboard-statistics"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["data"]["total_incidents"], 1)
        self.assertEqual(response.data["data"]["total_security_alerts"], 1)
        self.assertEqual(
            response.data["data"]["incidents_by_category"]["phishing"],
            1,
        )

        self.authenticate_as(self.admin)
        admin_stats = self.client.get(reverse("api:dashboard-statistics"))
        self.assertEqual(admin_stats.data["data"]["total_security_alerts"], 2)

    def test_analyst_directory_is_admin_only(self):
        self.authenticate_as(self.analyst)
        self.assertEqual(self.client.get(reverse("api:analysts")).status_code, 403)

        self.authenticate_as(self.admin)
        response = self.client.get(reverse("api:analysts"))
        self.assertEqual(response.status_code, 200)
        usernames = [
            row["username"]
            for row in response.data["data"]["results"]
        ]
        self.assertIn(self.analyst.username, usernames)
        self.assertNotIn(self.admin.username, usernames)


class DetectionApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        user_model = get_user_model()
        self.reporter = user_model.objects.create_user(
            username="detection-reporter",
            password="SecureApiPass!327",
        )
        self.analyst = user_model.objects.create_user(
            username="detection-analyst",
            password="SecureApiPass!327",
            is_staff=True,
        )
        self.admin = user_model.objects.create_superuser(
            username="detection-admin",
            password="SecureApiPass!327",
        )

    def authenticate_as(self, user):
        token, _ = Token.objects.get_or_create(user=user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")

    def test_detection_overview_and_rules_are_available_only_to_security_staff(self):
        overview_url = reverse("api:detection-overview")
        rules_url = reverse("api:detection-rules")
        self.assertEqual(self.client.get(overview_url).status_code, 401)

        self.authenticate_as(self.reporter)
        self.assertEqual(self.client.get(overview_url).status_code, 403)
        self.assertEqual(self.client.get(rules_url).status_code, 403)

        self.authenticate_as(self.analyst)
        overview = self.client.get(overview_url)
        rules = self.client.get(rules_url)
        self.assertEqual(overview.status_code, 200)
        self.assertGreaterEqual(overview.data["data"]["total_rules"], 5)
        self.assertEqual(rules.status_code, 200)
        self.assertIn(
            "multiple_failed_logins",
            {rule["identifier"] for rule in rules.data["data"]["rules"]},
        )

    def test_only_administrators_can_change_validated_detection_configuration(self):
        rule = DetectionRule.objects.get(identifier="multiple_failed_logins")
        url = reverse("api:detection-rule-detail", args=[rule.identifier])

        self.authenticate_as(self.analyst)
        self.assertEqual(
            self.client.patch(url, {"threshold": 7}, format="json").status_code,
            403,
        )

        self.authenticate_as(self.admin)
        updated = self.client.patch(
            url,
            {"threshold": 7, "window_seconds": 600},
            format="json",
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.data["data"]["threshold"], 7)
        self.assertEqual(updated.data["data"]["window_seconds"], 600)

        invalid = self.client.patch(
            url,
            {"threshold": 10001},
            format="json",
        )
        self.assertEqual(invalid.status_code, 400)
        rule.refresh_from_db()
        self.assertEqual(rule.threshold, 7)

        zero_threshold = self.client.patch(
            url,
            {"threshold": 0},
            format="json",
        )
        self.assertEqual(zero_threshold.status_code, 400)
        rule.refresh_from_db()
        self.assertEqual(rule.threshold, 7)

        immutable = self.client.patch(
            url,
            {"name": "Changed rule name"},
            format="json",
        )
        self.assertEqual(immutable.status_code, 400)
        self.assertTrue(
            ActivityLog.objects.filter(
                actor=self.admin,
                action=ActivityLog.Action.DETECTION_RULE_UPDATED,
            ).exists()
        )

    def test_alert_serialization_includes_detection_metadata_and_rule_filter(self):
        rule = DetectionRule.objects.get(identifier="multiple_failed_logins")
        alert = SecurityAlert.objects.create(
            title="Repeated failures",
            description="Threshold reached.",
            alert_type=SecurityAlert.AlertType.REPEATED_FAILED_LOGINS,
            severity=SecurityAlert.Severity.HIGH,
            auto_generated=True,
            detection_rule=rule,
        )
        self.authenticate_as(self.analyst)

        response = self.client.get(
            reverse("api:alert-list"),
            {"detection_rule": rule.identifier},
        )

        self.assertEqual(response.status_code, 200)
        serialized = response.data["data"]["results"][0]
        self.assertEqual(serialized["id"], alert.pk)
        self.assertTrue(serialized["auto_generated"])
        self.assertEqual(
            serialized["detection_rule_identifier"],
            rule.identifier,
        )


class IncidentIndicatorApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        user_model = get_user_model()
        self.admin = user_model.objects.create_superuser(
            username="ioc-admin",
            password="SecureIocPass!327",
        )
        self.analyst = user_model.objects.create_user(
            username="ioc-analyst",
            password="SecureIocPass!327",
            is_staff=True,
        )
        self.other_analyst = user_model.objects.create_user(
            username="ioc-other-analyst",
            password="SecureIocPass!327",
            is_staff=True,
        )
        self.reporter = user_model.objects.create_user(
            username="ioc-reporter",
            password="SecureIocPass!327",
        )
        self.incident = Incident.objects.create(
            title="IOC workspace incident",
            description="Indicator validation test.",
            category=Incident.Category.SUSPICIOUS_LOGIN,
            reporter=self.reporter,
        )
        self.other_incident = Incident.objects.create(
            title="Other analyst incident",
            description="Must remain outside this analyst's workspace.",
            category=Incident.Category.MALWARE,
            reporter=self.reporter,
        )
        assign_incident(
            actor=self.admin,
            incident=self.incident,
            analyst=self.analyst,
        )
        assign_incident(
            actor=self.admin,
            incident=self.other_incident,
            analyst=self.other_analyst,
        )

    def authenticate_as(self, user):
        token, _ = Token.objects.get_or_create(user=user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")

    def test_indicator_creation_normalizes_values_and_reports_no_intel_as_inconclusive(self):
        self.authenticate_as(self.analyst)
        response = self.client.post(
            reverse("api:incident-ioc-list", args=[self.incident.pk]),
            {
                "indicator_type": IndicatorOfCompromise.Type.DOMAIN,
                "value": "Example.COM.",
                "source": "Analyst observation",
                "confidence": 80,
                "risk": IndicatorOfCompromise.Risk.MEDIUM,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        data = response.data["data"]
        self.assertEqual(data["normalized_value"], "example.com")
        self.assertEqual(
            data["match_status"],
            IndicatorOfCompromise.MatchStatus.INCONCLUSIVE,
        )
        self.assertEqual(data["match_result"]["matches"], [])
        self.assertIn("inconclusive", data["match_result"]["explanation"].lower())
        self.assertTrue(
            ActivityLog.objects.filter(
                incident=self.incident,
                action=ActivityLog.Action.IOC_DISCOVERED,
            ).exists()
        )

        duplicate = self.client.post(
            reverse("api:incident-ioc-list", args=[self.incident.pk]),
            {
                "indicator_type": IndicatorOfCompromise.Type.DOMAIN,
                "value": "example.com",
                "source": "Second observation",
            },
            format="json",
        )
        self.assertEqual(duplicate.status_code, 400)
        self.assertEqual(IndicatorOfCompromise.objects.count(), 1)

    def test_exact_local_intelligence_match_reports_source_and_confidence(self):
        record = ThreatIntelRecord(
            indicator_type=IndicatorOfCompromise.Type.SHA256,
            value="a" * 64,
            source="Local incident response feed",
            confidence=92,
            classification="confirmed-malicious",
            notes="Verified in an internal response.",
        )
        record.full_clean()
        record.save()
        self.authenticate_as(self.analyst)

        response = self.client.post(
            reverse("api:incident-ioc-list", args=[self.incident.pk]),
            {
                "indicator_type": IndicatorOfCompromise.Type.SHA256,
                "value": "A" * 64,
                "source": "Analyst observation",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        data = response.data["data"]
        self.assertEqual(
            data["match_status"],
            IndicatorOfCompromise.MatchStatus.MATCHED,
        )
        self.assertEqual(
            data["match_result"]["matches"][0]["source"],
            "Local incident response feed",
        )
        self.assertEqual(data["match_result"]["matches"][0]["confidence"], 92)

    def test_indicator_type_validation_and_analyst_incident_scope(self):
        self.authenticate_as(self.analyst)
        url = reverse("api:incident-ioc-list", args=[self.incident.pk])
        invalid = (
            (IndicatorOfCompromise.Type.IPV4, "2001:db8::1"),
            (IndicatorOfCompromise.Type.DOMAIN, "not a domain"),
            (IndicatorOfCompromise.Type.URL, "ftp://example.com/file"),
            (IndicatorOfCompromise.Type.MD5, "z" * 32),
            (IndicatorOfCompromise.Type.SHA1, "a" * 39),
            (IndicatorOfCompromise.Type.SHA256, "a" * 65),
        )
        for indicator_type, value in invalid:
            with self.subTest(indicator_type=indicator_type, value=value):
                response = self.client.post(
                    url,
                    {
                        "indicator_type": indicator_type,
                        "value": value,
                        "source": "Analyst observation",
                    },
                    format="json",
                )
                self.assertEqual(response.status_code, 400)

        forbidden = self.client.get(
            reverse("api:incident-ioc-list", args=[self.other_incident.pk])
        )
        self.assertEqual(forbidden.status_code, 404)

        self.authenticate_as(self.reporter)
        denied = self.client.get(url)
        self.assertEqual(denied.status_code, 403)


class InvestigationWorkspaceApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        user_model = get_user_model()
        self.admin = user_model.objects.create_superuser(
            username="workspace-admin",
            password="SecureWorkspacePass!327",
        )
        self.analyst = user_model.objects.create_user(
            username="workspace-analyst",
            password="SecureWorkspacePass!327",
            is_staff=True,
        )
        self.other_analyst = user_model.objects.create_user(
            username="workspace-other",
            password="SecureWorkspacePass!327",
            is_staff=True,
        )
        self.reporter = user_model.objects.create_user(
            username="workspace-reporter",
            password="SecureWorkspacePass!327",
        )
        self.incident = Incident.objects.create(
            title="Investigation workspace incident",
            description="Workspace access-control test.",
            category=Incident.Category.PHISHING,
            reporter=self.reporter,
        )
        self.other_incident = Incident.objects.create(
            title="Other analyst investigation",
            description="Private from the first analyst.",
            category=Incident.Category.MALWARE,
            reporter=self.reporter,
        )
        assign_incident(
            actor=self.admin,
            incident=self.incident,
            analyst=self.analyst,
        )
        assign_incident(
            actor=self.admin,
            incident=self.other_incident,
            analyst=self.other_analyst,
        )

    def authenticate_as(self, user):
        token, _ = Token.objects.get_or_create(user=user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")

    def test_evidence_upload_validation_private_download_and_role_scope(self):
        storage = InvestigationEvidence._meta.get_field("file").storage
        with TemporaryDirectory() as evidence_dir:
            with patch.object(storage, "location", evidence_dir):
                self.authenticate_as(self.analyst)
                response = self.client.post(
                    reverse("api:incident-evidence", args=[self.incident.pk]),
                    {
                        "file": SimpleUploadedFile(
                            "..\\private.txt",
                            b"Incident evidence",
                            content_type="text/plain",
                        ),
                        "description": "Captured log file",
                        "classification": "restricted",
                    },
                    format="multipart",
                )

                self.assertEqual(response.status_code, 201)
                data = response.data["data"]
                evidence = InvestigationEvidence.objects.get(
                    incident=self.incident
                )
                self.assertEqual(data["id"], evidence.pk)
                self.assertEqual(data["original_filename"], "private.txt")
                self.assertNotIn("file", data)
                self.assertNotIn("url", data)
                self.assertTrue(evidence.file.path.startswith(evidence_dir))
                self.assertNotIn("private.txt", evidence.file.name)

                download = self.client.get(
                    reverse("api:evidence-download", args=[evidence.pk])
                )
                self.assertEqual(download.status_code, 200)
                downloaded_content = b"".join(download.streaming_content)
                download.close()
                self.assertEqual(downloaded_content, b"Incident evidence")
                self.assertEqual(
                    download["X-Content-Type-Options"],
                    "nosniff",
                )
                self.assertIn("private", download["Cache-Control"])

                denied = self.client.get(
                    reverse("api:incident-evidence", args=[self.other_incident.pk])
                )
                self.assertEqual(denied.status_code, 404)

                invalid = self.client.post(
                    reverse("api:incident-evidence", args=[self.incident.pk]),
                    {
                        "file": SimpleUploadedFile(
                            "invalid.json",
                            b"{not valid json}",
                            content_type="application/json",
                        ),
                        "description": "Invalid JSON evidence",
                    },
                    format="multipart",
                )
                self.assertEqual(invalid.status_code, 400)
                self.assertEqual(
                    InvestigationEvidence.objects.filter(
                        incident=self.incident
                    ).count(),
                    1,
                )

    def test_findings_are_scoped_and_can_only_be_finalized_after_resolution(self):
        findings_url = reverse("api:incident-findings", args=[self.incident.pk])
        self.authenticate_as(self.analyst)
        self.assertIsNone(self.client.get(findings_url).data["data"])

        draft = {
            "summary": "Suspicious message confirmed.",
            "findings": "The link redirected to a credential collection page.",
            "evidence_reviewed": "Original message and URL logs.",
            "actions_performed": "Blocked the URL.",
            "recommended_remediation": "Reset affected credentials.",
            "final_disposition": "confirmed",
        }
        premature = self.client.patch(
            findings_url,
            {**draft, "finalize": True},
            format="json",
        )
        self.assertEqual(premature.status_code, 400)
        self.assertFalse(InvestigationFinding.objects.exists())

        saved = self.client.patch(findings_url, draft, format="json")
        self.assertEqual(saved.status_code, 201)
        self.assertFalse(saved.data["data"]["is_finalized"])

        self.incident.status = Incident.Status.RESOLVED
        self.incident.resolution_summary = "URL blocked and credentials reset."
        self.incident.save(update_fields=("status", "resolution_summary"))
        finalized = self.client.patch(
            findings_url,
            {"finalize": True},
            format="json",
        )
        self.assertEqual(finalized.status_code, 200)
        self.assertTrue(finalized.data["data"]["is_finalized"])
        self.assertEqual(finalized.data["data"]["finalized_by_username"], self.analyst.username)

        locked = self.client.patch(
            findings_url,
            {"summary": "Changed after finalization."},
            format="json",
        )
        self.assertEqual(locked.status_code, 400)

        self.authenticate_as(self.other_analyst)
        self.assertEqual(self.client.get(findings_url).status_code, 404)

    def test_related_incidents_only_suggest_incidents_visible_to_analyst(self):
        visible_incident = Incident.objects.create(
            title="Visible shared-indicator incident",
            description="Assigned to this analyst.",
            category=Incident.Category.MALWARE,
            reporter=self.reporter,
        )
        assign_incident(
            actor=self.admin,
            incident=visible_incident,
            analyst=self.analyst,
        )
        for incident in (self.incident, visible_incident, self.other_incident):
            indicator = IndicatorOfCompromise(
                incident=incident,
                indicator_type=IndicatorOfCompromise.Type.DOMAIN,
                value="shared.example",
                source="Analyst observation",
                added_by=self.analyst,
            )
            indicator.full_clean()
            indicator.save()

        self.authenticate_as(self.analyst)
        response = self.client.get(
            reverse("api:incident-related", args=[self.incident.pk])
        )
        self.assertEqual(response.status_code, 200)
        suggestions = response.data["data"]["suggestions"]
        self.assertEqual(
            [item["incident_id"] for item in suggestions],
            [visible_incident.pk],
        )
        self.assertEqual(
            suggestions[0]["shared_indicators"][0]["value"],
            "shared.example",
        )
        self.assertIn("review", suggestions[0]["relationship"].lower())

        self.authenticate_as(self.reporter)
        denied = self.client.get(
            reverse("api:incident-related", args=[self.incident.pk])
        )
        self.assertEqual(denied.status_code, 403)


class SecurityAnalyticsApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        user_model = get_user_model()
        self.admin = user_model.objects.create_superuser(
            username="analytics-api-admin",
            password="SecureApiPass!327",
        )
        self.analyst = user_model.objects.create_user(
            username="analytics-api-analyst",
            password="SecureApiPass!327",
            is_staff=True,
        )
        self.other_analyst = user_model.objects.create_user(
            username="analytics-api-other",
            password="SecureApiPass!327",
            is_staff=True,
        )
        self.reporter = user_model.objects.create_user(
            username="analytics-api-reporter",
            password="SecureApiPass!327",
        )
        self.incident = Incident.objects.create(
            title="Analytics API incident",
            description="Assigned to the authorized analyst.",
            category=Incident.Category.PHISHING,
            reporter=self.reporter,
        )
        self.other_incident = Incident.objects.create(
            title="Other analyst private incident",
            description="Must not leak into analyst metrics.",
            category=Incident.Category.MALWARE,
            reporter=self.reporter,
        )
        assign_incident(
            actor=self.admin,
            incident=self.incident,
            analyst=self.analyst,
        )
        assign_incident(
            actor=self.admin,
            incident=self.other_incident,
            analyst=self.other_analyst,
        )
        self.unassigned = Incident.objects.create(
            title="Unassigned API incident",
            description="Visible to administrators only in workload counts.",
            category=Incident.Category.OTHER,
            reporter=self.reporter,
        )
        rule = DetectionRule.objects.get(identifier="multiple_failed_logins")
        SecurityAlert.objects.create(
            title="Analytics API generated alert",
            description="Generated from saved event data.",
            alert_type=SecurityAlert.AlertType.REPEATED_FAILED_LOGINS,
            severity=SecurityAlert.Severity.HIGH,
            auto_generated=True,
            detection_rule=rule,
        )
        SecurityAlert.objects.create(
            title="Analytics API manual alert",
            description="Saved manual alert.",
            alert_type=SecurityAlert.AlertType.OTHER,
            severity=SecurityAlert.Severity.LOW,
            auto_generated=False,
        )

    def authenticate_as(self, user):
        token, _ = Token.objects.get_or_create(user=user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")

    def test_analytics_endpoint_returns_real_statistics_and_trends(self):
        self.authenticate_as(self.admin)
        today = timezone.localdate()
        response = self.client.get(
            reverse("api:analytics"),
            {
                "start_date": (today - timedelta(days=6)).isoformat(),
                "end_date": today.isoformat(),
                "granularity": "weekly",
            },
        )

        self.assertEqual(response.status_code, 200)
        data = response.data["data"]
        self.assertEqual(data["filters"]["granularity"], "weekly")
        self.assertEqual(data["incident_statistics"]["total_incidents"], 3)
        self.assertEqual(data["incident_statistics"]["period"]["total"], 3)
        self.assertEqual(data["alert_statistics"]["total_alerts"], 2)
        self.assertEqual(data["alert_statistics"]["generated_alerts"], 1)
        self.assertEqual(data["alert_statistics"]["manual_alerts"], 1)
        self.assertEqual(data["alert_statistics"]["period"]["total"], 2)
        self.assertEqual(
            data["analyst_workload"]["unassigned_incidents"],
            1,
        )

    def test_analytics_is_authenticated_and_analyst_incident_data_is_scoped(self):
        url = reverse("api:analytics")
        self.assertEqual(self.client.get(url).status_code, 401)

        self.authenticate_as(self.reporter)
        self.assertEqual(self.client.get(url).status_code, 403)

        self.authenticate_as(self.analyst)
        response = self.client.get(url, {"days": "7"})
        self.assertEqual(response.status_code, 200)
        data = response.data["data"]
        self.assertEqual(data["incident_statistics"]["total_incidents"], 1)
        self.assertEqual(
            [row["username"] for row in data["analyst_workload"]["analysts"]],
            [self.analyst.username],
        )
        self.assertIsNone(data["analyst_workload"]["unassigned_incidents"])

    def test_analytics_rejects_invalid_date_ranges_and_granularity(self):
        self.authenticate_as(self.admin)
        url = reverse("api:analytics")
        invalid_ranges = (
            {"start_date": "2026-11-20", "end_date": "2026-11-10"},
            {"start_date": "not-a-date"},
            {"days": "7", "start_date": "2026-11-10"},
            {"granularity": "hourly"},
            {"start_date": "2010-01-01", "end_date": "2026-11-16"},
        )
        for params in invalid_ranges:
            with self.subTest(params=params):
                self.assertEqual(self.client.get(url, params).status_code, 400)
