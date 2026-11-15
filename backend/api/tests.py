from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from incidents.models import (
    ActivityLog,
    Incident,
    InvestigationNote,
    LoginAttempt,
    SecurityAlert,
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
