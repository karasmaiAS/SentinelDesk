from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.staticfiles import finders
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from incidents.models import ActivityLog, Incident, InvestigationNote, SecurityAlert
from incidents.services import assign_incident


class SharedDesignSystemTests(TestCase):
    def test_home_redirects_to_login_page(self):
        response = self.client.get(reverse("core:home"))

        self.assertRedirects(response, reverse("accounts:login"))

    def test_home_redirects_authenticated_reporter_to_user_dashboard(self):
        user = get_user_model().objects.create_user(
            username="reporter",
            password="StrongPassword!327",
        )
        self.client.force_login(user)

        response = self.client.get(reverse("core:home"))

        self.assertRedirects(response, reverse("incidents:dashboard"))

    def test_home_redirects_authenticated_staff_to_custom_admin_dashboard(self):
        staff_user = get_user_model().objects.create_user(
            username="staff",
            password="StrongPassword!327",
            is_staff=True,
        )
        self.client.force_login(staff_user)

        response = self.client.get(reverse("core:home"))

        self.assertRedirects(response, reverse("core:admin_dashboard"))

    def test_login_page_renders_shared_tokens_and_stylesheet(self):
        response = self.client.get(reverse("accounts:login"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "--sd-color-background: #0B1220;")
        self.assertContains(response, "core/css/sentineldesk.css")
        self.assertContains(response, "SentinelDesk")
        self.assertNotContains(response, "Admin dashboard")
        self.assertNotContains(response, 'aria-label="Main navigation"')
        self.assertNotContains(response, "Workspace")

    def test_login_and_registration_pages_have_no_public_sidebar(self):
        for route_name in ("accounts:login", "accounts:register"):
            with self.subTest(route=route_name):
                response = self.client.get(reverse(route_name))

                self.assertEqual(response.status_code, 200)
                self.assertNotContains(response, 'aria-label="Main navigation"')
                self.assertNotContains(response, "Workspace")

    def test_stylesheet_is_discoverable_and_contains_layout_styles(self):
        stylesheet = finders.find("core/css/sentineldesk.css")

        self.assertIsNotNone(stylesheet)
        with open(stylesheet, encoding="utf-8") as file:
            css = file.read()
        self.assertIn(".sd-shell", css)
        self.assertIn("@media (max-width: 800px)", css)

    def test_authenticated_navigation_shows_reporter_pages(self):
        user = get_user_model().objects.create_user(
            username="reporter",
            password="StrongPassword!327",
        )
        self.client.force_login(user)

        response = self.client.get(reverse("incidents:dashboard"))

        self.assertContains(response, "Submit incident")
        self.assertContains(response, "My incidents")
        self.assertContains(response, "Regular User")
        self.assertNotContains(response, ">Overview<")
        self.assertNotContains(response, "Administration")
        self.assertContains(response, 'aria-label="Main navigation"')


class SocDashboardTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_superuser(
            username="socadmin",
            email="socadmin@example.com",
            password="StrongPassword!327",
        )
        self.reporter = get_user_model().objects.create_user(
            username="reporter",
            password="StrongPassword!327",
        )

    def test_staff_dashboard_uses_real_incident_and_user_statistics(self):
        current_incident = Incident.objects.create(
            title="Critical phishing report",
            description="Reported today.",
            category=Incident.Category.PHISHING,
            severity=Incident.Severity.CRITICAL,
            reporter=self.reporter,
        )
        resolved_incident = Incident.objects.create(
            title="Resolved malware report",
            description="Reported last week.",
            category=Incident.Category.MALWARE,
            severity=Incident.Severity.MEDIUM,
            status=Incident.Status.RESOLVED,
            reporter=self.reporter,
        )
        Incident.objects.filter(pk=resolved_incident.pk).update(
            created_at=timezone.now() - timedelta(days=8)
        )
        self.client.force_login(self.admin)

        response = self.client.get(reverse("core:soc_dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["total_incidents"], 2)
        self.assertEqual(response.context["open_incidents"], 1)
        self.assertEqual(response.context["critical_incidents"], 1)
        self.assertEqual(response.context["resolved_incidents"], 1)
        self.assertEqual(response.context["active_users"], 2)
        self.assertEqual(response.context["severity_chart"]["values"], [1, 0, 1, 0])
        self.assertEqual(
            response.context["category_chart"]["values"],
            [1, 1, 0, 0, 0, 0, 0, 0],
        )
        self.assertEqual(sum(response.context["trend_chart"]["values"]), 1)
        self.assertContains(response, current_incident.title)
        self.assertContains(response, "Admin Dashboard")

    def test_regular_user_cannot_access_soc_dashboard(self):
        self.client.force_login(self.reporter)

        response = self.client.get(reverse("core:soc_dashboard"))

        self.assertEqual(response.status_code, 403)

    def test_staff_navigation_has_soc_dashboard_and_admin_fallback(self):
        self.client.force_login(self.admin)

        response = self.client.get(reverse("core:admin_dashboard"))

        self.assertContains(response, "Admin dashboard")
        self.assertContains(response, "Django admin (fallback)")
        self.assertContains(response, "Incident monitoring")
        self.assertNotContains(response, "Submit incident")
        self.assertNotContains(response, "My incidents")

    def test_admin_url_uses_custom_dashboard_and_builtin_admin_has_fallback(self):
        self.client.force_login(self.admin)

        dashboard_response = self.client.get("/admin/")
        fallback_response = self.client.get(reverse("admin:index"))
        view_site_response = self.client.get(reverse("core:home"))

        self.assertEqual(dashboard_response.status_code, 200)
        self.assertContains(dashboard_response, "Admin Dashboard")
        self.assertNotContains(dashboard_response, "Site administration")
        self.assertEqual(fallback_response.status_code, 200)
        self.assertContains(fallback_response, "Site administration")
        self.assertRedirects(view_site_response, reverse("core:admin_dashboard"))


class IncidentMonitoringTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_superuser(
            username="monitoradmin",
            email="monitoradmin@example.com",
            password="StrongPassword!327",
        )
        self.reporter = get_user_model().objects.create_user(
            username="reporter",
            email="reporter@example.com",
            password="StrongPassword!327",
        )
        self.phishing_incident = Incident.objects.create(
            title="Suspicious phishing email",
            description="Unexpected email link.",
            category=Incident.Category.PHISHING,
            severity=Incident.Severity.HIGH,
            reporter=self.reporter,
        )
        self.analyst = get_user_model().objects.create_user(
            username="analyst",
            password="StrongPassword!327",
            is_staff=True,
        )
        Incident.objects.create(
            title="Malware report",
            description="Endpoint warning.",
            category=Incident.Category.MALWARE,
            severity=Incident.Severity.MEDIUM,
            status=Incident.Status.UNDER_INVESTIGATION,
            reporter=self.reporter,
        )

    def test_staff_can_search_and_filter_incidents(self):
        self.client.force_login(self.admin)

        response = self.client.get(
            reverse("core:incident_monitoring"),
            {
                "q": "phishing",
                "category": Incident.Category.PHISHING,
                "severity": Incident.Severity.HIGH,
                "status": Incident.Status.OPEN,
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.phishing_incident.title)
        self.assertNotContains(response, "Malware report")
        self.assertEqual(response.context["page_obj"].paginator.count, 1)

    def test_staff_can_view_incident_details(self):
        self.client.force_login(self.admin)

        response = self.client.get(
            reverse(
                "core:monitored_incident_detail",
                args=[self.phishing_incident.pk],
            )
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.phishing_incident.title)
        self.assertContains(response, self.reporter.email)
        self.assertContains(response, "Unexpected email link.")

    def test_administrator_can_assign_incident_from_detail_page(self):
        self.client.force_login(self.admin)
        detail_url = reverse(
            "core:monitored_incident_detail",
            args=[self.phishing_incident.pk],
        )

        response = self.client.post(
            detail_url,
            {"action": "assign", "analyst": self.analyst.pk},
        )

        self.assertRedirects(response, detail_url)
        self.phishing_incident.refresh_from_db()
        self.assertEqual(self.phishing_incident.assigned_analyst, self.analyst)
        self.assertEqual(
            self.phishing_incident.status,
            Incident.Status.UNDER_INVESTIGATION,
        )
        self.assertTrue(
            ActivityLog.objects.filter(
                incident=self.phishing_incident,
                action=ActivityLog.Action.ASSIGNMENT_CHANGED,
            ).exists()
        )

    def test_assigned_analyst_can_add_private_investigation_note(self):
        assign_incident(
            actor=self.admin,
            incident=self.phishing_incident,
            analyst=self.analyst,
        )
        self.client.force_login(self.analyst)
        detail_url = reverse(
            "core:monitored_incident_detail",
            args=[self.phishing_incident.pk],
        )

        response = self.client.post(
            detail_url,
            {"action": "note", "content": "Checked the message headers."},
        )

        self.assertRedirects(response, detail_url)
        note = InvestigationNote.objects.get(incident=self.phishing_incident)
        self.assertEqual(note.analyst, self.analyst)
        self.assertEqual(note.content, "Checked the message headers.")
        self.client.force_login(self.reporter)
        self.assertNotContains(
            self.client.get(
                reverse("incidents:detail", args=[self.phishing_incident.pk])
            ),
            "Checked the message headers.",
        )

    def test_analyst_cannot_access_unassigned_incident(self):
        self.client.force_login(self.analyst)

        response = self.client.get(
            reverse(
                "core:monitored_incident_detail",
                args=[self.phishing_incident.pk],
            )
        )

        self.assertEqual(response.status_code, 404)

    def test_only_administrator_can_update_alert_status(self):
        alert = SecurityAlert.objects.create(
            title="Repeated failures",
            description="Repeated sign-in failures observed.",
            alert_type=SecurityAlert.AlertType.REPEATED_FAILED_LOGINS,
            severity=SecurityAlert.Severity.MEDIUM,
        )
        alert_url = reverse("core:security_alerts")
        payload = {
            "alert_id": alert.pk,
            "status": SecurityAlert.Status.INVESTIGATING,
        }

        self.client.force_login(self.analyst)
        self.assertEqual(self.client.post(alert_url, payload).status_code, 403)
        alert.refresh_from_db()
        self.assertEqual(alert.status, SecurityAlert.Status.OPEN)

        self.client.force_login(self.admin)
        response = self.client.post(alert_url, payload)

        self.assertRedirects(response, alert_url)
        alert.refresh_from_db()
        self.assertEqual(alert.status, SecurityAlert.Status.INVESTIGATING)
        self.assertTrue(
            ActivityLog.objects.filter(
                action=ActivityLog.Action.ALERT_UPDATED,
            ).exists()
        )

    def test_regular_user_cannot_access_incident_monitoring_or_details(self):
        self.client.force_login(self.reporter)

        list_response = self.client.get(reverse("core:incident_monitoring"))
        detail_response = self.client.get(
            reverse(
                "core:monitored_incident_detail",
                args=[self.phishing_incident.pk],
            )
        )

        self.assertEqual(list_response.status_code, 403)
        self.assertEqual(detail_response.status_code, 403)
