from django.core.exceptions import PermissionDenied, ValidationError
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from accounts.roles import ROLE_ANALYST, ROLE_REGULAR_USER

from .models import ActivityLog, Incident, InvestigationNote, SecurityAlert
from .services import (
    add_investigation_note,
    assign_incident,
    create_incident,
    update_incident,
    update_security_alert_status,
)


class IncidentWorkflowTests(TestCase):
    def setUp(self):
        self.reporter = get_user_model().objects.create_user(
            username="reporter",
            password="StrongPassword!327",
        )
        self.other_user = get_user_model().objects.create_user(
            username="other",
            password="StrongPassword!327",
        )

    def test_authenticated_user_can_submit_and_retrieve_incident(self):
        self.client.force_login(self.reporter)
        response = self.client.post(
            reverse("incidents:create"),
            {
                "title": "Suspicious email",
                "category": Incident.Category.PHISHING,
                "description": "A message contained an unexpected link.",
                "severity": Incident.Severity.MEDIUM,
                "evidence_reference": "https://example.test/message",
            },
        )

        incident = Incident.objects.get(title="Suspicious email")
        self.assertEqual(incident.reporter, self.reporter)
        self.assertEqual(incident.status, Incident.Status.OPEN)
        self.assertRedirects(response, reverse("incidents:detail", args=[incident.pk]))
        self.assertContains(
            self.client.get(reverse("incidents:detail", args=[incident.pk])),
            "Suspicious email",
        )

    def test_anonymous_user_is_redirected_to_login(self):
        response = self.client.get(reverse("incidents:list"))

        self.assertRedirects(
            response,
            f"{reverse('accounts:login')}?next={reverse('incidents:list')}",
        )

    def test_users_only_see_their_own_incidents(self):
        incident = Incident.objects.create(
            title="Private report",
            category=Incident.Category.OTHER,
            description="Visible only to the reporter.",
            reporter=self.reporter,
        )
        self.client.force_login(self.other_user)

        list_response = self.client.get(reverse("incidents:list"))
        detail_response = self.client.get(
            reverse("incidents:detail", args=[incident.pk])
        )

        self.assertNotContains(list_response, "Private report")
        self.assertEqual(detail_response.status_code, 404)

    def test_dashboard_counts_only_reporters_open_incidents(self):
        Incident.objects.create(
            title="My open report",
            category=Incident.Category.OTHER,
            description="Open.",
            reporter=self.reporter,
        )
        Incident.objects.create(
            title="My closed report",
            category=Incident.Category.OTHER,
            description="Closed.",
            status=Incident.Status.CLOSED,
            reporter=self.reporter,
        )
        Incident.objects.create(
            title="Other user's report",
            category=Incident.Category.OTHER,
            description="Not mine.",
            reporter=self.other_user,
        )
        self.client.force_login(self.reporter)

        response = self.client.get(reverse("incidents:dashboard"))

        self.assertEqual(response.context["incident_count"], 2)
        self.assertEqual(response.context["open_count"], 1)

    def test_incident_submission_service_creates_audit_entry(self):
        incident = create_incident(
            reporter=self.reporter,
            data={
                "title": "Account takeover attempt",
                "description": "Unrecognized authentication prompt.",
                "category": Incident.Category.UNAUTHORIZED_ACCESS,
                "severity": Incident.Severity.HIGH,
                "evidence_reference": "",
            },
        )

        self.assertEqual(incident.status, Incident.Status.OPEN)
        entry = ActivityLog.objects.get(incident=incident)
        self.assertEqual(entry.action, ActivityLog.Action.INCIDENT_SUBMITTED)
        self.assertEqual(entry.actor, self.reporter)


class IncidentAuthorizationAndLifecycleTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_superuser(
            username="administrator",
            password="StrongPassword!327",
        )
        self.analyst = get_user_model().objects.create_user(
            username="analyst",
            password="StrongPassword!327",
            is_staff=True,
        )
        self.other_analyst = get_user_model().objects.create_user(
            username="other-analyst",
            password="StrongPassword!327",
            is_staff=True,
        )
        self.reporter = get_user_model().objects.create_user(
            username="reporter",
            password="StrongPassword!327",
        )
        self.incident = Incident.objects.create(
            title="Suspicious access",
            description="Unexpected account activity.",
            category=Incident.Category.UNAUTHORIZED_ACCESS,
            reporter=self.reporter,
        )

    def test_assignment_requires_admin_and_active_analyst(self):
        with self.assertRaises(PermissionDenied):
            assign_incident(
                actor=self.reporter,
                incident=self.incident,
                analyst=self.analyst,
            )

        inactive_analyst = self.other_analyst
        inactive_analyst.is_active = False
        inactive_analyst.save(update_fields=("is_active",))
        with self.assertRaises(ValidationError):
            assign_incident(
                actor=self.admin,
                incident=self.incident,
                analyst=inactive_analyst,
            )

        assign_incident(
            actor=self.admin,
            incident=self.incident,
            analyst=self.analyst,
        )
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.assigned_analyst, self.analyst)
        self.assertEqual(
            self.incident.status,
            Incident.Status.UNDER_INVESTIGATION,
        )
        self.assertTrue(
            ActivityLog.objects.filter(
                incident=self.incident,
                action=ActivityLog.Action.ASSIGNMENT_CHANGED,
            ).exists()
        )

    def test_analyst_can_only_update_assigned_incident_status(self):
        assign_incident(
            actor=self.admin,
            incident=self.incident,
            analyst=self.analyst,
        )

        update_incident(
            actor=self.analyst,
            incident=self.incident,
            changes={"status": Incident.Status.PENDING},
        )
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, Incident.Status.PENDING)
        self.assertTrue(
            ActivityLog.objects.filter(
                incident=self.incident,
                action=ActivityLog.Action.STATUS_CHANGED,
            ).exists()
        )

        with self.assertRaises(PermissionDenied):
            update_incident(
                actor=self.other_analyst,
                incident=self.incident,
                changes={"status": Incident.Status.RESOLVED},
            )
        with self.assertRaises(PermissionDenied):
            update_incident(
                actor=self.analyst,
                incident=self.incident,
                changes={"severity": Incident.Severity.CRITICAL},
            )

    def test_invalid_transitions_and_resolution_without_summary_are_rejected(self):
        with self.assertRaises(ValidationError):
            update_incident(
                actor=self.admin,
                incident=self.incident,
                changes={"status": Incident.Status.CLOSED},
            )

        assign_incident(
            actor=self.admin,
            incident=self.incident,
            analyst=self.analyst,
        )
        with self.assertRaises(ValidationError):
            update_incident(
                actor=self.admin,
                incident=self.incident,
                changes={"status": Incident.Status.RESOLVED},
            )

        update_incident(
            actor=self.admin,
            incident=self.incident,
            changes={
                "status": Incident.Status.RESOLVED,
                "resolution_summary": "Reset credentials and confirmed access stopped.",
            },
        )
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, Incident.Status.RESOLVED)

    def test_only_assigned_analyst_or_admin_can_add_preserved_notes(self):
        with self.assertRaises(PermissionDenied):
            add_investigation_note(
                actor=self.analyst,
                incident=self.incident,
                content="Should not be accepted.",
            )
        with self.assertRaises(PermissionDenied):
            add_investigation_note(
                actor=self.reporter,
                incident=self.incident,
                content="Reporter cannot add notes.",
            )

        note = add_investigation_note(
            actor=self.admin,
            incident=self.incident,
            content="Reviewed the submitted details.",
        )
        self.assertEqual(InvestigationNote.objects.get(pk=note.pk).content, "Reviewed the submitted details.")
        self.assertTrue(
            ActivityLog.objects.filter(
                incident=self.incident,
                action=ActivityLog.Action.NOTE_ADDED,
            ).exists()
        )

    def test_admin_can_change_severity_and_status_history_is_logged(self):
        update_incident(
            actor=self.admin,
            incident=self.incident,
            changes={"severity": Incident.Severity.CRITICAL},
        )
        self.assertTrue(
            ActivityLog.objects.filter(
                incident=self.incident,
                action=ActivityLog.Action.SEVERITY_CHANGED,
            ).exists()
        )

    def test_regular_user_incident_details_show_progress_but_not_private_notes(self):
        self.client.force_login(self.admin)
        assign_incident(
            actor=self.admin,
            incident=self.incident,
            analyst=self.analyst,
        )
        add_investigation_note(
            actor=self.admin,
            incident=self.incident,
            content="Internal investigation detail.",
        )
        self.client.force_login(self.reporter)

        response = self.client.get(
            reverse("incidents:detail", args=[self.incident.pk])
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Progress updates")
        self.assertNotContains(response, "Internal investigation detail.")
