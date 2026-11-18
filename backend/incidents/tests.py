from datetime import timedelta
from unittest.mock import patch

from django.core.exceptions import PermissionDenied, ValidationError
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, TestCase
from django.urls import reverse
from django.utils.formats import date_format
from django.utils import timezone

from accounts.roles import ROLE_ANALYST, ROLE_REGULAR_USER

from .analytics import get_security_analytics
from .detection.event_processor import process_login_attempt
from .detection.event_processor import retry_pending_detection_events
from .evidence import (
    MAX_EVIDENCE_SIZE,
    PrivateEvidenceStorage,
    evidence_upload_path,
    safe_original_filename,
    validate_evidence_file,
)
from .models import (
    ActivityLog,
    DetectionEvent,
    DetectionRule,
    DetectionEvent,
    Incident,
    InvestigationNote,
    LoginAttempt,
    SecurityAlert,
)
from .services import (
    add_investigation_note,
    assign_incident,
    create_incident,
    update_incident,
    update_security_alert_status,
)


class EvidenceValidationTests(SimpleTestCase):
    def test_supported_text_is_validated_and_stream_position_is_restored(self):
        uploaded_file = SimpleUploadedFile(
            "capture.json",
            b'{"event": "login"}',
            content_type="application/json",
        )

        filename, size = validate_evidence_file(uploaded_file)

        self.assertEqual(filename, "capture.json")
        self.assertEqual(size, len(b'{"event": "login"}'))
        self.assertEqual(uploaded_file.tell(), 0)
        with self.assertRaisesRegex(ValueError, "authorized download view"):
            PrivateEvidenceStorage().url("capture.json")
        self.assertNotIn(
            filename,
            evidence_upload_path(None, f"..\\private\\{filename}"),
        )
        self.assertEqual(
            safe_original_filename("..\\private\\capture.json"),
            "capture.json",
        )

    def test_evidence_rejects_unsupported_extensions_malformed_images_and_oversize(self):
        invalid_files = (
            SimpleUploadedFile("payload.exe", b"not allowed"),
            SimpleUploadedFile("capture.png", b"not a PNG"),
            SimpleUploadedFile(
                "oversize.txt",
                b"x" * (MAX_EVIDENCE_SIZE + 1),
            ),
        )
        for uploaded_file in invalid_files:
            with self.subTest(filename=uploaded_file.name):
                with self.assertRaises(ValidationError):
                    validate_evidence_file(uploaded_file)


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

    def test_incident_submission_enforces_title_and_description_limits(self):
        self.client.force_login(self.reporter)
        form_response = self.client.get(reverse("incidents:create"))
        self.assertContains(form_response, 'maxlength="200"')
        self.assertContains(form_response, 'maxlength="5000"')

        valid_title = "T" * 200
        valid_response = self.client.post(
            reverse("incidents:create"),
            {
                "title": valid_title,
                "category": Incident.Category.OTHER,
                "description": "D" * 5000,
                "severity": Incident.Severity.LOW,
            },
        )
        self.assertEqual(valid_response.status_code, 302)
        self.assertEqual(len(Incident.objects.get(title=valid_title).description), 5000)

        long_title = self.client.post(
            reverse("incidents:create"),
            {
                "title": "T" * 201,
                "category": Incident.Category.OTHER,
                "description": "Description within limit.",
                "severity": Incident.Severity.LOW,
            },
        )
        self.assertEqual(long_title.status_code, 200)
        self.assertContains(
            long_title,
            "Incident title must be 200 characters or fewer.",
        )

        long_description = self.client.post(
            reverse("incidents:create"),
            {
                "title": "Description too long",
                "category": Incident.Category.OTHER,
                "description": "D" * 5001,
                "severity": Incident.Severity.LOW,
            },
        )
        self.assertEqual(long_description.status_code, 200)
        self.assertContains(
            long_description,
            "Incident description must be 5,000 characters or fewer.",
        )
        self.assertEqual(Incident.objects.filter(reporter=self.reporter).count(), 1)

    def test_title_validation_accepts_letters_and_rejects_nonletter_titles(self):
        self.client.force_login(self.reporter)
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
                    reverse("incidents:create"),
                    {
                        "title": title,
                        "category": Incident.Category.OTHER,
                        "description": "A test incident description.",
                        "severity": Incident.Severity.MEDIUM,
                    },
                )
                self.assertEqual(response.status_code, 302 if error_message is None else 200)
                if error_message is None:
                    self.assertTrue(
                        Incident.objects.filter(
                            reporter=self.reporter,
                            title=title.strip(),
                        ).exists()
                    )
                else:
                    self.assertContains(response, error_message)

    def test_existing_overlong_description_is_preserved_when_updating_status(self):
        admin = get_user_model().objects.create_superuser(
            username="legacy-admin",
            password="StrongPassword!327",
        )
        incident = Incident.objects.create(
            title="Legacy long description",
            description="L" * 5001,
            category=Incident.Category.OTHER,
            reporter=self.reporter,
        )

        update_incident(
            actor=admin,
            incident=incident,
            changes={"status": Incident.Status.UNDER_INVESTIGATION},
        )

        incident.refresh_from_db()
        self.assertEqual(incident.status, Incident.Status.UNDER_INVESTIGATION)
        self.assertEqual(len(incident.description), 5001)

    def test_existing_nonletter_title_remains_unchanged_when_updating_status(self):
        admin = get_user_model().objects.create_superuser(
            username="legacy-title-admin",
            password="StrongPassword!327",
        )
        incident = Incident.objects.create(
            title="123456789",
            description="Legacy incident.",
            category=Incident.Category.OTHER,
            reporter=self.reporter,
        )

        update_incident(
            actor=admin,
            incident=incident,
            changes={"status": Incident.Status.UNDER_INVESTIGATION},
        )

        incident.refresh_from_db()
        self.assertEqual(incident.title, "123456789")
        self.assertEqual(incident.status, Incident.Status.UNDER_INVESTIGATION)

    def test_submitted_incident_time_is_rendered_in_local_timezone(self):
        self.client.force_login(self.reporter)
        response = self.client.post(
            reverse("incidents:create"),
            {
                "title": "Local time report",
                "category": Incident.Category.OTHER,
                "description": "Check the displayed submission time.",
                "severity": Incident.Severity.LOW,
            },
        )
        incident = Incident.objects.get(title="Local time report")
        expected_time = date_format(
            timezone.localtime(incident.created_at),
            "M j, Y H:i",
        )

        self.assertRedirects(
            response,
            reverse("incidents:detail", args=[incident.pk]),
        )
        self.assertContains(
            self.client.get(reverse("incidents:detail", args=[incident.pk])),
            expected_time,
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


class DetectionEngineTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="detection-user",
            password="StrongPassword!327",
        )

    def rule(self, identifier, **changes):
        rule = DetectionRule.objects.get(identifier=identifier)
        for field, value in changes.items():
            setattr(rule, field, value)
        rule.save()
        return rule

    def test_failed_login_rule_uses_configured_threshold_and_suppresses_duplicates(self):
        rule = self.rule(
            "multiple_failed_logins",
            threshold=2,
            suppression_seconds=3600,
        )
        attempts = [
            LoginAttempt.objects.create(
                username="unknown-account",
                successful=False,
            )
            for _ in range(3)
        ]

        alerts = SecurityAlert.objects.filter(
            detection_rule=rule,
            auto_generated=True,
        )
        self.assertEqual(alerts.count(), 1)
        self.assertEqual(alerts.get().severity, rule.severity)
        process_login_attempt(attempts[-1])
        self.assertEqual(alerts.count(), 1)
        self.assertEqual(DetectionEvent.objects.count(), 3)

    def test_failed_login_rule_falls_back_to_ip_when_accounts_are_below_threshold(self):
        rule = self.rule("multiple_failed_logins", threshold=3)
        for username in ("first-account", "second-account", "third-account"):
            LoginAttempt.objects.create(
                username=username,
                ip_address="192.0.2.40",
                successful=False,
            )

        alert = SecurityAlert.objects.get(detection_rule=rule)
        self.assertEqual(alert.dedupe_key, "ip:192.0.2.40")

    def test_successful_login_after_configured_failure_threshold_generates_alert(self):
        self.rule("successful_login_after_failures", threshold=2)
        for _ in range(2):
            LoginAttempt.objects.create(
                user=self.user,
                username=self.user.username,
                ip_address="192.0.2.10",
                successful=False,
            )

        LoginAttempt.objects.create(
            user=self.user,
            username=self.user.username,
            ip_address="192.0.2.10",
            successful=True,
        )

        alert = SecurityAlert.objects.get(
            detection_rule__identifier="successful_login_after_failures"
        )
        self.assertEqual(alert.related_user, self.user)
        self.assertEqual(alert.source_ip, "192.0.2.10")

    def test_suspicious_login_rule_counts_distinct_accounts_from_one_ip(self):
        rule = self.rule("repeated_suspicious_login_activity", threshold=2)
        for username in ("first-account", "second-account"):
            LoginAttempt.objects.create(
                username=username,
                ip_address="192.0.2.20",
                successful=False,
            )

        alert = SecurityAlert.objects.get(detection_rule=rule)
        self.assertEqual(alert.source_ip, "192.0.2.20")
        self.assertEqual(alert.alert_type, SecurityAlert.AlertType.MULTIPLE_AUTH_FAILURES)

    def test_permission_denials_generate_alert_at_configured_threshold(self):
        rule = self.rule("repeated_unauthorized_activity", threshold=2)
        for _ in range(2):
            ActivityLog.objects.create(
                actor=self.user,
                action=ActivityLog.Action.ACCESS_DENIED,
                description="Permission denied.",
                source_ip="192.0.2.30",
            )

        alert = SecurityAlert.objects.get(detection_rule=rule)
        self.assertEqual(alert.related_user, self.user)
        self.assertEqual(alert.source_ip, "192.0.2.30")

    def test_repeated_incident_reports_are_linked_for_analyst_review(self):
        rule = self.rule("repeated_incident_reports", threshold=2)
        incidents = []
        for number in range(2):
            incidents.append(
                Incident.objects.create(
                    title=f"Report {number}",
                    description="Repeated category report.",
                    category=Incident.Category.PHISHING,
                    reporter=self.user,
                )
            )

        alert = SecurityAlert.objects.get(detection_rule=rule)
        self.assertEqual(alert.related_incident, incidents[-1])
        self.assertIn("does not establish", alert.description)

    def test_disabled_rules_do_not_emit_alerts_and_missing_ip_is_supported(self):
        rule = self.rule(
            "multiple_failed_logins",
            threshold=1,
            enabled=False,
        )

        LoginAttempt.objects.create(
            username="unknown-account",
            successful=False,
        )

        self.assertFalse(
            SecurityAlert.objects.filter(
                detection_rule=rule,
                auto_generated=True,
            ).exists()
        )

    def test_detection_failure_does_not_prevent_event_recording(self):
        with self.assertLogs("incidents.signals", level="ERROR"):
            with patch(
                "incidents.signals.process_login_attempt",
                side_effect=RuntimeError("detector unavailable"),
            ):
                attempt = LoginAttempt.objects.create(
                    username="detector-outage",
                    successful=False,
                )

        self.assertTrue(LoginAttempt.objects.filter(pk=attempt.pk).exists())

    def test_failed_rule_stays_pending_and_can_be_retried_without_recreating_event(self):
        with patch(
            "incidents.detection.event_processor._process_rule",
            return_value=False,
        ):
            attempt = LoginAttempt.objects.create(
                username="retry-detection",
                successful=False,
            )

        event = DetectionEvent.objects.get(
            event_key=f"login_attempt:{attempt.pk}"
        )
        self.assertIsNone(event.processed_at)

        with patch(
            "incidents.detection.event_processor._process_rule",
            return_value=True,
        ):
            result = retry_pending_detection_events()

        event.refresh_from_db()
        self.assertEqual(result, {"attempted": 1, "completed": 1})
        self.assertIsNotNone(event.processed_at)
        self.assertEqual(
            DetectionEvent.objects.filter(event_key=f"login_attempt:{attempt.pk}").count(),
            1,
        )
        self.assertEqual(retry_pending_detection_events(), {"attempted": 0, "completed": 0})


class SecurityAnalyticsTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.admin = user_model.objects.create_superuser(
            username="analytics-admin",
            password="StrongPassword!327",
        )
        self.analyst = user_model.objects.create_user(
            username="analytics-analyst",
            password="StrongPassword!327",
            is_staff=True,
        )
        self.other_analyst = user_model.objects.create_user(
            username="analytics-other",
            password="StrongPassword!327",
            is_staff=True,
        )
        self.reporter = user_model.objects.create_user(
            username="analytics-reporter",
            password="StrongPassword!327",
        )
        self.other_reporter = user_model.objects.create_user(
            username="analytics-other-reporter",
            password="StrongPassword!327",
        )
        now = timezone.now()
        self.incident = Incident.objects.create(
            title="Analytics resolved incident",
            description="Used for response-time measurements.",
            category=Incident.Category.PHISHING,
            reporter=self.reporter,
        )
        self.created_at = now - timedelta(hours=3)
        Incident.objects.filter(pk=self.incident.pk).update(
            created_at=self.created_at
        )
        self.incident.refresh_from_db()
        assign_incident(
            actor=self.admin,
            incident=self.incident,
            analyst=self.analyst,
        )
        self.assignment_at = self.created_at + timedelta(minutes=30)
        ActivityLog.objects.filter(
            incident=self.incident,
            action=ActivityLog.Action.ASSIGNMENT_CHANGED,
        ).update(created_at=self.assignment_at)

        note = add_investigation_note(
            actor=self.analyst,
            incident=self.incident,
            content="First investigation note.",
        )
        self.investigation_at = self.created_at + timedelta(hours=1)
        InvestigationNote.objects.filter(pk=note.pk).update(
            created_at=self.investigation_at
        )
        update_incident(
            actor=self.analyst,
            incident=self.incident,
            changes={
                "status": Incident.Status.RESOLVED,
                "resolution_summary": "Access reset and verified.",
            },
        )
        self.resolution_at = self.created_at + timedelta(hours=2)
        ActivityLog.objects.filter(
            incident=self.incident,
            action=ActivityLog.Action.STATUS_CHANGED,
            description__endswith="to resolved.",
        ).update(created_at=self.resolution_at)

        self.other_incident = Incident.objects.create(
            title="Other analyst incident",
            description="Outside the selected date range.",
            category=Incident.Category.MALWARE,
            reporter=self.other_reporter,
        )
        assign_incident(
            actor=self.admin,
            incident=self.other_incident,
            analyst=self.other_analyst,
        )
        Incident.objects.filter(pk=self.other_incident.pk).update(
            created_at=now - timedelta(days=45)
        )
        self.unassigned_incident = Incident.objects.create(
            title="Unassigned current incident",
            description="Included in current workload reporting.",
            category=Incident.Category.OTHER,
            reporter=self.other_reporter,
        )

        rule = DetectionRule.objects.get(identifier="multiple_failed_logins")
        self.alert = SecurityAlert.objects.create(
            title="Critical analytics alert",
            description="Generated alert for analytics.",
            alert_type=SecurityAlert.AlertType.REPEATED_FAILED_LOGINS,
            severity=SecurityAlert.Severity.CRITICAL,
            detection_rule=rule,
            auto_generated=True,
        )
        SecurityAlert.objects.filter(pk=self.alert.pk).update(
            created_at=now - timedelta(hours=2)
        )
        self.old_manual_alert = SecurityAlert.objects.create(
            title="Older manual alert",
            description="Outside the selected date range.",
            alert_type=SecurityAlert.AlertType.OTHER,
            severity=SecurityAlert.Severity.LOW,
            auto_generated=False,
        )
        SecurityAlert.objects.filter(pk=self.old_manual_alert.pk).update(
            created_at=now - timedelta(days=45)
        )
        self.start_date = timezone.localdate() - timedelta(days=6)
        self.end_date = timezone.localdate()

    def get_analytics(self, user, **kwargs):
        return get_security_analytics(
            user=user,
            start_date=kwargs.pop("start_date", self.start_date),
            end_date=kwargs.pop("end_date", self.end_date),
            **kwargs,
        )

    def test_date_range_filters_trends_and_alert_types_without_faking_empty_periods(self):
        analytics = self.get_analytics(self.admin)
        incidents = analytics["incident_statistics"]
        alerts = analytics["alert_statistics"]

        self.assertEqual(incidents["total_incidents"], 3)
        self.assertEqual(incidents["period"]["total"], 2)
        self.assertEqual(incidents["period"]["by_category"]["phishing"], 1)
        self.assertEqual(
            sum(row["count"] for row in analytics["incident_trends"]["counts"]),
            2,
        )
        self.assertEqual(
            sum(row["count"] for row in analytics["incident_trends"]["new_vs_resolved"]["resolved"]),
            1,
        )
        self.assertEqual(alerts["total_alerts"], 2)
        self.assertEqual(alerts["generated_alerts"], 1)
        self.assertEqual(alerts["manual_alerts"], 1)
        self.assertEqual(alerts["period"]["total"], 1)
        self.assertEqual(alerts["period"]["by_severity"]["critical"], 1)
        self.assertEqual(analytics["most_triggered_rules"][0]["alert_count"], 1)
        self.assertEqual(analytics["recent_priority_alerts"][0]["id"], self.alert.pk)

        empty = self.get_analytics(
            self.admin,
            start_date=self.end_date - timedelta(days=180),
            end_date=self.end_date - timedelta(days=170),
        )
        self.assertEqual(empty["incident_trends"]["counts"], [])
        self.assertEqual(empty["alert_trends"]["counts"], [])

    def test_response_metrics_use_audit_timestamps_and_exclude_missing_events(self):
        performance = self.get_analytics(self.admin)["response_performance"]

        self.assertEqual(
            performance["average_time_to_assignment"]["average_seconds"],
            1800,
        )
        self.assertEqual(
            performance["average_time_to_first_investigation_activity"]["average_seconds"],
            3600,
        )
        self.assertEqual(
            performance["average_time_to_resolution"]["average_seconds"],
            7200,
        )
        self.assertEqual(performance["average_time_to_resolution"]["sample_size"], 1)
        self.assertIsNone(performance["overdue_incidents"])
        self.assertIn("No incident deadline", performance["overdue_unavailable_reason"])

    def test_workload_is_role_scoped_and_unassigned_counts_are_admin_only(self):
        admin_data = self.get_analytics(self.admin)["analyst_workload"]
        admin_rows = {row["username"]: row for row in admin_data["analysts"]}
        self.assertEqual(admin_rows[self.analyst.username]["resolved_incidents"], 1)
        self.assertEqual(admin_rows[self.other_analyst.username]["active_incidents"], 1)
        self.assertEqual(admin_data["unassigned_active_incidents"], 1)

        analyst_data = self.get_analytics(self.analyst)["analyst_workload"]
        self.assertEqual(
            [row["username"] for row in analyst_data["analysts"]],
            [self.analyst.username],
        )
        self.assertIsNone(analyst_data["unassigned_incidents"])
        with self.assertRaises(PermissionDenied):
            self.get_analytics(self.reporter)

    def test_weekly_and_monthly_trends_use_actual_nonempty_buckets(self):
        weekly = self.get_analytics(self.admin, granularity="weekly")
        monthly = self.get_analytics(self.admin, granularity="monthly")

        self.assertEqual(len(weekly["incident_trends"]["counts"]), 2)
        self.assertEqual(
            sum(row["count"] for row in weekly["incident_trends"]["counts"]),
            2,
        )
        self.assertEqual(len(monthly["incident_trends"]["counts"]), 1)
        self.assertEqual(monthly["incident_trends"]["counts"][0]["count"], 2)
