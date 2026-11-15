from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse

from incidents.models import ActivityLog, LoginAttempt, SecurityAlert

from .models import UserProfile
from .roles import ROLE_ADMINISTRATOR, ROLE_ANALYST, ROLE_REGULAR_USER, get_role, role_group
from .services import update_managed_user


class RegistrationAndAuthenticationTests(TestCase):
    def test_registration_password_help_is_compact(self):
        response = self.client.get(reverse("accounts:register"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'id="id_email"')
        self.assertContains(response, 'id="id_password1"')
        self.assertContains(response, 'id="id_password2"')
        self.assertContains(response, "Use at least 8 characters.")
        self.assertContains(response, "Enter the same password again.")
        self.assertNotContains(response, "<ul>")

    def test_registration_creates_user_and_login_works(self):
        response = self.client.post(
            reverse("accounts:register"),
            {
                "username": "reporter",
                "email": "reporter@example.com",
                "password1": "StrongPassword!327",
                "password2": "StrongPassword!327",
            },
        )

        self.assertRedirects(response, reverse("accounts:login"))
        user = get_user_model().objects.get(username="reporter")
        self.assertEqual(user.email, "reporter@example.com")
        self.assertTrue(user.check_password("StrongPassword!327"))

        self.assertTrue(
            self.client.login(username="reporter", password="StrongPassword!327")
        )
        response = self.client.get(reverse("incidents:dashboard"))
        self.assertEqual(response.status_code, 200)

    def test_staff_login_redirects_to_custom_admin_dashboard(self):
        get_user_model().objects.create_user(
            username="staff",
            password="StrongPassword!327",
            is_staff=True,
        )

        response = self.client.post(
            reverse("accounts:login"),
            {"username": "staff", "password": "StrongPassword!327"},
        )

        self.assertRedirects(response, reverse("core:admin_dashboard"))

    def test_regular_user_login_redirects_to_own_dashboard(self):
        get_user_model().objects.create_user(
            username="reporter",
            password="StrongPassword!327",
        )

        response = self.client.post(
            reverse("accounts:login"),
            {"username": "reporter", "password": "StrongPassword!327"},
        )

        self.assertRedirects(response, reverse("incidents:dashboard"))

    def test_login_respects_safe_next_destination(self):
        get_user_model().objects.create_user(
            username="reporter",
            password="StrongPassword!327",
        )

        response = self.client.post(
            reverse("accounts:login"),
            {
                "username": "reporter",
                "password": "StrongPassword!327",
                "next": reverse("incidents:list"),
            },
        )

        self.assertRedirects(response, reverse("incidents:list"))

    def test_registration_rejects_duplicate_email_case_insensitively(self):
        get_user_model().objects.create_user(
            username="existing",
            email="person@example.com",
            password="StrongPassword!327",
        )

        response = self.client.post(
            reverse("accounts:register"),
            {
                "username": "another",
                "email": "PERSON@example.com",
                "password1": "StrongPassword!327",
                "password2": "StrongPassword!327",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "An account with this email already exists.")

    def test_logout_ends_authenticated_session(self):
        user = get_user_model().objects.create_user(
            username="reporter",
            password="StrongPassword!327",
        )
        self.client.force_login(user)

        response = self.client.post(reverse("accounts:logout"))

        self.assertRedirects(response, reverse("accounts:login"))
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_staff_user_can_open_django_administration(self):
        admin = get_user_model().objects.create_superuser(
            username="administrator",
            email="admin@example.com",
            password="StrongPassword!327",
        )
        self.client.force_login(admin)

        response = self.client.get(reverse("admin:index"))

        self.assertEqual(response.status_code, 200)

    def test_registration_assigns_regular_role_and_creates_profile(self):
        response = self.client.post(
            reverse("accounts:register"),
            {
                "username": "newreporter",
                "email": "newreporter@example.com",
                "password1": "StrongPassword!327",
                "password2": "StrongPassword!327",
            },
        )

        self.assertRedirects(response, reverse("accounts:login"))
        user = get_user_model().objects.get(username="newreporter")
        self.assertEqual(get_role(user), ROLE_REGULAR_USER)
        self.assertTrue(UserProfile.objects.filter(user=user).exists())

    def test_inactive_accounts_cannot_log_in(self):
        get_user_model().objects.create_user(
            username="inactive",
            password="StrongPassword!327",
            is_active=False,
        )

        response = self.client.post(
            reverse("accounts:login"),
            {"username": "inactive", "password": "StrongPassword!327"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_failed_logins_are_logged_and_generate_alert_at_threshold(self):
        for _ in range(5):
            self.client.post(
                reverse("accounts:login"),
                {"username": "unknown-user", "password": "NotARealPassword!"},
            )

        self.assertEqual(
            LoginAttempt.objects.filter(
                username="unknown-user",
                successful=False,
            ).count(),
            5,
        )
        self.assertTrue(
            ActivityLog.objects.filter(
                action=ActivityLog.Action.LOGIN_FAILURE,
                description__contains="unknown-user",
            ).exists()
        )
        alert = SecurityAlert.objects.get(
            alert_type=SecurityAlert.AlertType.REPEATED_FAILED_LOGINS
        )
        self.assertEqual(alert.severity, SecurityAlert.Severity.MEDIUM)
        self.assertNotIn("NotARealPassword!", alert.description)

    def test_successful_login_after_failures_creates_suspicious_login_alert(self):
        user = get_user_model().objects.create_user(
            username="valid-user",
            password="StrongPassword!327",
        )
        for _ in range(5):
            self.client.post(
                reverse("accounts:login"),
                {"username": "valid-user", "password": "WrongPassword!"},
            )

        self.client.post(
            reverse("accounts:login"),
            {"username": "valid-user", "password": "StrongPassword!327"},
        )

        self.assertTrue(
            SecurityAlert.objects.filter(
                alert_type=SecurityAlert.AlertType.SUSPICIOUS_LOGIN,
                related_user=user,
                severity=SecurityAlert.Severity.HIGH,
            ).exists()
        )

    def test_profile_update_changes_only_own_account_and_profile(self):
        user = get_user_model().objects.create_user(
            username="profile-user",
            email="before@example.com",
            password="StrongPassword!327",
        )
        self.client.force_login(user)

        response = self.client.post(
            reverse("accounts:profile"),
            {
                "account-username": "profile-user",
                "account-email": "after@example.com",
                "account-first_name": "Sentinel",
                "account-last_name": "User",
                "profile-department": "Operations",
                "profile-phone": "555-0101",
            },
        )

        user.refresh_from_db()
        self.assertRedirects(response, reverse("accounts:profile"))
        self.assertEqual(user.email, "after@example.com")
        self.assertEqual(user.profile.department, "Operations")
        self.assertEqual(get_role(user), ROLE_REGULAR_USER)

    def test_administrator_can_assign_analyst_role_and_deactivate_account(self):
        admin = get_user_model().objects.create_superuser(
            username="role-admin",
            password="StrongPassword!327",
        )
        user = get_user_model().objects.create_user(
            username="managed",
            password="StrongPassword!327",
        )

        update_managed_user(
            actor=admin,
            user=user,
            role=ROLE_ANALYST,
            is_active=True,
        )

        user.refresh_from_db()
        self.assertEqual(get_role(user), ROLE_ANALYST)
        self.assertTrue(user.is_staff)
        self.assertTrue(
            ActivityLog.objects.filter(
                action=ActivityLog.Action.ROLE_CHANGED,
                description__contains="managed",
            ).exists()
        )

        update_managed_user(
            actor=admin,
            user=user,
            role=ROLE_ANALYST,
            is_active=False,
        )
        user.refresh_from_db()
        self.assertFalse(user.is_active)

    def test_regular_user_cannot_manage_roles_and_last_admin_is_protected(self):
        regular_user = get_user_model().objects.create_user(
            username="regular",
            password="StrongPassword!327",
        )
        self.client.force_login(regular_user)
        self.assertEqual(
            self.client.get(reverse("accounts:user_management")).status_code,
            403,
        )

        sole_admin = get_user_model().objects.create_user(
            username="sole-admin",
            password="StrongPassword!327",
            is_staff=True,
        )
        sole_admin.groups.add(role_group(ROLE_ADMINISTRATOR))
        with self.assertRaises(ValidationError):
            update_managed_user(
                actor=sole_admin,
                user=sole_admin,
                role=ROLE_REGULAR_USER,
                is_active=True,
            )

    def test_administrator_can_manage_account_role_through_web_page(self):
        admin = get_user_model().objects.create_superuser(
            username="management-admin",
            password="StrongPassword!327",
        )
        managed_user = get_user_model().objects.create_user(
            username="managed-through-page",
            password="StrongPassword!327",
        )
        self.client.force_login(admin)

        response = self.client.post(
            reverse("accounts:user_management"),
            {
                "user_id": managed_user.pk,
                "role": ROLE_ANALYST,
                "is_active": "on",
            },
        )

        self.assertRedirects(response, reverse("accounts:user_management"))
        managed_user.refresh_from_db()
        self.assertEqual(get_role(managed_user), ROLE_ANALYST)
        self.assertTrue(managed_user.is_staff)
