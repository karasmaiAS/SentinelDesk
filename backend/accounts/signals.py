from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.db.models.signals import post_migrate
from django.db.models.signals import post_save
from django.dispatch import receiver

from incidents.services import record_login_attempt

from .models import UserProfile
from .roles import ROLE_ADMINISTRATOR, ROLE_ANALYST, ROLE_REGULAR_USER


@receiver(post_save, sender=get_user_model())
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.get_or_create(user=instance)


@receiver(user_logged_in)
def record_successful_login(sender, request, user, **kwargs):
    record_login_attempt(
        username=user.get_username(),
        user=user,
        successful=True,
        request=request,
    )


@receiver(user_login_failed)
def record_failed_login(sender, credentials, request, **kwargs):
    username = credentials.get("username") or credentials.get("email") or ""
    record_login_attempt(
        username=str(username),
        successful=False,
        request=request,
    )


@receiver(post_migrate)
def assign_role_model_permissions(sender, apps, **kwargs):
    if sender.label not in {"accounts", "incidents"}:
        return

    Group = apps.get_model("auth", "Group")
    Permission = apps.get_model("auth", "Permission")
    permissions_by_role = {
        ROLE_REGULAR_USER: {
            "incidents": {"view_incident", "add_incident"},
        },
        ROLE_ANALYST: {
            "incidents": {
                "view_incident",
                "view_investigationnote",
                "add_investigationnote",
                "view_securityalert",
                "view_activitylog",
                "view_loginattempt",
            },
        },
        ROLE_ADMINISTRATOR: {
            "incidents": {
                "view_incident",
                "add_incident",
                "change_incident",
                "view_investigationnote",
                "view_securityalert",
                "view_activitylog",
                "view_loginattempt",
            },
            "accounts": {"view_userprofile"},
        },
    }

    for role, app_permissions in permissions_by_role.items():
        group, _ = Group.objects.get_or_create(name=role)
        permission_ids = Permission.objects.none()
        for app_label, codenames in app_permissions.items():
            permission_ids = permission_ids | Permission.objects.filter(
                content_type__app_label=app_label,
                codename__in=codenames,
            )
        group.permissions.add(*permission_ids)
