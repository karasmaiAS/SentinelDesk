from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction

from incidents.models import ActivityLog
from incidents.services import log_activity

from .roles import (
    ROLE_ADMINISTRATOR,
    ROLE_ANALYST,
    ROLE_GROUPS,
    ROLE_REGULAR_USER,
    is_administrator,
    role_group,
)


@transaction.atomic
def update_managed_user(*, actor, user, role, is_active, request=None):
    if not is_administrator(actor):
        raise PermissionDenied("Administrator access is required.")
    if user.is_superuser:
        raise PermissionDenied("Superuser accounts cannot be changed here.")
    if role not in (ROLE_ADMINISTRATOR, ROLE_ANALYST, ROLE_REGULAR_USER):
        raise ValidationError({"role": "Select a valid SentinelDesk role."})

    role_group_names = ROLE_GROUPS
    was_administrator = is_administrator(user)
    if was_administrator and (role != ROLE_ADMINISTRATOR or not is_active):
        active_admin_exists = get_user_model().objects.filter(
            is_active=True,
            groups__name=ROLE_ADMINISTRATOR,
        ).exclude(pk=user.pk).exists()
        if not active_admin_exists and not get_user_model().objects.filter(
            is_active=True,
            is_superuser=True,
        ).exclude(pk=user.pk).exists():
            raise ValidationError(
                "The last active administrator cannot be demoted or deactivated."
            )

    previous_role = (
        ROLE_ADMINISTRATOR
        if was_administrator
        else ROLE_ANALYST
        if user.is_staff
        else ROLE_REGULAR_USER
    )
    previous_active = user.is_active
    user.groups.remove(
        *user.groups.filter(name__in=role_group_names)
    )
    user.groups.add(role_group(role))
    user.is_staff = role in (ROLE_ADMINISTRATOR, ROLE_ANALYST)
    user.is_active = is_active
    user.save(update_fields=("is_staff", "is_active"))

    if role != previous_role:
        log_activity(
            action=ActivityLog.Action.ROLE_CHANGED,
            description=f"Role for {user.get_username()} changed from {previous_role} to {role}.",
            actor=actor,
            request=request,
        )
    if is_active != previous_active:
        log_activity(
            action=ActivityLog.Action.ACCOUNT_UPDATED,
            description=(
                f"Account {user.get_username()} "
                f"{'activated' if is_active else 'deactivated'}."
            ),
            actor=actor,
            request=request,
        )
    return user
