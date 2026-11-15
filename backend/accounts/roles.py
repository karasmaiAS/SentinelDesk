from django.contrib.auth.models import Group

ROLE_ADMINISTRATOR = "Administrator"
ROLE_ANALYST = "Security Analyst"
ROLE_REGULAR_USER = "Regular User"
ROLE_GROUPS = (ROLE_ADMINISTRATOR, ROLE_ANALYST, ROLE_REGULAR_USER)


def get_role(user):
    if not user.is_authenticated:
        return None
    if user.is_superuser or user.groups.filter(name=ROLE_ADMINISTRATOR).exists():
        return ROLE_ADMINISTRATOR
    if user.groups.filter(name=ROLE_ANALYST).exists() or user.is_staff:
        return ROLE_ANALYST
    return ROLE_REGULAR_USER


def is_administrator(user):
    return get_role(user) == ROLE_ADMINISTRATOR


def is_analyst(user):
    return get_role(user) == ROLE_ANALYST


def can_investigate(user, incident):
    return is_administrator(user) or (
        is_analyst(user) and incident.assigned_analyst_id == user.pk
    )


def active_analysts():
    from django.contrib.auth import get_user_model

    user_model = get_user_model()
    return (
        user_model.objects.filter(is_active=True, is_staff=True)
        .exclude(is_superuser=True)
        .exclude(groups__name=ROLE_ADMINISTRATOR)
        .order_by("username")
        .distinct()
    )


def role_group(role):
    if role not in ROLE_GROUPS:
        raise ValueError(f"Unknown SentinelDesk role: {role}")
    group, _ = Group.objects.get_or_create(name=role)
    return group
