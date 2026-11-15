from .design_tokens import get_design_tokens
from accounts.roles import ROLE_ADMINISTRATOR, get_role


def design_tokens(request):
    return {"design_tokens": get_design_tokens()}


def user_role(request):
    role = get_role(request.user)
    return {
        "sentineldesk_role": role,
        "sentineldesk_is_administrator": role == ROLE_ADMINISTRATOR,
    }
