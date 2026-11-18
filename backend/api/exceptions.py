import logging

from django.contrib.auth.models import AnonymousUser
from rest_framework.views import exception_handler
from rest_framework.response import Response

from incidents.models import ActivityLog
from incidents.services import log_activity

logger = logging.getLogger("django.request")


def api_exception_handler(exc, context):
    response = exception_handler(exc, context)
    if response is None:
        logger.error(
            "Unhandled exception in REST API.",
            exc_info=(type(exc), exc, exc.__traceback__),
        )
        return Response(
            {
                "error": {
                    "code": "internal_server_error",
                    "detail": "An unexpected server error occurred.",
                }
            },
            status=500,
        )

    original_data = response.data
    status_code = response.status_code
    if status_code == 403:
        request = context.get("request")
        if request is not None:
            actor = request.user
            if isinstance(actor, AnonymousUser) or not actor.is_authenticated:
                actor = None
            try:
                log_activity(
                    action=ActivityLog.Action.ACCESS_DENIED,
                    description=(
                        f"Permission denied for {request.method} "
                        f"{request.path[:250]}."
                    ),
                    actor=actor,
                    request=request,
                )
            except Exception:
                logger.exception("Could not record a permission-denied API event.")
    if status_code == 400:
        code = "validation_error"
    elif status_code == 401:
        code = "authentication_required"
    elif status_code == 403:
        code = "permission_denied"
    elif status_code == 404:
        code = "not_found"
    elif status_code == 405:
        code = "method_not_allowed"
    else:
        code = "request_error"

    if isinstance(original_data, dict):
        detail = original_data.get("detail", "The request could not be completed.")
        fields = {
            key: value
            for key, value in original_data.items()
            if key != "detail"
        }
    else:
        detail = original_data
        fields = {}

    response.data = {
        "error": {
            "code": code,
            "detail": detail,
            **({"fields": fields} if fields else {}),
        }
    }
    return response
