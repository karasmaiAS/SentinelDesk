from django.contrib import admin

from .models import ActivityLog, Incident, InvestigationNote, LoginAttempt, SecurityAlert
from .services import assign_incident, log_activity, update_incident


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = (
        "title",
        "category",
        "severity",
        "status",
        "reporter",
        "assigned_analyst",
        "created_at",
    )
    list_filter = ("category", "severity", "status")
    search_fields = ("title", "description", "reporter__username")
    readonly_fields = ("public_id", "created_at", "updated_at")
    fieldsets = (
        (None, {"fields": ("public_id", "title", "description", "category", "severity", "status")}),
        ("Ownership", {"fields": ("reporter", "assigned_analyst")}),
        ("Resolution", {"fields": ("evidence_reference", "resolution_summary")}),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )

    def save_model(self, request, obj, form, change):
        if not change:
            super().save_model(request, obj, form, change)
            log_activity(
                action=ActivityLog.Action.INCIDENT_SUBMITTED,
                description=f"Incident {obj.public_id} created by an administrator.",
                actor=request.user,
                incident=obj,
                request=request,
            )
            return

        previous = Incident.objects.get(pk=obj.pk)
        changes = {}
        for field in ("status", "severity", "resolution_summary"):
            new_value = getattr(obj, field)
            if new_value != getattr(previous, field):
                changes[field] = new_value
        if changes:
            update_incident(
                actor=request.user,
                incident=previous,
                changes=changes,
                request=request,
            )
        if obj.assigned_analyst_id != previous.assigned_analyst_id:
            assign_incident(
                actor=request.user,
                incident=previous,
                analyst=obj.assigned_analyst,
                request=request,
            )
        for field in ("title", "description", "category", "reporter", "evidence_reference"):
            new_value = getattr(obj, f"{field}_id") if field == "reporter" else getattr(obj, field)
            old_value = getattr(previous, f"{field}_id") if field == "reporter" else getattr(previous, field)
            if new_value != old_value:
                setattr(previous, field, new_value)
        previous.full_clean()
        previous.save()
        obj.refresh_from_db()


@admin.register(InvestigationNote)
class InvestigationNoteAdmin(admin.ModelAdmin):
    list_display = ("incident", "analyst", "created_at")
    search_fields = ("incident__title", "analyst__username", "content")
    readonly_fields = ("created_at",)

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "actor", "action", "incident", "source_ip")
    list_filter = ("action", "created_at")
    search_fields = ("description", "actor__username", "incident__title")
    readonly_fields = tuple(field.name for field in ActivityLog._meta.fields)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return request.method in ("GET", "HEAD") and super().has_view_permission(
            request, obj
        )

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ("attempted_at", "username", "ip_address", "successful", "user")
    list_filter = ("successful", "attempted_at")
    search_fields = ("username", "ip_address", "user__username")
    readonly_fields = tuple(field.name for field in LoginAttempt._meta.fields)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return request.method in ("GET", "HEAD") and super().has_view_permission(
            request, obj
        )

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(SecurityAlert)
class SecurityAlertAdmin(admin.ModelAdmin):
    list_display = ("title", "alert_type", "severity", "status", "created_at")
    list_filter = ("alert_type", "severity", "status")
    search_fields = ("title", "description")
    readonly_fields = tuple(field.name for field in SecurityAlert._meta.fields)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return request.method in ("GET", "HEAD") and super().has_view_permission(
            request, obj
        )

    def has_delete_permission(self, request, obj=None):
        return False
