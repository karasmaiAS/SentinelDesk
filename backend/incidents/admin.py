from django.contrib import admin

from accounts.roles import is_administrator, is_analyst
from incidents.intelligence import check_indicator

from .models import (
    ActivityLog,
    Incident,
    IndicatorOfCompromise,
    InvestigationNote,
    LoginAttempt,
    SecurityAlert,
    ThreatIntelRecord,
)
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


@admin.register(IndicatorOfCompromise)
class IndicatorOfCompromiseAdmin(admin.ModelAdmin):
    list_display = (
        "value",
        "indicator_type",
        "risk",
        "confidence",
        "match_status",
        "incident",
        "date_identified",
    )
    list_filter = ("indicator_type", "risk", "status", "match_status")
    search_fields = ("value", "normalized_value", "description", "source")
    readonly_fields = (
        "normalized_value",
        "added_by",
        "match_status",
        "last_checked_at",
        "created_at",
        "updated_at",
    )

    def get_queryset(self, request):
        queryset = super().get_queryset(request).select_related(
            "incident",
            "added_by",
        )
        if is_administrator(request.user):
            return queryset
        if is_analyst(request.user):
            return queryset.filter(incident__assigned_analyst=request.user)
        return queryset.none()

    def has_add_permission(self, request):
        return is_administrator(request.user) or is_analyst(request.user)

    def has_view_permission(self, request, obj=None):
        if is_administrator(request.user):
            return True
        return bool(
            is_analyst(request.user)
            and (obj is None or obj.incident.assigned_analyst_id == request.user.pk)
        )

    def has_change_permission(self, request, obj=None):
        return self.has_view_permission(request, obj)

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == "incident" and is_analyst(request.user):
            kwargs["queryset"] = Incident.objects.filter(
                assigned_analyst=request.user
            )
        return super().formfield_for_foreignkey(db_field, request, **kwargs)

    def save_model(self, request, obj, form, change):
        previous = None
        if change:
            previous = IndicatorOfCompromise.objects.get(pk=obj.pk)
        if not change:
            obj.added_by = request.user
        obj.full_clean()
        super().save_model(request, obj, form, change)
        if not change:
            log_activity(
                action=ActivityLog.Action.IOC_DISCOVERED,
                description=f"{obj.indicator_type} indicator discovered: {obj.value}.",
                actor=request.user,
                incident=obj.incident,
                request=request,
            )
            check_indicator(obj, actor=request.user, request=request)
        else:
            modified = any(
                getattr(previous, field) != getattr(obj, field)
                for field in (
                    "indicator_type",
                    "value",
                    "description",
                    "source",
                    "confidence",
                    "risk",
                    "date_identified",
                    "notes",
                    "status",
                )
            )
            if modified:
                log_activity(
                    action=ActivityLog.Action.IOC_UPDATED,
                    description=f"Indicator updated: {obj.value}.",
                    actor=request.user,
                    incident=obj.incident,
                    request=request,
                )
            if (
                previous.indicator_type != obj.indicator_type
                or previous.value != obj.value
            ):
                obj.match_status = IndicatorOfCompromise.MatchStatus.UNCHECKED
                obj.last_checked_at = None
                obj.save(
                    update_fields=("match_status", "last_checked_at", "updated_at")
                )
                check_indicator(obj, actor=request.user, request=request)

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(ThreatIntelRecord)
class ThreatIntelRecordAdmin(admin.ModelAdmin):
    list_display = (
        "value",
        "indicator_type",
        "source",
        "confidence",
        "classification",
        "last_updated",
    )
    list_filter = ("indicator_type", "source", "classification")
    search_fields = ("value", "normalized_value", "source", "classification", "notes")
    readonly_fields = ("normalized_value", "created_by", "last_updated")

    def has_module_permission(self, request):
        return is_administrator(request.user)

    def has_view_permission(self, request, obj=None):
        return is_administrator(request.user)

    def has_add_permission(self, request):
        return is_administrator(request.user)

    def has_change_permission(self, request, obj=None):
        return is_administrator(request.user)

    def save_model(self, request, obj, form, change):
        if not change:
            obj.created_by = request.user
        obj.full_clean()
        super().save_model(request, obj, form, change)
        log_activity(
            action=ActivityLog.Action.THREAT_INTEL_UPDATED,
            description=(
                f"Local threat-intelligence record "
                f"{obj.indicator_type} {obj.value} was "
                f"{'updated' if change else 'created'}."
            ),
            actor=request.user,
            request=request,
        )

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
