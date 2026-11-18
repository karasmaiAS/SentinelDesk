from datetime import timedelta

from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.core.exceptions import (
    PermissionDenied as DjangoPermissionDenied,
    ValidationError as DjangoValidationError,
)
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied
from django.utils import timezone

from accounts.roles import ROLE_ADMINISTRATOR, get_role
from incidents.analytics import (
    GRANULARITIES,
    default_analytics_dates,
    validate_analytics_dates,
)
from incidents.models import (
    ActivityLog,
    DetectionRule,
    INCIDENT_DESCRIPTION_MAX_LENGTH,
    INCIDENT_TITLE_REQUIRED_ERROR,
    INCIDENT_TITLE_MAX_LENGTH,
    IndicatorOfCompromise,
    Incident,
    InvestigationEvidence,
    InvestigationFinding,
    InvestigationNote,
    SecurityAlert,
    validate_incident_title,
)
from incidents.services import (
    add_investigation_note,
    assign_incident,
    create_incident,
    log_activity,
    update_incident,
    update_security_alert_status,
)
from incidents.intelligence import check_indicator, get_indicator_matches
from incidents.indicators import normalize_indicator


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150, trim_whitespace=False)
    password = serializers.CharField(
        max_length=128,
        trim_whitespace=False,
        write_only=True,
        style={"input_type": "password"},
    )

    def validate(self, attrs):
        request = self.context.get("request")
        user = authenticate(
            request=request,
            username=attrs["username"],
            password=attrs["password"],
        )
        if user is None:
            raise AuthenticationFailed("Invalid username or password.")
        attrs["user"] = user
        return attrs


class IncidentSerializer(serializers.ModelSerializer):
    title = serializers.CharField(
        max_length=INCIDENT_TITLE_MAX_LENGTH,
        validators=[validate_incident_title],
        error_messages={
            "blank": INCIDENT_TITLE_REQUIRED_ERROR,
            "max_length": "Incident title must be 200 characters or fewer.",
            "required": INCIDENT_TITLE_REQUIRED_ERROR,
        },
    )
    description = serializers.CharField(
        max_length=INCIDENT_DESCRIPTION_MAX_LENGTH,
        error_messages={
            "max_length": (
                "Incident description must be 5,000 characters or fewer."
            )
        },
    )
    reporter = serializers.IntegerField(source="reporter_id", read_only=True)
    reporter_username = serializers.CharField(
        source="reporter.username",
        read_only=True,
    )
    assigned_analyst = serializers.IntegerField(
        source="assigned_analyst_id",
        read_only=True,
        allow_null=True,
    )
    assigned_analyst_username = serializers.CharField(
        source="assigned_analyst.username",
        read_only=True,
        allow_null=True,
    )

    class Meta:
        model = Incident
        fields = (
            "id",
            "public_id",
            "title",
            "description",
            "category",
            "severity",
            "status",
            "reporter",
            "reporter_username",
            "assigned_analyst",
            "assigned_analyst_username",
            "evidence_reference",
            "resolution_summary",
            "created_at",
            "updated_at",
        )
        read_only_fields = (
            "id",
            "public_id",
            "reporter",
            "reporter_username",
            "assigned_analyst",
            "assigned_analyst_username",
            "created_at",
            "updated_at",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance is None:
            self.fields["status"].read_only = True
            self.fields["resolution_summary"].read_only = True

    def validate(self, attrs):
        request = self.context["request"]
        allowed_fields = (
            {"title", "description", "category", "severity", "evidence_reference"}
            if self.instance is None
            else {"status", "resolution_summary"}
        )
        if (
            self.instance is not None
            and get_role(request.user) == ROLE_ADMINISTRATOR
        ):
            allowed_fields.add("severity")
        supplied_fields = set(self.initial_data)
        forbidden_fields = supplied_fields - allowed_fields
        if forbidden_fields:
            raise serializers.ValidationError(
                {
                    field: "This field cannot be changed through this endpoint."
                    for field in sorted(forbidden_fields)
                }
            )
        if self.instance is not None and not attrs:
            raise serializers.ValidationError(
                {"detail": "Provide at least one incident field to update."}
            )
        return attrs

    def create(self, validated_data):
        request = self.context["request"]
        try:
            return create_incident(
                reporter=request.user,
                data=validated_data,
                request=request,
            )
        except DjangoValidationError as error:
            raise serializers.ValidationError(
                getattr(error, "message_dict", error.messages)
            ) from error

    def update(self, instance, validated_data):
        request = self.context["request"]
        try:
            return update_incident(
                actor=request.user,
                incident=instance,
                changes=validated_data,
                request=request,
            )
        except DjangoValidationError as error:
            raise serializers.ValidationError(
                getattr(error, "message_dict", error.messages)
            ) from error
        except DjangoPermissionDenied as error:
            raise PermissionDenied(str(error)) from error


def serialize_user(user):
    display_name = user.get_full_name().strip() or user.get_username()
    return {
        "id": user.pk,
        "username": user.get_username(),
        "display_name": display_name,
        "role": get_role(user),
    }


class AnalystSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    username = serializers.CharField(read_only=True)
    display_name = serializers.SerializerMethodField()

    def get_display_name(self, user):
        return user.get_full_name().strip() or user.get_username()


class AssignmentSerializer(serializers.Serializer):
    analyst_id = serializers.IntegerField(required=True, allow_null=True)

    def validate_analyst_id(self, value):
        if value is None:
            return None
        user_model = get_user_model()
        try:
            analyst = user_model.objects.get(pk=value, is_active=True)
        except user_model.DoesNotExist as error:
            raise serializers.ValidationError(
                "Choose an active security analyst."
            ) from error
        from accounts.roles import is_analyst

        if not is_analyst(analyst):
            raise serializers.ValidationError(
                "Choose an active security analyst."
            )
        return analyst

    def update(self, instance, validated_data):
        try:
            return assign_incident(
                actor=self.context["request"].user,
                incident=instance,
                analyst=validated_data.get("analyst_id"),
                request=self.context["request"],
            )
        except DjangoValidationError as error:
            raise serializers.ValidationError(
                getattr(error, "message_dict", error.messages)
            ) from error
        except DjangoPermissionDenied as error:
            raise PermissionDenied(str(error)) from error


class InvestigationNoteSerializer(serializers.ModelSerializer):
    analyst = serializers.IntegerField(source="analyst_id", read_only=True)
    analyst_username = serializers.CharField(
        source="analyst.username",
        read_only=True,
    )

    class Meta:
        model = InvestigationNote
        fields = ("id", "analyst", "analyst_username", "content", "created_at")
        read_only_fields = ("id", "analyst", "analyst_username", "created_at")

    def create(self, validated_data):
        try:
            return add_investigation_note(
                actor=self.context["request"].user,
                incident=self.context["incident"],
                content=validated_data["content"],
                request=self.context["request"],
            )
        except DjangoValidationError as error:
            raise serializers.ValidationError(
                getattr(error, "message_dict", error.messages)
            ) from error
        except DjangoPermissionDenied as error:
            raise PermissionDenied(str(error)) from error


class IndicatorOfCompromiseSerializer(serializers.ModelSerializer):
    incident = serializers.IntegerField(source="incident_id", read_only=True)
    added_by = serializers.IntegerField(source="added_by_id", read_only=True)
    added_by_username = serializers.CharField(
        source="added_by.username",
        read_only=True,
    )
    match_result = serializers.SerializerMethodField()

    class Meta:
        model = IndicatorOfCompromise
        fields = (
            "id",
            "incident",
            "indicator_type",
            "value",
            "normalized_value",
            "description",
            "source",
            "confidence",
            "risk",
            "date_identified",
            "notes",
            "status",
            "added_by",
            "added_by_username",
            "match_status",
            "last_checked_at",
            "match_result",
            "created_at",
            "updated_at",
        )
        read_only_fields = (
            "id",
            "incident",
            "normalized_value",
            "added_by",
            "added_by_username",
            "match_status",
            "last_checked_at",
            "match_result",
            "created_at",
            "updated_at",
        )
        validators = ()

    def get_match_result(self, instance):
        return get_indicator_matches(instance)

    def validate(self, attrs):
        indicator_type = attrs.get(
            "indicator_type",
            getattr(self.instance, "indicator_type", None),
        )
        value = attrs.get("value", getattr(self.instance, "value", None))
        if indicator_type is None or value is None:
            raise serializers.ValidationError(
                {"value": "Both indicator type and value are required."}
            )
        try:
            normalize_indicator(indicator_type, value)
        except DjangoValidationError as error:
            raise serializers.ValidationError(
                getattr(error, "message_dict", error.messages)
            ) from error
        return attrs

    def create(self, validated_data):
        request = self.context["request"]
        indicator = IndicatorOfCompromise(
            incident=self.context["incident"],
            added_by=request.user,
            **validated_data,
        )
        try:
            indicator.full_clean()
            indicator.save()
        except DjangoValidationError as error:
            raise serializers.ValidationError(
                getattr(error, "message_dict", error.messages)
            ) from error
        log_activity(
            action=ActivityLog.Action.IOC_DISCOVERED,
            description=(
                f"{indicator.get_indicator_type_display()} indicator discovered: "
                f"{indicator.value}."
            ),
            actor=request.user,
            incident=indicator.incident,
            request=request,
        )
        check_indicator(indicator, actor=request.user, request=request)
        return indicator

    def update(self, instance, validated_data):
        request = self.context["request"]
        old_type = instance.indicator_type
        old_value = instance.value
        changed = any(
            getattr(instance, field) != value
            for field, value in validated_data.items()
        )
        for field, value in validated_data.items():
            setattr(instance, field, value)
        try:
            instance.full_clean()
            instance.save()
        except DjangoValidationError as error:
            raise serializers.ValidationError(
                getattr(error, "message_dict", error.messages)
            ) from error
        if changed:
            log_activity(
                action=ActivityLog.Action.IOC_UPDATED,
                description=f"Indicator updated: {instance.value}.",
                actor=request.user,
                incident=instance.incident,
                request=request,
            )
        if old_type != instance.indicator_type or old_value != instance.value:
            instance.match_status = IndicatorOfCompromise.MatchStatus.UNCHECKED
            instance.last_checked_at = None
            instance.save(
                update_fields=("match_status", "last_checked_at", "updated_at")
            )
            check_indicator(instance, actor=request.user, request=request)
        return instance


class InvestigationFindingSerializer(serializers.ModelSerializer):
    incident = serializers.IntegerField(source="incident_id", read_only=True)
    created_by_username = serializers.CharField(
        source="created_by.username",
        read_only=True,
        allow_null=True,
    )
    updated_by_username = serializers.CharField(
        source="updated_by.username",
        read_only=True,
        allow_null=True,
    )
    finalized_by_username = serializers.CharField(
        source="finalized_by.username",
        read_only=True,
        allow_null=True,
    )
    finalize = serializers.BooleanField(write_only=True, required=False, default=False)

    class Meta:
        model = InvestigationFinding
        fields = (
            "incident",
            "summary",
            "findings",
            "identified_indicators",
            "evidence_reviewed",
            "actions_performed",
            "recommended_remediation",
            "final_disposition",
            "is_finalized",
            "finalize",
            "created_by_username",
            "updated_by_username",
            "finalized_by_username",
            "finalized_at",
            "created_at",
            "updated_at",
        )
        read_only_fields = (
            "incident",
            "is_finalized",
            "created_by_username",
            "updated_by_username",
            "finalized_by_username",
            "finalized_at",
            "created_at",
            "updated_at",
        )
        validators = ()

    def validate(self, attrs):
        if self.instance and self.instance.is_finalized:
            raise serializers.ValidationError(
                {"detail": "Finalized investigation findings are read-only."}
            )
        if not attrs:
            raise serializers.ValidationError(
                {"detail": "Provide investigation findings to save."}
            )
        return attrs

    def create(self, validated_data):
        request = self.context["request"]
        incident = self.context["incident"]
        finalize = validated_data.pop("finalize", False)
        finding = InvestigationFinding(
            incident=incident,
            created_by=request.user,
            updated_by=request.user,
            **validated_data,
        )
        if finalize:
            finding.is_finalized = True
            finding.finalized_by = request.user
            finding.finalized_at = timezone.now()
        try:
            finding.full_clean()
            finding.save()
        except DjangoValidationError as error:
            raise serializers.ValidationError(
                getattr(error, "message_dict", error.messages)
            ) from error
        log_activity(
            action=ActivityLog.Action.FINDINGS_UPDATED,
            description=(
                "Investigation findings finalized."
                if finalize
                else "Investigation findings saved."
            ),
            actor=request.user,
            incident=incident,
            request=request,
        )
        return finding

    def update(self, instance, validated_data):
        request = self.context["request"]
        finalize = validated_data.pop("finalize", False)
        for field, value in validated_data.items():
            setattr(instance, field, value)
        instance.updated_by = request.user
        if finalize:
            instance.is_finalized = True
            instance.finalized_by = request.user
            instance.finalized_at = timezone.now()
        try:
            instance.full_clean()
            instance.save()
        except DjangoValidationError as error:
            raise serializers.ValidationError(
                getattr(error, "message_dict", error.messages)
            ) from error
        log_activity(
            action=ActivityLog.Action.FINDINGS_UPDATED,
            description=(
                "Investigation findings finalized."
                if finalize
                else "Investigation findings updated."
            ),
            actor=request.user,
            incident=instance.incident,
            request=request,
        )
        return instance


class InvestigationEvidenceSerializer(serializers.ModelSerializer):
    file = serializers.FileField(write_only=True)
    incident = serializers.IntegerField(source="incident_id", read_only=True)
    uploaded_by_username = serializers.CharField(
        source="uploaded_by.username",
        read_only=True,
    )

    class Meta:
        model = InvestigationEvidence
        fields = (
            "id",
            "evidence_id",
            "incident",
            "file",
            "original_filename",
            "content_type",
            "file_size",
            "description",
            "classification",
            "uploaded_by_username",
            "uploaded_at",
        )
        read_only_fields = (
            "id",
            "evidence_id",
            "incident",
            "original_filename",
            "content_type",
            "file_size",
            "uploaded_by_username",
            "uploaded_at",
        )
        validators = ()

    def create(self, validated_data):
        request = self.context["request"]
        evidence = InvestigationEvidence(
            incident=self.context["incident"],
            uploaded_by=request.user,
            **validated_data,
        )
        try:
            evidence.full_clean()
            evidence.save()
        except DjangoValidationError as error:
            raise serializers.ValidationError(
                getattr(error, "message_dict", error.messages)
            ) from error
        log_activity(
            action=ActivityLog.Action.EVIDENCE_ADDED,
            description=(
                f"Evidence uploaded: {evidence.original_filename} "
                f"({evidence.file_size} bytes)."
            ),
            actor=request.user,
            incident=evidence.incident,
            request=request,
        )
        return evidence


class SecurityAlertSerializer(serializers.ModelSerializer):
    related_user = serializers.IntegerField(
        source="related_user_id",
        read_only=True,
        allow_null=True,
    )
    related_incident = serializers.IntegerField(
        source="related_incident_id",
        read_only=True,
        allow_null=True,
    )
    detection_rule_identifier = serializers.CharField(
        source="detection_rule.identifier",
        read_only=True,
        allow_null=True,
    )

    class Meta:
        model = SecurityAlert
        fields = (
            "id",
            "title",
            "description",
            "alert_type",
            "severity",
            "status",
            "related_user",
            "related_incident",
            "auto_generated",
            "detection_rule_identifier",
            "source_ip",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields


class SecurityAlertStatusSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=SecurityAlert.Status.choices)

    def update(self, instance, validated_data):
        try:
            return update_security_alert_status(
                actor=self.context["request"].user,
                alert=instance,
                status=validated_data["status"],
                request=self.context["request"],
            )
        except DjangoValidationError as error:
            raise serializers.ValidationError(
                getattr(error, "message_dict", error.messages)
            ) from error
        except DjangoPermissionDenied as error:
            raise PermissionDenied(str(error)) from error


class ActivityLogSerializer(serializers.ModelSerializer):
    actor = serializers.IntegerField(source="actor_id", read_only=True)
    actor_username = serializers.CharField(
        source="actor.username",
        read_only=True,
        allow_null=True,
    )
    incident_public_id = serializers.UUIDField(
        source="incident.public_id",
        read_only=True,
        allow_null=True,
    )

    class Meta:
        model = ActivityLog
        fields = (
            "id",
            "actor",
            "actor_username",
            "incident",
            "incident_public_id",
            "action",
            "description",
            "source_ip",
            "created_at",
        )
        read_only_fields = fields


class DetectionRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = DetectionRule
        fields = (
            "identifier",
            "name",
            "description",
            "enabled",
            "threshold",
            "window_seconds",
            "severity",
            "suppression_seconds",
            "updated_at",
        )
        read_only_fields = (
            "identifier",
            "name",
            "description",
            "updated_at",
        )

    def validate(self, attrs):
        editable_fields = {
            "enabled",
            "threshold",
            "window_seconds",
            "severity",
            "suppression_seconds",
        }
        unknown = set(self.initial_data) - editable_fields
        if unknown:
            raise serializers.ValidationError(
                {
                    field: "This detection rule field cannot be changed."
                    for field in sorted(unknown)
                }
            )
        for field, maximum in (
            ("threshold", 10000),
            ("window_seconds", 604800),
            ("suppression_seconds", 604800),
        ):
            value = attrs.get(field)
            if value is not None:
                if value < 1:
                    raise serializers.ValidationError(
                        {field: "Ensure this value is greater than or equal to 1."}
                    )
                if value > maximum:
                    raise serializers.ValidationError(
                        {field: f"Ensure this value is no greater than {maximum}."}
                    )
        return attrs


class AnalyticsQuerySerializer(serializers.Serializer):
    days = serializers.ChoiceField(
        choices=(("7", "Last 7 days"), ("30", "Last 30 days"), ("90", "Last 90 days")),
        required=False,
    )
    start_date = serializers.DateField(required=False)
    end_date = serializers.DateField(required=False)
    granularity = serializers.ChoiceField(
        choices=GRANULARITIES,
        default="daily",
    )

    def validate(self, attrs):
        default_start, default_end = default_analytics_dates()
        if "days" in attrs:
            if "start_date" in attrs or "end_date" in attrs:
                raise serializers.ValidationError(
                    {"date_range": "Use either a preset period or custom dates, not both."}
                )
            end_date = default_end
            start_date = end_date - timedelta(days=int(attrs.pop("days")) - 1)
        else:
            end_date = attrs.get("end_date", default_end)
            default_range = default_end - default_start
            start_date = attrs.get("start_date", end_date - default_range)
        try:
            validate_analytics_dates(start_date, end_date)
        except ValueError as error:
            raise serializers.ValidationError(
                {"date_range": str(error)}
            ) from error
        attrs["start_date"] = start_date
        attrs["end_date"] = end_date
        return attrs
