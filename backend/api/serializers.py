from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.core.exceptions import (
    PermissionDenied as DjangoPermissionDenied,
    ValidationError as DjangoValidationError,
)
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied

from accounts.roles import ROLE_ADMINISTRATOR, get_role
from incidents.models import (
    ActivityLog,
    Incident,
    InvestigationNote,
    SecurityAlert,
)
from incidents.services import (
    add_investigation_note,
    assign_incident,
    create_incident,
    update_incident,
    update_security_alert_status,
)


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


class SecurityAlertSerializer(serializers.ModelSerializer):
    related_user = serializers.IntegerField(
        source="related_user_id",
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
