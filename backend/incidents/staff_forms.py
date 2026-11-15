from django import forms
from django.core.exceptions import ValidationError

from accounts.roles import active_analysts, is_administrator

from .models import Incident, InvestigationNote, SecurityAlert
from .services import STATUS_TRANSITIONS


class StaffIncidentUpdateForm(forms.Form):
    status = forms.ChoiceField(widget=forms.Select(attrs={"class": "form-select"}))
    resolution_summary = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={"class": "form-control", "rows": 4}),
    )

    def __init__(self, *args, actor, incident, **kwargs):
        super().__init__(*args, **kwargs)
        allowed_statuses = {incident.status} | STATUS_TRANSITIONS[incident.status]
        self.fields["status"].choices = [
            (value, label)
            for value, label in Incident.Status.choices
            if value in allowed_statuses
        ]
        self.fields["status"].initial = incident.status
        self.fields["resolution_summary"].initial = incident.resolution_summary
        self.fields["status"].widget.attrs["class"] = "form-select"
        if is_administrator(actor):
            self.fields["severity"] = forms.ChoiceField(
                choices=Incident.Severity.choices,
                initial=incident.severity,
                widget=forms.Select(attrs={"class": "form-select"}),
            )

    def get_changes(self):
        return {
            key: value
            for key, value in self.cleaned_data.items()
            if key in {"status", "severity", "resolution_summary"}
        }


class IncidentAssignmentForm(forms.Form):
    analyst = forms.ModelChoiceField(
        queryset=active_analysts(),
        required=False,
        empty_label="Unassigned",
        widget=forms.Select(attrs={"class": "form-select"}),
    )


class InvestigationNoteForm(forms.ModelForm):
    class Meta:
        model = InvestigationNote
        fields = ("content",)
        widgets = {
            "content": forms.Textarea(
                attrs={
                    "class": "form-control",
                    "rows": 4,
                    "maxlength": 10000,
                }
            )
        }

    def clean_content(self):
        content = self.cleaned_data["content"].strip()
        if not content:
            raise ValidationError("Investigation notes cannot be empty.")
        return content


class SecurityAlertStatusForm(forms.Form):
    status = forms.ChoiceField(
        choices=SecurityAlert.Status.choices,
        widget=forms.Select(attrs={"class": "form-select"}),
    )
