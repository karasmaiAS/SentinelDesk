from django import forms

from .models import (
    INCIDENT_DESCRIPTION_MAX_LENGTH,
    INCIDENT_TITLE_REQUIRED_ERROR,
    INCIDENT_TITLE_MAX_LENGTH,
    Incident,
    validate_incident_title,
)


class IncidentSubmissionForm(forms.ModelForm):
    title = forms.CharField(
        max_length=INCIDENT_TITLE_MAX_LENGTH,
        validators=[validate_incident_title],
        error_messages={
            "max_length": "Incident title must be 200 characters or fewer.",
            "required": INCIDENT_TITLE_REQUIRED_ERROR,
        },
        help_text="Include at least one letter; maximum 200 characters.",
    )
    description = forms.CharField(
        max_length=INCIDENT_DESCRIPTION_MAX_LENGTH,
        widget=forms.Textarea(attrs={"rows": 5}),
        error_messages={
            "max_length": (
                "Incident description must be 5,000 characters or fewer."
            )
        },
        help_text="Maximum 5,000 characters.",
    )

    class Meta:
        model = Incident
        fields = (
            "title",
            "category",
            "description",
            "severity",
            "evidence_reference",
        )
        widgets = {
            "evidence_reference": forms.TextInput(
                attrs={"placeholder": "Optional link or reference"}
            ),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name, field in self.fields.items():
            field.widget.attrs["class"] = (
                "form-select" if name == "category" or name == "severity" else "form-control"
            )
