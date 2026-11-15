from django import forms

from .models import Incident


class IncidentSubmissionForm(forms.ModelForm):
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
            "description": forms.Textarea(attrs={"rows": 5}),
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
