from datetime import timedelta

from django import forms
from django.utils import timezone

from incidents.analytics import validate_analytics_dates
from incidents.models import (
    DetectionRule,
    InvestigationEvidence,
    InvestigationFinding,
    IndicatorOfCompromise,
    SecurityAlert,
)


class DetectionRuleForm(forms.ModelForm):
    threshold = forms.IntegerField(min_value=1, max_value=10000)
    window_seconds = forms.IntegerField(min_value=1, max_value=604800)
    suppression_seconds = forms.IntegerField(min_value=1, max_value=604800)

    class Meta:
        model = DetectionRule
        fields = (
            "enabled",
            "threshold",
            "window_seconds",
            "severity",
            "suppression_seconds",
        )
        widgets = {
            "enabled": forms.CheckboxInput(attrs={"class": "form-check-input"}),
            "threshold": forms.NumberInput(attrs={"class": "form-control", "min": 1}),
            "window_seconds": forms.NumberInput(
                attrs={"class": "form-control", "min": 1}
            ),
            "severity": forms.Select(
                attrs={"class": "form-select"},
                choices=SecurityAlert.Severity.choices,
            ),
            "suppression_seconds": forms.NumberInput(
                attrs={"class": "form-control", "min": 1}
            ),
        }


class AnalyticsFilterForm(forms.Form):
    period = forms.ChoiceField(
        choices=(
            ("7", "Last 7 days"),
            ("30", "Last 30 days"),
            ("90", "Last 90 days"),
            ("custom", "Custom range"),
        ),
        initial="30",
        widget=forms.Select(attrs={"class": "form-select"}),
    )
    granularity = forms.ChoiceField(
        choices=(
            ("daily", "Daily"),
            ("weekly", "Weekly"),
            ("monthly", "Monthly"),
        ),
        initial="daily",
        widget=forms.Select(attrs={"class": "form-select"}),
    )
    start_date = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={"class": "form-control", "type": "date"}),
    )
    end_date = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={"class": "form-control", "type": "date"}),
    )

    def clean(self):
        cleaned_data = super().clean()
        period = cleaned_data.get("period")
        today = timezone.localdate()
        if period == "custom":
            start_date = cleaned_data.get("start_date")
            end_date = cleaned_data.get("end_date")
            if not start_date:
                self.add_error("start_date", "Enter a start date for the custom range.")
            if not end_date:
                self.add_error("end_date", "Enter an end date for the custom range.")
            if not start_date or not end_date:
                return cleaned_data
        elif period in ("7", "30", "90"):
            end_date = today
            start_date = end_date - timedelta(days=int(period) - 1)
            cleaned_data["start_date"] = start_date
            cleaned_data["end_date"] = end_date
        else:
            return cleaned_data

        try:
            validate_analytics_dates(start_date, end_date)
        except ValueError as error:
            self.add_error(None, str(error))
        return cleaned_data


class IndicatorOfCompromiseForm(forms.ModelForm):
    date_identified = forms.DateTimeField(
        required=False,
        input_formats=("%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S"),
        widget=forms.DateTimeInput(
            attrs={"class": "form-control", "type": "datetime-local"},
            format="%Y-%m-%dT%H:%M",
        ),
    )

    class Meta:
        model = IndicatorOfCompromise
        fields = (
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
        widgets = {
            "indicator_type": forms.Select(attrs={"class": "form-select"}),
            "value": forms.TextInput(attrs={"class": "form-control"}),
            "description": forms.Textarea(
                attrs={"class": "form-control", "rows": 2}
            ),
            "source": forms.TextInput(attrs={"class": "form-control"}),
            "confidence": forms.NumberInput(
                attrs={"class": "form-control", "min": 0, "max": 100}
            ),
            "risk": forms.Select(attrs={"class": "form-select"}),
            "date_identified": forms.DateTimeInput(
                attrs={"class": "form-control", "type": "datetime-local"}
            ),
            "notes": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
            "status": forms.Select(attrs={"class": "form-select"}),
        }

    def clean_date_identified(self):
        return self.cleaned_data.get("date_identified") or timezone.now()


class InvestigationEvidenceForm(forms.ModelForm):
    class Meta:
        model = InvestigationEvidence
        fields = ("file", "description", "classification")
        widgets = {
            "file": forms.ClearableFileInput(attrs={"class": "form-control"}),
            "description": forms.Textarea(
                attrs={"class": "form-control", "rows": 2}
            ),
            "classification": forms.Select(attrs={"class": "form-select"}),
        }


class InvestigationFindingForm(forms.ModelForm):
    finalize = forms.BooleanField(required=False)

    class Meta:
        model = InvestigationFinding
        fields = (
            "summary",
            "findings",
            "identified_indicators",
            "evidence_reviewed",
            "actions_performed",
            "recommended_remediation",
            "final_disposition",
        )
        widgets = {
            "summary": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
            "findings": forms.Textarea(attrs={"class": "form-control", "rows": 3}),
            "identified_indicators": forms.Textarea(
                attrs={"class": "form-control", "rows": 2}
            ),
            "evidence_reviewed": forms.Textarea(
                attrs={"class": "form-control", "rows": 2}
            ),
            "actions_performed": forms.Textarea(
                attrs={"class": "form-control", "rows": 2}
            ),
            "recommended_remediation": forms.Textarea(
                attrs={"class": "form-control", "rows": 2}
            ),
            "final_disposition": forms.Select(attrs={"class": "form-select"}),
        }
