from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError
from django.db import transaction

from .models import UserProfile
from .roles import ROLE_REGULAR_USER, role_group


class RegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta(UserCreationForm.Meta):
        model = get_user_model()
        fields = ("username", "email")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs["class"] = "form-control"
        self.fields["password1"].help_text = (
            "Use at least 8 characters. Avoid common passwords, personal details, "
            "or a password made only of numbers."
        )
        self.fields["password2"].help_text = "Enter the same password again."

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        if get_user_model().objects.filter(email__iexact=email).exists():
            raise ValidationError("An account with this email already exists.")
        return email

    @transaction.atomic
    def save(self, commit=True):
        user = super().save(commit=commit)
        if commit:
            user.groups.add(role_group(ROLE_REGULAR_USER))
            UserProfile.objects.get_or_create(user=user)
        return user


class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ("department", "phone")
        widgets = {
            "department": forms.TextInput(attrs={"class": "form-control"}),
            "phone": forms.TextInput(attrs={"class": "form-control"}),
        }


class AccountDetailsForm(forms.ModelForm):
    class Meta:
        model = get_user_model()
        fields = ("username", "email", "first_name", "last_name")
        widgets = {
            "username": forms.TextInput(attrs={"class": "form-control"}),
            "email": forms.EmailInput(attrs={"class": "form-control"}),
            "first_name": forms.TextInput(attrs={"class": "form-control"}),
            "last_name": forms.TextInput(attrs={"class": "form-control"}),
        }

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        users = get_user_model().objects.filter(email__iexact=email).exclude(
            pk=self.instance.pk
        )
        if users.exists():
            raise ValidationError("An account with this email already exists.")
        return email


class UserManagementForm(forms.Form):
    role = forms.ChoiceField(
        choices=(
            (ROLE_REGULAR_USER, "Regular User"),
            ("Security Analyst", "Security Analyst"),
            ("Administrator", "Administrator"),
        ),
        widget=forms.Select(attrs={"class": "form-select"}),
    )
    is_active = forms.BooleanField(
        required=False,
        label="Account active",
        widget=forms.CheckboxInput(attrs={"class": "form-check-input"}),
    )
