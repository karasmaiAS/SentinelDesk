from datetime import datetime, timedelta
from functools import wraps

from django.contrib.auth import get_user_model
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView, LogoutView
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse_lazy
from django.utils import timezone

from incidents.models import ActivityLog, LoginAttempt
from incidents.services import log_activity

from .forms import (
    AccountDetailsForm,
    RegistrationForm,
    UserManagementForm,
    UserProfileForm,
)
from .models import UserProfile
from .roles import get_role, is_administrator
from .services import update_managed_user


MAX_LOGIN_FAILURES = 10
LOGIN_FAILURE_WINDOW = timedelta(minutes=15)
LOGIN_LOCKOUT_WINDOW = timedelta(minutes=15)


class UserLoginView(LoginView):
    template_name = "accounts/login.html"

    def dispatch(self, request, *args, **kwargs):
        lockout_until = request.session.get("login_lockout_until")
        if lockout_until:
            lockout_time = datetime.fromisoformat(lockout_until)
            if timezone.now() < lockout_time:
                form = self.get_form()
                form.add_error(
                    None,
                    "Too many failed sign-in attempts. Please wait 15 minutes before trying again.",
                )
                return self.render_to_response(self.get_context_data(form=form), status=429)
            del request.session["login_lockout_until"]
        return super().dispatch(request, *args, **kwargs)

    def form_invalid(self, form):
        username = (self.request.POST.get("username") or "").strip()
        if username:
            failures = LoginAttempt.objects.filter(
                username__iexact=username,
                successful=False,
                attempted_at__gte=timezone.now() - LOGIN_FAILURE_WINDOW,
            ).count()
            if failures >= MAX_LOGIN_FAILURES:
                self.request.session["login_lockout_until"] = (
                    timezone.now() + LOGIN_LOCKOUT_WINDOW
                ).isoformat()
                form.add_error(
                    None,
                    "Too many failed sign-in attempts. Please wait 15 minutes before trying again.",
                )
                return self.render_to_response(self.get_context_data(form=form), status=429)
        return super().form_invalid(form)

    def form_valid(self, form):
        self.request.session.pop("login_lockout_until", None)
        return super().form_valid(form)

    def get_success_url(self):
        next_url = self.get_redirect_url()
        if next_url:
            return next_url
        if self.request.user.is_staff:
            return reverse_lazy("core:admin_dashboard")
        return reverse_lazy("incidents:dashboard")


class UserLogoutView(LogoutView):
    next_page = reverse_lazy("accounts:login")


def register(request):
    if request.user.is_authenticated:
        if request.user.is_staff:
            return redirect("core:admin_dashboard")
        return redirect("incidents:dashboard")

    if request.method == "POST":
        form = RegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Your account has been created. You can now sign in.")
            return redirect("accounts:login")
    else:
        form = RegistrationForm()

    return render(request, "accounts/register.html", {"form": form})


def administrator_required(view):
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect(f"{reverse_lazy('accounts:login')}?next={request.path}")
        if not is_administrator(request.user):
            raise PermissionDenied
        return view(request, *args, **kwargs)

    return wrapped


@administrator_required
def user_management(request):
    user_model = get_user_model()
    bound_user_id = request.POST.get("user_id") if request.method == "POST" else None
    bound_user = None
    bound_form = None
    if bound_user_id:
        bound_user = get_object_or_404(
            user_model.objects.exclude(is_superuser=True),
            pk=bound_user_id,
        )
        bound_form = UserManagementForm(request.POST)
        if bound_form.is_valid():
            try:
                update_managed_user(
                    actor=request.user,
                    user=bound_user,
                    role=bound_form.cleaned_data["role"],
                    is_active=bound_form.cleaned_data["is_active"],
                    request=request,
                )
            except ValidationError as error:
                bound_form.add_error(None, error)
            else:
                messages.success(request, f"Updated account for {bound_user.username}.")
                return redirect("accounts:user_management")

    users = user_model.objects.exclude(is_superuser=True).order_by("username")
    search_query = request.GET.get("q", "").strip()
    if search_query:
        users = users.filter(
            Q(username__icontains=search_query) | Q(email__icontains=search_query)
        )
    user_rows = []
    selected_role = request.GET.get("role", "")
    for managed_user in users:
        managed_role = get_role(managed_user)
        if selected_role and managed_role != selected_role:
            continue
        form = (
            bound_form
            if bound_user and managed_user.pk == bound_user.pk
            else UserManagementForm(
                initial={
                    "role": managed_role,
                    "is_active": managed_user.is_active,
                }
            )
        )
        user_rows.append({"user": managed_user, "form": form})

    return render(
        request,
        "accounts/user_management.html",
        {
            "user_rows": user_rows,
            "search_query": search_query,
            "selected_role": selected_role,
        },
    )


@login_required
def profile(request):
    profile_record, _ = UserProfile.objects.get_or_create(user=request.user)
    account_form = AccountDetailsForm(
        request.POST or None,
        instance=request.user,
        prefix="account",
    )
    profile_form = UserProfileForm(
        request.POST or None,
        instance=profile_record,
        prefix="profile",
    )
    if request.method == "POST" and account_form.is_valid() and profile_form.is_valid():
        with transaction.atomic():
            account_form.save()
            profile_form.save()
            log_activity(
                action=ActivityLog.Action.ACCOUNT_UPDATED,
                description=f"Profile updated for {request.user.get_username()}.",
                actor=request.user,
                request=request,
            )
        messages.success(request, "Your profile has been updated.")
        return redirect("accounts:profile")
    return render(
        request,
        "accounts/profile.html",
        {"account_form": account_form, "profile_form": profile_form},
    )
