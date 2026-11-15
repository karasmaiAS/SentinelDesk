from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib import messages

from .forms import IncidentSubmissionForm
from .models import Incident
from .services import create_incident


@login_required
def dashboard(request):
    incidents = Incident.objects.filter(reporter=request.user)
    return render(
        request,
        "incidents/dashboard.html",
        {
            "recent_incidents": incidents[:5],
            "incident_count": incidents.count(),
            "open_count": incidents.exclude(
                status__in=(Incident.Status.RESOLVED, Incident.Status.CLOSED)
            ).count(),
        },
    )


@login_required
def incident_list(request):
    incidents = Incident.objects.filter(reporter=request.user)
    return render(request, "incidents/incident_list.html", {"incidents": incidents})


@login_required
def incident_detail(request, pk):
    incident = get_object_or_404(Incident, pk=pk, reporter=request.user)
    status_history = incident.activity_entries.filter(
        action__in=(
            "status_changed",
            "severity_changed",
            "assignment_changed",
        )
    ).select_related("actor")
    return render(
        request,
        "incidents/incident_detail.html",
        {"incident": incident, "status_history": status_history},
    )


@login_required
def incident_create(request):
    if request.method == "POST":
        form = IncidentSubmissionForm(request.POST)
        if form.is_valid():
            incident = create_incident(
                reporter=request.user,
                data=form.cleaned_data,
                request=request,
            )
            messages.success(request, "Incident report submitted.")
            return redirect("incidents:detail", pk=incident.pk)
    else:
        form = IncidentSubmissionForm()

    return render(request, "incidents/incident_form.html", {"form": form})
