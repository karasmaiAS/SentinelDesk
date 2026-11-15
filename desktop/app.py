import json
import logging
import os
import queue
import threading
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, ttk

from .api_client import ApiError, SentinelDeskApi

logger = logging.getLogger(__name__)

DEFAULT_COLORS = {
    "background": "#0B1220",
    "sidebar": "#111B2E",
    "surface": "#162338",
    "surfaceRaised": "#1B2A41",
    "primary": "#2563EB",
    "secondary": "#06B6D4",
    "text": "#F1F5F9",
    "textMuted": "#94A3B8",
    "border": "#263449",
    "critical": "#EF4444",
    "high": "#F97316",
    "medium": "#EAB308",
    "low": "#22C55E",
}


def _load_colors():
    token_file = Path(__file__).resolve().parent.parent / "shared" / "design_tokens.json"
    try:
        with token_file.open(encoding="utf-8") as file:
            colors = json.load(file)["colors"]
    except (OSError, ValueError, KeyError, TypeError):
        colors = {}
    return {**DEFAULT_COLORS, **colors}


COLORS = _load_colors()

STATUS_CHOICES = (
    "open",
    "under_investigation",
    "pending",
    "resolved",
    "closed",
)
SEVERITY_CHOICES = ("critical", "high", "medium", "low")
ALERT_STATUS_CHOICES = ("open", "investigating", "resolved")
CATEGORY_CHOICES = (
    "phishing",
    "malware",
    "unauthorized_access",
    "suspicious_login",
    "data_breach",
    "social_engineering",
    "denial_of_service",
    "other",
)


class SentinelDeskApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SentinelDesk | Analyst Console")
        self.geometry("1180x760")
        self.minsize(900, 600)
        self.configure(background=COLORS["background"])
        self.api = None
        self.current_user = None
        self._login_results = queue.Queue()
        self._login_in_progress = False
        self._configure_styles()
        self.show_login()

    def _configure_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            ".",
            background=COLORS["background"],
            foreground=COLORS["text"],
            fieldbackground=COLORS["surfaceRaised"],
            bordercolor=COLORS["border"],
            font=("Segoe UI", 10),
        )
        style.configure("TFrame", background=COLORS["background"])
        style.configure("Panel.TFrame", background=COLORS["surface"])
        style.configure("Sidebar.TFrame", background=COLORS["sidebar"])
        style.configure("TLabel", background=COLORS["background"], foreground=COLORS["text"])
        style.configure("Panel.TLabel", background=COLORS["surface"], foreground=COLORS["text"])
        style.configure(
            "Title.TLabel",
            font=("Segoe UI Semibold", 21),
            foreground=COLORS["text"],
        )
        style.configure(
            "Muted.TLabel",
            foreground=COLORS["textMuted"],
        )
        style.configure(
            "Sidebar.TLabel",
            background=COLORS["sidebar"],
            foreground=COLORS["textMuted"],
        )
        style.configure(
            "TButton",
            background=COLORS["surfaceRaised"],
            foreground=COLORS["text"],
            padding=(12, 8),
        )
        style.map(
            "TButton",
            background=[("active", COLORS["secondary"])],
            foreground=[("active", COLORS["text"])],
        )
        style.configure(
            "Accent.TButton",
            background=COLORS["primary"],
            foreground=COLORS["text"],
            font=("Segoe UI Semibold", 10),
        )
        style.configure(
            "TEntry",
            fieldbackground=COLORS["surfaceRaised"],
            foreground=COLORS["text"],
            insertcolor=COLORS["text"],
            padding=8,
        )
        style.configure(
            "TCombobox",
            fieldbackground=COLORS["surfaceRaised"],
            foreground=COLORS["text"],
            padding=6,
        )
        style.configure(
            "TCheckbutton",
            background=COLORS["background"],
            foreground=COLORS["textMuted"],
        )
        style.configure(
            "Horizontal.TProgressbar",
            background=COLORS["secondary"],
            troughcolor=COLORS["surfaceRaised"],
        )
        style.configure(
            "Treeview",
            background=COLORS["surface"],
            fieldbackground=COLORS["surface"],
            foreground=COLORS["text"],
            rowheight=29,
            bordercolor=COLORS["border"],
        )
        style.configure(
            "Treeview.Heading",
            background=COLORS["surfaceRaised"],
            foreground=COLORS["text"],
            font=("Segoe UI Semibold", 9),
        )
        style.map(
            "Treeview",
            background=[("selected", COLORS["primary"])],
            foreground=[("selected", "white")],
        )

    def _clear(self):
        for child in self.winfo_children():
            child.destroy()

    def _show_error(self, error):
        if isinstance(error, ApiError):
            messagebox.showerror("SentinelDesk API", str(error), parent=self)
        else:
            messagebox.showerror(
                "SentinelDesk",
                f"Something went wrong: {error}",
                parent=self,
            )

    def show_login(self):
        self._clear()
        container = ttk.Frame(self, padding=32)
        container.place(relx=0.5, rely=0.5, anchor="center")
        ttk.Label(container, text="SentinelDesk", style="Title.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 4)
        )
        ttk.Label(
            container,
            text="Security operations console",
            style="Muted.TLabel",
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 22))

        ttk.Label(container, text="API server").grid(row=2, column=0, sticky="w", pady=6)
        self.api_url = tk.StringVar(
            value=os.environ.get(
                "SENTINELDESK_API_URL",
                "http://127.0.0.1:8000/api",
            )
        )
        ttk.Entry(container, textvariable=self.api_url, width=42).grid(
            row=2, column=1, sticky="ew", pady=6
        )
        ttk.Label(container, text="Username").grid(row=3, column=0, sticky="w", pady=6)
        self.username = tk.StringVar()
        username_entry = ttk.Entry(container, textvariable=self.username, width=42)
        username_entry.grid(row=3, column=1, sticky="ew", pady=6)
        ttk.Label(container, text="Password").grid(row=4, column=0, sticky="w", pady=6)
        self.password = tk.StringVar()
        password_entry = ttk.Entry(
            container,
            textvariable=self.password,
            show="*",
            width=42,
        )
        password_entry.grid(row=4, column=1, sticky="ew", pady=6)
        self.show_password = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            container,
            text="Show password",
            variable=self.show_password,
            command=lambda: password_entry.configure(
                show="" if self.show_password.get() else "*"
            ),
        ).grid(row=5, column=1, sticky="w")
        self.login_button = ttk.Button(
            container,
            text="Sign in",
            style="Accent.TButton",
            command=self._login,
        )
        self.login_button.grid(row=6, column=1, sticky="e", pady=(18, 0))
        self.login_progress = ttk.Progressbar(
            container,
            mode="indeterminate",
            length=240,
        )
        self.login_progress.grid(row=7, column=1, sticky="e", pady=(8, 0))
        self.login_progress.grid_remove()
        password_entry.bind("<Return>", lambda _event: self._login())
        username_entry.focus_set()

    def _login(self):
        if self._login_in_progress:
            return
        base_url = self.api_url.get().strip()
        username = self.username.get().strip()
        password = self.password.get()
        if not base_url or not username or not password:
            messagebox.showwarning(
                "Sign in",
                "Enter the API server, username, and password.",
                parent=self,
            )
            return

        self._login_in_progress = True
        self.login_button.configure(state="disabled", text="Signing in…")
        self.login_progress.grid()
        self.login_progress.start(12)
        threading.Thread(
            target=self._authenticate,
            args=(base_url, username, password),
            daemon=True,
        ).start()
        self.after(100, self._poll_login_result)

    def _authenticate(self, base_url, username, password):
        api = SentinelDeskApi(base_url)
        try:
            api.login(username, password)
            user = api.get_current_user()
            if user.get("role") not in ("Administrator", "Security Analyst"):
                message = (
                    "The desktop console is for administrators and security "
                    "analysts. Use the SentinelDesk website for a regular account."
                )
                try:
                    api.logout()
                except ApiError as error:
                    message = f"{message}\nThe session could not be revoked: {error}"
                self._login_results.put((None, None, ApiError(message, 403)))
                return
            self._login_results.put((api, user, None))
        except Exception as error:
            if isinstance(error, ApiError):
                result_error = error
            else:
                logger.exception("Unexpected error during SentinelDesk sign-in")
                result_error = ApiError(
                    "Sign-in could not be completed because of an unexpected error. "
                    "Check the desktop application output for diagnostic details."
                )
            self._login_results.put((None, None, result_error))

    def _poll_login_result(self):
        try:
            api, user, error = self._login_results.get_nowait()
        except queue.Empty:
            self.after(100, self._poll_login_result)
            return

        self._login_in_progress = False
        self.login_progress.stop()
        self.login_progress.grid_remove()
        if error is not None:
            self.login_button.configure(state="normal", text="Sign in")
            self.password.set("")
            self._show_error(error)
            return

        self.api = api
        self.current_user = user
        self.password.set("")
        self.show_workspace()

    def show_workspace(self):
        self._clear()
        header = ttk.Frame(self, padding=(20, 14))
        header.pack(fill="x")
        ttk.Label(header, text="SentinelDesk", style="Title.TLabel").pack(side="left")
        ttk.Label(
            header,
            text=f"{self.current_user['display_name']}  ·  {self.current_user['role']}",
            style="Muted.TLabel",
        ).pack(side="right", padx=(0, 12))
        ttk.Button(header, text="Sign out", command=self._logout).pack(side="right")

        body = ttk.Frame(self)
        body.pack(fill="both", expand=True)
        navigation = ttk.Frame(body, style="Sidebar.TFrame", padding=12)
        navigation.pack(side="left", fill="y", padx=(14, 8), pady=(0, 14))
        self.content = ttk.Frame(body, padding=(14, 8, 18, 18))
        self.content.pack(side="left", fill="both", expand=True)

        self._nav_button(navigation, "Overview", self.show_dashboard)
        self._nav_button(navigation, "Incidents", self.show_incidents)
        self._nav_button(
            navigation,
            "Assigned incidents",
            lambda: self.show_incidents(assigned_only=True),
        )
        self._nav_button(navigation, "Security alerts", self.show_alerts)
        self._nav_button(navigation, "Activity log", self.show_activity)
        self._nav_button(navigation, "Account / Profile", self.show_profile)
        if self.current_user["role"] == "Administrator":
            self._nav_button(navigation, "Analysts", self.show_analysts)
        self._nav_button(navigation, "Sign out", self._logout)
        ttk.Label(
            navigation,
            text="Connected to Django REST API",
            style="Sidebar.TLabel",
            wraplength=170,
        ).pack(side="bottom", anchor="w", pady=6)
        self.show_dashboard()

    def _nav_button(self, parent, label, command):
        ttk.Button(parent, text=label, command=command, width=22).pack(
            fill="x", pady=4
        )

    def _logout(self):
        if self.api:
            try:
                self.api.logout()
            except ApiError as error:
                messagebox.showwarning("Sign out", str(error), parent=self)
        self.api = None
        self.current_user = None
        self.show_login()

    def _clear_content(self):
        for child in self.content.winfo_children():
            child.destroy()
        if hasattr(self, "page_info"):
            del self.page_info
        if hasattr(self, "pager"):
            del self.pager

    def _page_heading(self, title, subtitle=None):
        ttk.Label(self.content, text=title, style="Title.TLabel").pack(
            anchor="w", pady=(4, 2)
        )
        if subtitle:
            ttk.Label(
                self.content,
                text=subtitle,
                style="Muted.TLabel",
            ).pack(anchor="w", pady=(0, 16))

    def show_dashboard(self):
        self._clear_content()
        self._page_heading("Operations overview", "Live statistics from the SentinelDesk backend.")
        try:
            stats = self.api.get_statistics()
        except ApiError as error:
            self._show_error(error)
            return

        grid = ttk.Frame(self.content)
        grid.pack(fill="x", pady=(12, 20))
        cards = (
            ("Total incidents", "total_incidents"),
            ("Open incidents", "open_incidents"),
            ("Under investigation", "under_investigation_incidents"),
            ("Pending", "pending_incidents"),
            ("Resolved", "resolved_incidents"),
            ("Critical", "critical_incidents"),
            ("High severity", "high_severity_incidents"),
            ("Medium severity", "medium_severity_incidents"),
            ("Low severity", "low_severity_incidents"),
            ("Assigned incidents", "assigned_incidents"),
            ("Security alerts", "total_security_alerts"),
            ("Active users", "active_users"),
        )
        for index, (title, key) in enumerate(cards):
            row, column = divmod(index, 3)
            panel = ttk.Frame(grid, style="Panel.TFrame", padding=16)
            panel.grid(row=row, column=column, sticky="nsew", padx=5, pady=5)
            ttk.Label(panel, text=title, style="Muted.TLabel").pack(anchor="w")
            value = stats.get(key)
            ttk.Label(
                panel,
                text="—" if value is None else str(value),
                style="Panel.TLabel",
                font=("Segoe UI Semibold", 22),
            ).pack(anchor="w", pady=(8, 0))
        for column in range(3):
            grid.columnconfigure(column, weight=1)

        breakdown = ttk.Frame(self.content, style="Panel.TFrame", padding=16)
        breakdown.pack(fill="x")
        ttk.Label(
            breakdown,
            text="Incidents by category",
            style="Panel.TLabel",
            font=("Segoe UI Semibold", 12),
        ).pack(anchor="w", pady=(0, 10))
        categories = stats.get("incidents_by_category", {})
        severity = stats.get("incidents_by_severity", {})
        values = "    ".join(
            f"{category.replace('_', ' ').title()}: {count}"
            for category, count in categories.items()
        )
        ttk.Label(breakdown, text=values or "No incident data", style="Panel.TLabel").pack(
            anchor="w"
        )
        values = "    ".join(
            f"{level.title()}: {count}" for level, count in severity.items()
        )
        ttk.Label(breakdown, text=values or "No severity data", style="Panel.TLabel").pack(
            anchor="w", pady=(8, 0)
        )
        ttk.Button(
            self.content,
            text="Refresh",
            command=self.show_dashboard,
        ).pack(anchor="e", pady=(10, 0))

    def show_profile(self):
        self._clear_content()
        self._page_heading("Account / Profile", "Your authenticated SentinelDesk account.")
        try:
            user = self.api.get_current_user()
        except ApiError as error:
            self._show_error(error)
            return
        profile = ttk.Frame(self.content, style="Panel.TFrame", padding=20)
        profile.pack(fill="x", anchor="n", pady=10)
        for label, value in (
            ("User ID", user["id"]),
            ("Username", user["username"]),
            ("Display name", user["display_name"]),
            ("Role", user["role"]),
        ):
            row = ttk.Frame(profile, style="Panel.TFrame")
            row.pack(fill="x", pady=7)
            ttk.Label(row, text=label, style="Muted.TLabel", width=18).pack(
                side="left"
            )
            ttk.Label(row, text=str(value), style="Panel.TLabel").pack(side="left")

    def show_incidents(self, assigned_only=False):
        self._clear_content()
        self.incident_assigned_only = assigned_only
        title = "Assigned incidents" if assigned_only else "Incident queue"
        self._page_heading(
            title,
            "Search, filter, and open incident investigations.",
        )
        controls = ttk.Frame(self.content)
        controls.pack(fill="x", pady=(0, 12))
        self.incident_search = tk.StringVar()
        search_entry = ttk.Entry(
            controls,
            textvariable=self.incident_search,
            width=25,
        )
        search_entry.pack(side="left", padx=(0, 6))
        search_entry.bind("<Return>", lambda _event: self._search_incidents())
        self.incident_category = tk.StringVar()
        self._filter_combo(controls, self.incident_category, ("",) + CATEGORY_CHOICES, 18)
        self.incident_severity = tk.StringVar()
        self._filter_combo(controls, self.incident_severity, ("",) + SEVERITY_CHOICES, 12)
        self.incident_status = tk.StringVar()
        self._filter_combo(controls, self.incident_status, ("",) + STATUS_CHOICES, 24)
        ttk.Button(controls, text="Search", command=self._search_incidents).pack(
            side="left", padx=4
        )
        ttk.Button(controls, text="Clear", command=self._clear_incident_filters).pack(
            side="left", padx=4
        )

        self.incident_tree = self._make_tree(
            self.content,
            (
                ("id", "ID", 55),
                ("title", "Title", 230),
                ("category", "Category", 150),
                ("severity", "Severity", 90),
                ("status", "Status", 150),
                ("reporter", "Reporter", 120),
                ("analyst", "Assigned analyst", 130),
            ),
        )
        self.incident_tree.bind("<Double-1>", lambda _event: self._open_selected_incident())
        self.incident_page = 1
        ttk.Button(
            self.content,
            text="Open selected incident",
            style="Accent.TButton",
            command=self._open_selected_incident,
        ).pack(anchor="e", pady=(10, 0))
        self._load_incidents()

    def _filter_combo(self, parent, variable, values, width):
        combo = ttk.Combobox(
            parent,
            textvariable=variable,
            values=values,
            state="readonly",
            width=width,
        )
        combo.pack(side="left", padx=4)

    def _clear_incident_filters(self):
        self.incident_search.set("")
        self.incident_category.set("")
        self.incident_severity.set("")
        self.incident_status.set("")
        self.incident_page = 1
        self._load_incidents()

    def _search_incidents(self):
        self.incident_page = 1
        self._load_incidents()

    def _load_incidents(self, page_number=None):
        if page_number is not None:
            self.incident_page = page_number
        filters = {
            "search": self.incident_search.get().strip(),
            "category": self.incident_category.get(),
            "severity": self.incident_severity.get(),
            "status": self.incident_status.get(),
            "page": self.incident_page,
        }
        filters = {key: value for key, value in filters.items() if value}
        try:
            if self.incident_assigned_only:
                page = self.api.get_assigned_incidents(**filters)
            else:
                page = self.api.get_incidents(**filters)
        except ApiError as error:
            self._show_error(error)
            return
        self._fill_tree(
            self.incident_tree,
            (
                (
                    row["id"],
                    row["title"],
                    row["category"].replace("_", " ").title(),
                    row["severity"].title(),
                    row["status"].replace("_", " ").title(),
                    row.get("reporter_username", ""),
                    row.get("assigned_analyst_username") or "Unassigned",
                )
                for row in page["results"]
            ),
        )
        self._set_tree_page_info(page)
        self._render_pager(
            self.content,
            self.incident_page,
            page,
            self._load_incidents,
        )

    def _make_tree(self, parent, columns):
        container = ttk.Frame(parent)
        container.pack(fill="both", expand=True)
        names = [column[0] for column in columns]
        tree = ttk.Treeview(container, columns=names, show="headings", selectmode="browse")
        for name, heading, width in columns:
            tree.heading(name, text=heading)
            tree.column(name, width=width, minwidth=45, anchor="w")
        for severity in SEVERITY_CHOICES:
            tree.tag_configure(severity, foreground=COLORS[severity])
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
        horizontal_scrollbar = ttk.Scrollbar(
            container,
            orient="horizontal",
            command=tree.xview,
        )
        tree.configure(
            yscrollcommand=scrollbar.set,
            xscrollcommand=horizontal_scrollbar.set,
        )
        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        horizontal_scrollbar.pack(side="bottom", fill="x")
        return tree

    @staticmethod
    def _fill_tree(tree, rows):
        for item in tree.get_children():
            tree.delete(item)
        for row in rows:
            severity = str(row[3]).lower() if len(row) > 3 else ""
            tags = (severity,) if severity in SEVERITY_CHOICES else ()
            tree.insert("", "end", values=row, tags=tags)

    def _set_tree_page_info(self, page):
        if hasattr(self, "page_info"):
            self.page_info.destroy()
        self.page_info = ttk.Label(
            self.content,
            text=f"Showing {len(page['results'])} of {page['count']} records",
            style="Muted.TLabel",
        )
        self.page_info.pack(anchor="w", pady=(8, 0))

    def _render_pager(self, parent, page_number, page_data, on_change):
        if hasattr(self, "pager"):
            self.pager.destroy()
        self.pager = ttk.Frame(parent)
        self.pager.pack(fill="x", pady=(8, 0))
        ttk.Button(
            self.pager,
            text="Previous",
            state="normal" if page_data["previous"] else "disabled",
            command=lambda: on_change(page_number - 1),
        ).pack(side="left")
        ttk.Label(
            self.pager,
            text=f"Page {page_number}",
            style="Muted.TLabel",
        ).pack(side="left", padx=10)
        ttk.Button(
            self.pager,
            text="Next",
            state="normal" if page_data["next"] else "disabled",
            command=lambda: on_change(page_number + 1),
        ).pack(side="left")

    def _open_selected_incident(self):
        selection = self.incident_tree.selection()
        if not selection:
            messagebox.showinfo("Incident", "Select an incident first.", parent=self)
            return
        incident_id = self.incident_tree.item(selection[0], "values")[0]
        IncidentWindow(self, int(incident_id))

    def show_alerts(self):
        self._clear_content()
        self._page_heading("Security alerts", "Alerts generated by recorded application activity.")
        controls = ttk.Frame(self.content)
        controls.pack(fill="x", pady=(0, 12))
        severity_var = tk.StringVar()
        type_var = tk.StringVar()
        self._filter_combo(controls, severity_var, ("",) + SEVERITY_CHOICES, 12)
        self._filter_combo(
            controls,
            type_var,
            (
                "",
                "repeated_failed_logins",
                "suspicious_login",
                "multiple_auth_failures",
                "other",
            ),
            28,
        )
        tree = self._make_tree(
            self.content,
            (
                ("id", "ID", 55),
                ("title", "Title", 250),
                ("type", "Type", 190),
                ("severity", "Severity", 90),
                ("status", "Status", 110),
                ("created", "Created", 170),
            ),
        )
        page_number = [1]
        pager_holder = {"frame": ttk.Frame(self.content)}
        pager_holder["frame"].pack(fill="x", pady=(8, 0))

        def load(page=None):
            if page is not None:
                page_number[0] = page
            filters = {
                "severity": severity_var.get(),
                "alert_type": type_var.get(),
                "page": page_number[0],
            }
            try:
                page = self.api.get_alerts(**{k: v for k, v in filters.items() if v})
            except ApiError as error:
                self._show_error(error)
                return
            self._fill_tree(
                tree,
                (
                    (
                        alert["id"],
                        alert["title"],
                        alert["alert_type"].replace("_", " ").title(),
                        alert["severity"].title(),
                        alert["status"].title(),
                        alert["created_at"],
                    )
                    for alert in page["results"]
                ),
            )
            self._render_pager(
                pager_holder["frame"],
                page_number[0],
                page,
                load,
            )

        ttk.Button(controls, text="Filter", command=lambda: load(1)).pack(
            side="left",
            padx=4,
        )
        if self.current_user["role"] == "Administrator":
            ttk.Button(
                self.content,
                text="Update selected alert",
                command=lambda: self._update_selected_alert(tree, load),
            ).pack(anchor="e", pady=(10, 0))
        load()

    def _update_selected_alert(self, tree, refresh):
        selection = tree.selection()
        if not selection:
            messagebox.showinfo("Alert", "Select an alert first.", parent=self)
            return
        alert_id = tree.item(selection[0], "values")[0]
        self._choose_value(
            "Update alert status",
            "New status",
            ALERT_STATUS_CHOICES,
            lambda value: self._save_alert_status(alert_id, value, refresh),
        )

    def _save_alert_status(self, alert_id, status_value, refresh):
        try:
            self.api.update_alert(alert_id, status_value)
        except ApiError as error:
            self._show_error(error)
            return
        refresh()

    def show_activity(self):
        self._clear_content()
        self._page_heading("Activity log", "Read-only audit history available to your role.")
        tree = self._make_tree(
            self.content,
            (
                ("created", "Created", 170),
                ("action", "Action", 170),
                ("actor", "Actor", 120),
                ("incident", "Incident", 140),
                ("description", "Details", 420),
            ),
        )
        page_number = [1]
        pager_holder = {"frame": ttk.Frame(self.content)}
        pager_holder["frame"].pack(fill="x", pady=(8, 0))

        def load(page=None):
            if page is not None:
                page_number[0] = page
            try:
                data = self.api.get_activity_logs(page=page_number[0])
            except ApiError as error:
                self._show_error(error)
                return
            self._fill_tree(
                tree,
                (
                    (
                        entry["created_at"],
                        entry["action"].replace("_", " ").title(),
                        entry.get("actor_username") or "System",
                        str(entry.get("incident_public_id") or "—"),
                        entry["description"],
                    )
                    for entry in data["results"]
                ),
            )
            self._render_pager(
                pager_holder["frame"],
                page_number[0],
                data,
                load,
            )

        load()

    def show_analysts(self):
        self._clear_content()
        self._page_heading("Analyst directory", "Active analysts available for incident assignment.")
        tree = self._make_tree(
            self.content,
            (("id", "ID", 90), ("username", "Username", 220), ("name", "Display name", 300)),
        )
        page_number = [1]
        pager_holder = {"frame": ttk.Frame(self.content)}
        pager_holder["frame"].pack(fill="x", pady=(8, 0))

        def load(page=None):
            if page is not None:
                page_number[0] = page
            try:
                data = self.api.get_analysts(page=page_number[0])
            except ApiError as error:
                self._show_error(error)
                return
            self._fill_tree(
                tree,
                (
                    (analyst["id"], analyst["username"], analyst["display_name"])
                    for analyst in data["results"]
                ),
            )
            self._render_pager(
                pager_holder["frame"],
                page_number[0],
                data,
                load,
            )

        load()

    def _choose_value(self, title, label, values, on_save):
        dialog = tk.Toplevel(self)
        dialog.title(title)
        dialog.configure(background=COLORS["background"])
        dialog.transient(self)
        dialog.grab_set()
        ttk.Label(dialog, text=label).pack(anchor="w", padx=18, pady=(18, 6))
        variable = tk.StringVar(value=values[0])
        ttk.Combobox(
            dialog,
            textvariable=variable,
            values=values,
            state="readonly",
            width=30,
        ).pack(padx=18, pady=4)

        def save():
            value = variable.get()
            dialog.destroy()
            on_save(value)

        ttk.Button(dialog, text="Save", command=save).pack(
            anchor="e", padx=18, pady=18
        )


class IncidentWindow(tk.Toplevel):
    def __init__(self, app, incident_id):
        super().__init__(app)
        self.app = app
        self.incident_id = incident_id
        self.title(f"Incident {incident_id} | SentinelDesk")
        self.geometry("850x720")
        self.minsize(700, 560)
        self.configure(background=COLORS["background"])
        self._build()
        self._load()

    def _build(self):
        self.container = ttk.Frame(self, padding=18)
        self.container.pack(fill="both", expand=True)
        self.title_label = ttk.Label(self.container, text="Incident details", style="Title.TLabel")
        self.title_label.pack(anchor="w")
        self.summary_label = ttk.Label(self.container, text="", style="Muted.TLabel")
        self.summary_label.pack(anchor="w", pady=(4, 12))

        details = ttk.Frame(self.container, style="Panel.TFrame", padding=14)
        details.pack(fill="x")
        ttk.Label(details, text="Description", style="Panel.TLabel").pack(anchor="w")
        self.description = tk.Text(
            details,
            height=5,
            wrap="word",
            background=COLORS["surface"],
            foreground=COLORS["text"],
            relief="flat",
            insertbackground=COLORS["text"],
        )
        self.description.pack(fill="x", pady=(6, 12))
        ttk.Label(details, text="Resolution summary", style="Panel.TLabel").pack(
            anchor="w"
        )
        self.resolution = tk.Text(
            details,
            height=3,
            wrap="word",
            background=COLORS["surface"],
            foreground=COLORS["text"],
            relief="flat",
            insertbackground=COLORS["text"],
        )
        self.resolution.pack(fill="x", pady=(6, 8))

        form = ttk.Frame(self.container)
        form.pack(fill="x", pady=10)
        ttk.Label(form, text="Status").grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.status = tk.StringVar()
        self.status_combo = ttk.Combobox(
            form,
            textvariable=self.status,
            values=STATUS_CHOICES,
            state="readonly",
            width=25,
        )
        self.status_combo.grid(row=0, column=1, sticky="w")
        self.severity_label = ttk.Label(form, text="Severity")
        self.severity_label.grid(row=0, column=2, sticky="w", padx=(20, 8))
        self.severity = tk.StringVar()
        self.severity_combo = ttk.Combobox(
            form,
            textvariable=self.severity,
            values=SEVERITY_CHOICES,
            state="readonly",
            width=15,
        )
        self.severity_combo.grid(row=0, column=3, sticky="w")
        ttk.Button(
            form,
            text="Save changes",
            style="Accent.TButton",
            command=self._save_changes,
        ).grid(row=0, column=4, padx=(12, 0))

        self.assignment_frame = ttk.Frame(self.container)
        self.assignment_frame.pack(fill="x", pady=(4, 10))
        ttk.Label(self.assignment_frame, text="Assigned analyst").pack(side="left")
        self.assignment = tk.StringVar()
        self.analyst_combo = ttk.Combobox(
            self.assignment_frame,
            textvariable=self.assignment,
            state="readonly",
            width=28,
        )
        self.analyst_combo.pack(side="left", padx=8)
        self.assignment_button = ttk.Button(
            self.assignment_frame,
            text="Assign",
            command=self._assign,
        )
        self.assignment_button.pack(side="left")

        ttk.Label(self.container, text="Investigation notes", style="Title.TLabel").pack(
            anchor="w", pady=(6, 6)
        )
        self.notes_text = tk.Text(
            self.container,
            height=8,
            wrap="word",
            state="disabled",
            background=COLORS["surface"],
            foreground=COLORS["text"],
            relief="flat",
        )
        self.notes_text.pack(fill="both", expand=True)
        self.note_entry = tk.Text(
            self.container,
            height=3,
            wrap="word",
            background=COLORS["surfaceRaised"],
            foreground=COLORS["text"],
            insertbackground=COLORS["text"],
            relief="flat",
        )
        self.note_entry.pack(fill="x", pady=(8, 4))
        self.add_note_button = ttk.Button(
            self.container,
            text="Add investigation note",
            command=self._add_note,
        )
        self.add_note_button.pack(anchor="e")

    def _load(self):
        try:
            incident = self.app.api.get_incident(self.incident_id)
        except ApiError as error:
            self.app._show_error(error)
            self.destroy()
            return
        self.incident = incident
        self.title_label.configure(text=incident["title"])
        self.summary_label.configure(
            text=(
                f"{incident['category'].replace('_', ' ').title()} · "
                f"{incident['severity'].title()} · "
                f"{incident['status'].replace('_', ' ').title()} · "
                f"Reporter: {incident['reporter_username']}"
            )
        )
        self._set_text(self.description, incident["description"])
        self.description.configure(state="disabled")
        self._set_text(self.resolution, incident.get("resolution_summary", ""))
        self.status.set(incident["status"])
        status_options = {
            "open": ("open", "under_investigation"),
            "under_investigation": (
                "under_investigation",
                "pending",
                "resolved",
            ),
            "pending": ("pending", "under_investigation", "resolved"),
            "resolved": ("resolved", "closed"),
            "closed": ("closed",),
        }
        self.status_combo.configure(values=status_options[incident["status"]])
        self.severity.set(incident["severity"])
        is_admin = self.app.current_user["role"] == "Administrator"
        if not is_admin:
            self.severity_combo.configure(state="disabled")
            self.assignment_frame.pack_forget()
        else:
            self._load_assignment()
        self._load_notes()

    @staticmethod
    def _set_text(widget, value):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)

    def _save_changes(self):
        changes = {"status": self.status.get()}
        resolution = self.resolution.get("1.0", "end").strip()
        if resolution != self.incident.get("resolution_summary", ""):
            changes["resolution_summary"] = resolution
        if self.app.current_user["role"] == "Administrator":
            if self.severity.get() != self.incident["severity"]:
                changes["severity"] = self.severity.get()
        try:
            self.app.api.update_incident(self.incident_id, changes)
        except ApiError as error:
            self.app._show_error(error)
            return
        messagebox.showinfo("Incident", "Incident updated.", parent=self)
        self._load()

    def _load_assignment(self):
        try:
            assignment = self.app.api.get_assignment(self.incident_id)
            analyst_page = self.app.api.get_analysts(page_size=100)
        except ApiError as error:
            self.app._show_error(error)
            self.assignment_button.configure(state="disabled")
            return
        self.analysts = analyst_page["results"]
        self.analyst_options = ["Unassigned"] + [
            f"{analyst['username']} (ID {analyst['id']})"
            for analyst in self.analysts
        ]
        self.analyst_combo.configure(values=self.analyst_options)
        active = assignment.get("analyst")
        self.assignment.set(
            f"{active['username']} (ID {active['id']})"
            if active
            else "Unassigned"
        )

    def _assign(self):
        selected = self.assignment.get()
        analyst_id = None
        if selected != "Unassigned":
            analyst = next(
                (
                    item
                    for item in self.analysts
                    if f"{item['username']} (ID {item['id']})" == selected
                ),
                None,
            )
            if analyst is None:
                messagebox.showerror("Assignment", "Select a valid analyst.", parent=self)
                return
            analyst_id = analyst["id"]
        try:
            self.app.api.assign_incident(self.incident_id, analyst_id)
        except ApiError as error:
            self.app._show_error(error)
            return
        self._load()

    def _load_notes(self):
        self.notes_text.configure(state="normal")
        self.notes_text.delete("1.0", "end")
        try:
            page = self.app.api.get_notes(self.incident_id)
        except ApiError as error:
            self.notes_text.insert("end", f"Notes are unavailable: {error}")
            self.add_note_button.configure(state="disabled")
        else:
            for note in page["results"]:
                self.notes_text.insert(
                    "end",
                    f"{note['created_at']} · {note['analyst_username']}\n"
                    f"{note['content']}\n\n",
                )
            if self.app.current_user["role"] == "Administrator" or (
                self.incident.get("assigned_analyst")
                == self.app.current_user["id"]
            ):
                self.add_note_button.configure(state="normal")
            else:
                self.add_note_button.configure(state="disabled")
        self.notes_text.configure(state="disabled")

    def _add_note(self):
        content = self.note_entry.get("1.0", "end").strip()
        if not content:
            messagebox.showwarning("Investigation note", "Enter a note first.", parent=self)
            return
        try:
            self.app.api.add_note(self.incident_id, content)
        except ApiError as error:
            self.app._show_error(error)
            return
        self.note_entry.delete("1.0", "end")
        self._load_notes()
