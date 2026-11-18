import base64
import json
import logging
import os
import queue
import struct
import threading
from pathlib import Path
import tkinter as tk
from tkinter import font as tkfont
from tkinter import filedialog, messagebox, ttk
import zlib

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


def _rounded_button_image(master, color):
    size = 24
    radius = 8
    supersampling = 3
    rgb = tuple(int(color[index : index + 2], 16) for index in (1, 3, 5))
    pixels = bytearray()
    for y in range(size):
        pixels.append(0)
        for x in range(size):
            covered = 0
            for sample_y in range(supersampling):
                py = y + (sample_y + 0.5) / supersampling
                nearest_y = min(max(py, radius), size - radius)
                for sample_x in range(supersampling):
                    px = x + (sample_x + 0.5) / supersampling
                    nearest_x = min(max(px, radius), size - radius)
                    if (px - nearest_x) ** 2 + (py - nearest_y) ** 2 <= radius**2:
                        covered += 1
            alpha = round(255 * covered / supersampling**2)
            pixels.extend((*rgb, alpha))

    def png_chunk(kind, data):
        chunk = kind + data
        return (
            struct.pack(">I", len(data))
            + chunk
            + struct.pack(">I", zlib.crc32(chunk) & 0xFFFFFFFF)
        )

    png = (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
        + png_chunk(b"IDAT", zlib.compress(pixels))
        + png_chunk(b"IEND", b"")
    )
    return tk.PhotoImage(
        master=master,
        data=base64.b64encode(png).decode("ascii"),
        format="png",
    )


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
        self._api_jobs = queue.Queue()
        self._api_results = queue.Queue()
        self._api_tasks = {}
        self._latest_api_task = {}
        self._api_task_id = 0
        self._api_poll_scheduled = False
        threading.Thread(target=self._api_worker, daemon=True).start()
        self._configure_styles()
        self.show_login()

    def _configure_styles(self):
        for font_name in ("TkDefaultFont", "TkTextFont", "TkMenuFont"):
            tkfont.nametofont(font_name).configure(family="Segoe UI", size=10)

        style = ttk.Style(self)
        style.theme_use("clam")
        self._button_images = {
            color: _rounded_button_image(self, color)
            for color in {
                COLORS["surfaceRaised"],
                COLORS["surface"],
                COLORS["primary"],
                COLORS["secondary"],
            }
        }

        def configure_rounded_button(style_name, element_name, normal, pressed):
            style.element_create(
                element_name,
                "image",
                self._button_images[normal],
                ("disabled", self._button_images[COLORS["surface"]]),
                ("pressed", self._button_images[pressed]),
                ("active", self._button_images[COLORS["secondary"]]),
                border=8,
                padding=(12, 8),
                sticky="nsew",
            )
            style.layout(
                style_name,
                [
                    (
                        element_name,
                        {
                            "sticky": "nswe",
                            "children": [("Button.label", {"sticky": "nswe"})],
                        },
                    )
                ],
            )

        configure_rounded_button(
            "TButton",
            "RoundedButton.border",
            COLORS["surfaceRaised"],
            COLORS["primary"],
        )
        configure_rounded_button(
            "Accent.TButton",
            "RoundedAccentButton.border",
            COLORS["primary"],
            COLORS["primary"],
        )
        style.configure(
            ".",
            background=COLORS["background"],
            foreground=COLORS["text"],
            fieldbackground=COLORS["surfaceRaised"],
            bordercolor=COLORS["background"],
            lightcolor=COLORS["background"],
            darkcolor=COLORS["background"],
            font=("Segoe UI", 10),
        )
        style.configure("TFrame", background=COLORS["background"])
        style.configure("Panel.TFrame", background=COLORS["surface"])
        style.configure("Sidebar.TFrame", background=COLORS["sidebar"])
        style.configure("Login.TFrame", background=COLORS["surface"])
        style.configure("TLabel", background=COLORS["background"], foreground=COLORS["text"])
        style.configure("Panel.TLabel", background=COLORS["surface"], foreground=COLORS["text"])
        style.configure(
            "PanelMuted.TLabel",
            background=COLORS["surface"],
            foreground=COLORS["textMuted"],
        )
        style.configure("Login.TLabel", background=COLORS["surface"], foreground=COLORS["text"])
        style.configure(
            "LoginMuted.TLabel",
            background=COLORS["surface"],
            foreground=COLORS["textMuted"],
        )
        style.configure(
            "LoginTitle.TLabel",
            background=COLORS["surface"],
            foreground=COLORS["text"],
            font=("Segoe UI Semibold", 21),
        )
        style.configure(
            "ProfileAvatar.TLabel",
            background=COLORS["primary"],
            foreground=COLORS["text"],
            font=("Segoe UI Semibold", 18),
            padding=(16, 12),
        )
        style.configure(
            "ProfileName.TLabel",
            background=COLORS["surface"],
            foreground=COLORS["text"],
            font=("Segoe UI Semibold", 17),
        )
        style.configure(
            "ProfileRole.TLabel",
            background=COLORS["primary"],
            foreground=COLORS["text"],
            font=("Segoe UI Semibold", 9),
            padding=(12, 6),
        )
        style.configure("ProfileField.TFrame", background=COLORS["surfaceRaised"])
        style.configure(
            "ProfileFieldLabel.TLabel",
            background=COLORS["surfaceRaised"],
            foreground=COLORS["textMuted"],
            font=("Segoe UI", 9),
        )
        style.configure(
            "ProfileFieldValue.TLabel",
            background=COLORS["surfaceRaised"],
            foreground=COLORS["text"],
            font=("Segoe UI Semibold", 11),
        )
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
            font=("Segoe UI", 10),
            borderwidth=0,
            relief="flat",
            bordercolor=COLORS["surfaceRaised"],
            lightcolor=COLORS["surfaceRaised"],
            darkcolor=COLORS["surfaceRaised"],
        )
        style.map(
            "TButton",
            foreground=[
                ("disabled", COLORS["textMuted"]),
                ("active", COLORS["text"]),
            ],
        )
        style.configure(
            "Accent.TButton",
            background=COLORS["primary"],
            foreground=COLORS["text"],
            font=("Segoe UI Semibold", 10),
            borderwidth=0,
            relief="flat",
            bordercolor=COLORS["primary"],
            lightcolor=COLORS["primary"],
            darkcolor=COLORS["primary"],
        )
        style.configure(
            "TEntry",
            fieldbackground=COLORS["surfaceRaised"],
            foreground=COLORS["text"],
            insertcolor=COLORS["text"],
            bordercolor=COLORS["surfaceRaised"],
            lightcolor=COLORS["surfaceRaised"],
            borderwidth=0,
            relief="flat",
            padding=8,
        )
        style.map(
            "TEntry",
            fieldbackground=[("disabled", COLORS["surface"])],
            foreground=[("disabled", COLORS["textMuted"])],
            bordercolor=[("focus", COLORS["surfaceRaised"])],
            lightcolor=[("focus", COLORS["surfaceRaised"])],
        )
        style.configure(
            "TCombobox",
            background=COLORS["surfaceRaised"],
            fieldbackground=COLORS["surfaceRaised"],
            foreground=COLORS["text"],
            bordercolor=COLORS["surfaceRaised"],
            lightcolor=COLORS["surfaceRaised"],
            darkcolor=COLORS["surfaceRaised"],
            arrowcolor=COLORS["textMuted"],
            borderwidth=0,
            relief="flat",
            padding=6,
        )
        style.map(
            "TCombobox",
            fieldbackground=[
                ("readonly", COLORS["surfaceRaised"]),
                ("disabled", COLORS["surface"]),
            ],
            foreground=[
                ("readonly", COLORS["text"]),
                ("disabled", COLORS["textMuted"]),
            ],
            selectbackground=[("readonly", COLORS["primary"])],
            selectforeground=[("readonly", COLORS["text"])],
            bordercolor=[("focus", COLORS["surfaceRaised"])],
            lightcolor=[("focus", COLORS["surfaceRaised"])],
        )
        style.configure(
            "TCheckbutton",
            background=COLORS["background"],
            foreground=COLORS["textMuted"],
            indicatorbackground=COLORS["surfaceRaised"],
            indicatorforeground=COLORS["text"],
            upperbordercolor=COLORS["surfaceRaised"],
            lowerbordercolor=COLORS["surfaceRaised"],
        )
        style.configure(
            "Login.TCheckbutton",
            background=COLORS["surface"],
            foreground=COLORS["textMuted"],
            indicatorbackground=COLORS["surfaceRaised"],
            indicatorforeground=COLORS["text"],
            upperbordercolor=COLORS["surfaceRaised"],
            lowerbordercolor=COLORS["surfaceRaised"],
        )
        style.map(
            "TCheckbutton",
            indicatorbackground=[("selected", COLORS["primary"])],
            upperbordercolor=[("selected", COLORS["primary"])],
            lowerbordercolor=[("selected", COLORS["primary"])],
        )
        style.map(
            "Login.TCheckbutton",
            indicatorbackground=[("selected", COLORS["primary"])],
            upperbordercolor=[("selected", COLORS["primary"])],
            lowerbordercolor=[("selected", COLORS["primary"])],
        )
        for scrollbar_style in ("Vertical.TScrollbar", "Horizontal.TScrollbar"):
            style.configure(
                scrollbar_style,
                background=COLORS["surfaceRaised"],
                troughcolor=COLORS["background"],
                bordercolor=COLORS["background"],
                lightcolor=COLORS["background"],
                darkcolor=COLORS["background"],
                arrowcolor=COLORS["textMuted"],
                borderwidth=0,
                relief="flat",
            )
            style.map(
                scrollbar_style,
                background=[("active", COLORS["primary"])],
                arrowcolor=[("active", COLORS["text"])],
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
            bordercolor=COLORS["surface"],
            lightcolor=COLORS["surface"],
            borderwidth=0,
            relief="flat",
            font=("Segoe UI", 10),
        )
        style.configure(
            "Treeview.Heading",
            background=COLORS["surfaceRaised"],
            foreground=COLORS["text"],
            borderwidth=0,
            bordercolor=COLORS["surfaceRaised"],
            lightcolor=COLORS["surfaceRaised"],
            darkcolor=COLORS["surfaceRaised"],
            relief="flat",
            font=("Segoe UI Semibold", 9),
        )
        style.configure(
            "Dashboard.Treeview",
            background=COLORS["surface"],
            fieldbackground=COLORS["surface"],
            foreground=COLORS["text"],
            rowheight=29,
            borderwidth=0,
            bordercolor=COLORS["surface"],
            lightcolor=COLORS["surface"],
            relief="flat",
            font=("Segoe UI", 10),
        )
        style.configure(
            "Dashboard.Treeview.Heading",
            background=COLORS["surfaceRaised"],
            foreground=COLORS["text"],
            borderwidth=0,
            bordercolor=COLORS["surfaceRaised"],
            lightcolor=COLORS["surfaceRaised"],
            darkcolor=COLORS["surfaceRaised"],
            relief="flat",
            font=("Segoe UI Semibold", 9),
        )
        style.configure(
            "TNotebook",
            background=COLORS["background"],
            bordercolor=COLORS["background"],
            lightcolor=COLORS["background"],
            darkcolor=COLORS["background"],
            borderwidth=0,
            relief="flat",
        )
        style.configure(
            "TNotebook.Tab",
            background=COLORS["surfaceRaised"],
            foreground=COLORS["text"],
            bordercolor=COLORS["surfaceRaised"],
            lightcolor=COLORS["surfaceRaised"],
            darkcolor=COLORS["surfaceRaised"],
            borderwidth=0,
            relief="flat",
            padding=(12, 7),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", COLORS["primary"])],
            foreground=[("selected", COLORS["text"])],
        )
        style.map(
            "Treeview",
            background=[("selected", COLORS["primary"])],
            foreground=[("selected", "white")],
        )

    def _clear(self):
        for child in self.winfo_children():
            child.destroy()

    def _api_worker(self):
        while True:
            task_id, api, operation = self._api_jobs.get()
            try:
                result = operation(api)
            except Exception as error:
                self._api_results.put((task_id, None, error))
            else:
                self._api_results.put((task_id, result, None))

    def _run_api_async(
        self,
        operation,
        on_success,
        *,
        owner=None,
        request_key=None,
        on_error=None,
    ):
        api = self.api
        if api is None:
            self._show_error(ApiError("Sign in to connect to SentinelDesk."))
            return
        self._api_task_id += 1
        task_id = self._api_task_id
        key = request_key if request_key is not None else owner
        self._latest_api_task[key] = task_id
        self._api_tasks[task_id] = (key, owner, on_success, on_error)
        self._api_jobs.put((task_id, api, operation))
        if not self._api_poll_scheduled:
            self._api_poll_scheduled = True
            self.after(50, self._poll_api_results)

    def _invalidate_api_owner(self, owner):
        for task_id, task in tuple(self._api_tasks.items()):
            if task[1] is owner:
                self._api_tasks.pop(task_id, None)

    def _poll_api_results(self):
        self._api_poll_scheduled = False
        while True:
            try:
                task_id, result, error = self._api_results.get_nowait()
            except queue.Empty:
                break
            task = self._api_tasks.pop(task_id, None)
            if task is None:
                continue
            key, owner, on_success, on_error = task
            if self._latest_api_task.get(key) != task_id:
                continue
            if owner is not None:
                try:
                    if not owner.winfo_exists():
                        continue
                except tk.TclError:
                    continue
            if error is not None:
                if on_error is not None:
                    on_error(error)
                    continue
                if isinstance(error, (ApiError, OSError)):
                    self._show_error(error)
                else:
                    logger.exception(
                        "Unexpected error in a desktop API operation.",
                        exc_info=(type(error), error, error.__traceback__),
                    )
                    self._show_error(
                        ApiError(
                            "The operation could not be completed. "
                            "Check the desktop application output for details."
                        )
                    )
                continue
            on_success(result)
        if self._api_tasks and not self._api_poll_scheduled:
            self._api_poll_scheduled = True
            self.after(50, self._poll_api_results)

    def _show_error(self, error):
        if isinstance(error, ApiError):
            if error.status_code == 401 and self.current_user is not None:
                self.api = None
                self.current_user = None
                self.show_login()
                messagebox.showwarning(
                    "Session expired",
                    "Your SentinelDesk session is no longer valid. Sign in again.",
                    parent=self,
                )
                return
            messagebox.showerror("SentinelDesk API", str(error), parent=self)
        else:
            messagebox.showerror(
                "SentinelDesk",
                f"Something went wrong: {error}",
                parent=self,
            )

    def show_login(self):
        self._clear()
        container = ttk.Frame(self, style="Login.TFrame", padding=32)
        container.place(relx=0.5, rely=0.5, anchor="center")
        ttk.Label(container, text="SentinelDesk", style="LoginTitle.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 4)
        )
        ttk.Label(
            container,
            text="Security operations console",
            style="LoginMuted.TLabel",
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 22))
        container.columnconfigure(1, weight=1)

        self.api_url = tk.StringVar(
            value=os.environ.get(
                "SENTINELDESK_API_URL",
                "http://127.0.0.1:8000/api",
            )
        )
        ttk.Label(container, text="Username", style="Login.TLabel").grid(
            row=2, column=0, sticky="w", pady=6
        )
        self.username = tk.StringVar()
        username_entry = ttk.Entry(container, textvariable=self.username, width=42)
        username_entry.grid(row=2, column=1, sticky="ew", pady=6)
        ttk.Label(container, text="Password", style="Login.TLabel").grid(
            row=3, column=0, sticky="w", pady=6
        )
        self.password = tk.StringVar()
        password_entry = ttk.Entry(
            container,
            textvariable=self.password,
            show="*",
            width=42,
        )
        password_entry.grid(row=3, column=1, sticky="ew", pady=6)
        self.show_password = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            container,
            text="Show password",
            variable=self.show_password,
            style="Login.TCheckbutton",
            command=lambda: password_entry.configure(
                show="" if self.show_password.get() else "*"
            ),
        ).grid(row=4, column=1, sticky="w")
        self.login_button = ttk.Button(
            container,
            text="Sign in",
            style="Accent.TButton",
            command=self._login,
        )
        self.login_button.grid(row=5, column=1, sticky="e", pady=(18, 0))
        self.login_progress = ttk.Progressbar(
            container,
            mode="indeterminate",
            length=240,
        )
        self.login_progress.grid(row=6, column=1, sticky="e", pady=(8, 0))
        self.login_progress.grid_remove()
        password_entry.bind("<Return>", lambda _event: self._login())
        username_entry.focus_set()

    def _login(self):
        if self._login_in_progress:
            return
        base_url = self.api_url.get().strip()
        username = self.username.get().strip()
        password = self.password.get()
        if not base_url:
            messagebox.showwarning(
                "Sign in",
                "The API server is not configured. Set SENTINELDESK_API_URL.",
                parent=self,
            )
            return
        if not username or not password:
            messagebox.showwarning(
                "Sign in",
                "Enter your username and password.",
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
            self._nav_button(navigation, "Detection rules", self.show_detection_rules)
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
        if self.api is None:
            self.current_user = None
            self.show_login()
            return

        def signed_out(_result):
            self.show_login()

        def sign_out_failed(error):
            self.show_login()
            messagebox.showwarning("Sign out", str(error), parent=self)

        self._run_api_async(
            lambda api: api.logout(),
            signed_out,
            owner=self,
            request_key="logout",
            on_error=sign_out_failed,
        )
        self.api = None
        self.current_user = None
        self._clear()
        ttk.Label(
            self,
            text="Signing out…",
            style="Muted.TLabel",
        ).place(relx=0.5, rely=0.5, anchor="center")

    def _clear_content(self):
        self._invalidate_api_owner(self.content)
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
        self._page_heading(
            "Security analytics",
            "Current database-backed metrics and historical trends from Django.",
        )
        controls = ttk.Frame(self.content)
        controls.pack(fill="x", pady=(0, 10))
        ttk.Label(controls, text="Period").pack(side="left", padx=(0, 5))
        period = tk.StringVar(value="Last 30 days")
        period_combo = ttk.Combobox(
            controls,
            textvariable=period,
            values=("Last 7 days", "Last 30 days", "Last 90 days", "Custom range"),
            state="readonly",
            width=17,
        )
        period_combo.pack(side="left", padx=(0, 12))
        ttk.Label(controls, text="Trend interval").pack(side="left", padx=(0, 5))
        granularity = tk.StringVar(value="Daily")
        ttk.Combobox(
            controls,
            textvariable=granularity,
            values=("Daily", "Weekly", "Monthly"),
            state="readonly",
            width=11,
        ).pack(side="left", padx=(0, 12))
        ttk.Label(controls, text="Start").pack(side="left", padx=(0, 5))
        start_date = tk.StringVar()
        start_entry = ttk.Entry(controls, textvariable=start_date, width=12)
        start_entry.pack(side="left", padx=(0, 8))
        ttk.Label(controls, text="End").pack(side="left", padx=(0, 5))
        end_date = tk.StringVar()
        end_entry = ttk.Entry(controls, textvariable=end_date, width=12)
        end_entry.pack(side="left", padx=(0, 8))
        results = ttk.Frame(self.content)
        results.pack(fill="both", expand=True)

        def update_custom_fields(_event=None):
            state = "normal" if period.get() == "Custom range" else "disabled"
            start_entry.configure(state=state)
            end_entry.configure(state=state)

        def load_analytics():
            granularity_value = granularity.get().lower()
            if period.get() == "Custom range":
                if not start_date.get().strip() or not end_date.get().strip():
                    messagebox.showwarning(
                        "Analytics date range",
                        "Enter both custom dates in YYYY-MM-DD format.",
                        parent=self,
                    )
                    return
                filters = {
                    "start_date": start_date.get().strip(),
                    "end_date": end_date.get().strip(),
                    "granularity": granularity_value,
                }
            else:
                days = {
                    "Last 7 days": "7",
                    "Last 30 days": "30",
                    "Last 90 days": "90",
                }[period.get()]
                filters = {"days": days, "granularity": granularity_value}
            for child in results.winfo_children():
                child.destroy()
            ttk.Label(
                results,
                text="Loading analytics from Django…",
                style="Muted.TLabel",
            ).pack(anchor="w", pady=12)
            self._run_api_async(
                lambda api: api.get_analytics(**filters),
                lambda analytics: self._render_dashboard_analytics(
                    results,
                    analytics,
                ),
                owner=results,
                request_key="dashboard-analytics",
            )

        period_combo.bind("<<ComboboxSelected>>", update_custom_fields)
        update_custom_fields()
        ttk.Button(
            controls,
            text="Refresh",
            style="Accent.TButton",
            command=load_analytics,
        ).pack(side="left", padx=(4, 0))
        load_analytics()

    def _render_dashboard_analytics(self, parent, analytics):
        incidents = analytics["incident_statistics"]
        alerts = analytics["alert_statistics"]
        cards = (
            ("Total incidents", incidents["total_incidents"]),
            ("Active incidents", incidents["active_incidents"]),
            ("Open", incidents["open_incidents"]),
            ("Under investigation", incidents["under_investigation_incidents"]),
            ("Pending", incidents["pending_incidents"]),
            ("Resolved", incidents["resolved_incidents"]),
            ("Closed", incidents["closed_incidents"]),
            ("Critical incidents", incidents["critical_incidents"]),
            ("High-severity incidents", incidents["high_severity_incidents"]),
            ("Total alerts", alerts["total_alerts"]),
            ("Generated alerts", alerts["generated_alerts"]),
            ("Critical alerts", alerts["by_severity"].get("critical", 0)),
        )
        grid = ttk.Frame(parent)
        grid.pack(fill="x", pady=(0, 8))
        for index, (title, value) in enumerate(cards):
            row, column = divmod(index, 4)
            card = ttk.Frame(grid, style="Panel.TFrame", padding=(10, 8))
            card.grid(row=row, column=column, sticky="nsew", padx=3, pady=3)
            ttk.Label(card, text=title, style="PanelMuted.TLabel").pack(anchor="w")
            ttk.Label(
                card,
                text=str(value),
                style="Panel.TLabel",
                font=("Segoe UI Semibold", 17),
            ).pack(anchor="w", pady=(4, 0))
        for column in range(4):
            grid.columnconfigure(column, weight=1)

        notebook = ttk.Notebook(parent)
        notebook.pack(fill="both", expand=True)
        trends_tab = ttk.Frame(notebook, padding=8)
        distributions_tab = ttk.Frame(notebook, padding=8)
        operations_tab = ttk.Frame(notebook, padding=8)
        notebook.add(trends_tab, text="Trends")
        notebook.add(distributions_tab, text="Distributions")
        notebook.add(operations_tab, text="Operations")

        incident_trends = analytics["incident_trends"]
        alert_trends = analytics["alert_trends"]
        self._add_line_chart(
            trends_tab,
            "Incident volume",
            incident_trends["counts"],
            (("Incidents", COLORS["primary"]),),
            0,
            0,
        )
        self._add_line_chart(
            trends_tab,
            "Security alerts",
            alert_trends["counts"],
            (("Alerts", COLORS["high"]),),
            0,
            1,
        )
        new_series = incident_trends["new_vs_resolved"]["new"]
        resolved_series = incident_trends["new_vs_resolved"]["resolved"]
        comparison = new_series if new_series else resolved_series
        comparison_points = [
            row["period"] for row in comparison
        ]
        self._add_line_chart(
            trends_tab,
            "New versus resolved incidents",
            comparison_points,
            [
                {
                    "values": [row["count"] for row in rows]
                    if rows
                    else [0] * len(comparison_points),
                    "label": label,
                    "color": color,
                }
                for rows, label, color in (
                    (new_series, "New", COLORS["secondary"]),
                    (resolved_series, "Resolved", COLORS["low"]),
                )
            ],
            1,
            0,
            preformatted=True,
        )
        timeline = [row["period"] for row in incident_trends["counts"]]
        self._add_line_chart(
            trends_tab,
            "Incident severity trends",
            timeline,
            [
                {
                    "label": item["label"],
                    "values": item["values"],
                    "color": color,
                }
                for item, color in zip(
                    incident_trends["by_severity"],
                    (
                        COLORS["critical"],
                        COLORS["high"],
                        COLORS["medium"],
                        COLORS["low"],
                    ),
                )
            ],
            1,
            1,
            preformatted=True,
        )
        category_colors = (
            COLORS["secondary"],
            COLORS["primary"],
            COLORS["critical"],
            COLORS["high"],
            COLORS["medium"],
            COLORS["low"],
        )
        self._add_line_chart(
            trends_tab,
            "Incident category trends",
            timeline,
            [
                {
                    "label": item["label"],
                    "values": item["values"],
                    "color": category_colors[index % len(category_colors)],
                }
                for index, item in enumerate(incident_trends["by_category"])
            ],
            2,
            0,
            preformatted=True,
        )
        for column in range(2):
            trends_tab.columnconfigure(column, weight=1)
        for row in range(3):
            trends_tab.rowconfigure(row, weight=1)

        period_incidents = incidents["period"]
        period_alerts = alerts["period"]
        self._add_bar_chart(
            distributions_tab,
            "Incidents by severity",
            period_incidents["by_severity"],
            COLORS["critical"],
            0,
            0,
        )
        self._add_bar_chart(
            distributions_tab,
            "Incidents by category",
            period_incidents["by_category"],
            COLORS["secondary"],
            0,
            1,
        )
        self._add_bar_chart(
            distributions_tab,
            "Incidents by status",
            period_incidents["by_status"],
            COLORS["primary"],
            1,
            0,
        )
        self._add_bar_chart(
            distributions_tab,
            "Alerts by severity",
            period_alerts["by_severity"],
            COLORS["high"],
            1,
            1,
        )
        self._add_bar_chart(
            distributions_tab,
            "Alerts by type",
            period_alerts["by_type"],
            COLORS["secondary"],
            2,
            0,
        )
        self._add_bar_chart(
            distributions_tab,
            "Alerts by status",
            period_alerts["by_status"],
            COLORS["medium"],
            2,
            1,
        )
        for column in range(2):
            distributions_tab.columnconfigure(column, weight=1)
        for row in range(3):
            distributions_tab.rowconfigure(row, weight=1)

        response_frame = ttk.Frame(operations_tab, style="Panel.TFrame", padding=12)
        response_frame.pack(fill="x", pady=(0, 10))
        response = analytics["response_performance"]
        response_metrics = (
            ("Avg. time to assignment", response["average_time_to_assignment"]),
            (
                "Avg. time to first note",
                response["average_time_to_first_investigation_activity"],
            ),
            ("Avg. time to resolution", response["average_time_to_resolution"]),
        )
        for index, (label, metric) in enumerate(response_metrics):
            column = index % 3
            cell = ttk.Frame(response_frame, style="Panel.TFrame")
            cell.grid(row=0, column=column, sticky="nsew", padx=5)
            ttk.Label(cell, text=label, style="PanelMuted.TLabel").pack(anchor="w")
            ttk.Label(
                cell,
                text=self._format_analytics_duration(metric["average_seconds"]),
                style="Panel.TLabel",
                font=("Segoe UI Semibold", 13),
            ).pack(anchor="w", pady=(4, 0))
            ttk.Label(
                cell,
                text=f"{metric['sample_size']} measured incidents",
                style="PanelMuted.TLabel",
            ).pack(anchor="w")
        for column in range(3):
            response_frame.columnconfigure(column, weight=1)
        ttk.Label(
            response_frame,
            text=(
                f"Unresolved: {response['unresolved_incidents']} · "
                f"Overdue: unavailable — {response['overdue_unavailable_reason']}"
            ),
            style="PanelMuted.TLabel",
            wraplength=800,
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 0))

        ttk.Label(
            operations_tab,
            text="Analyst workload (current assignments)",
            style="Panel.TLabel",
            font=("Segoe UI Semibold", 12),
        ).pack(anchor="w", pady=(4, 6))
        workload_tree = self._make_tree(
            operations_tab,
            (
                ("analyst", "Analyst", 150),
                ("assigned", "Assigned", 80),
                ("open", "Open", 65),
                ("investigating", "Investigating", 110),
                ("pending", "Pending", 75),
                ("resolved", "Resolved", 75),
                ("active", "Active", 70),
                ("share", "Active share", 95),
            ),
            style_name="Dashboard.Treeview",
        )
        workload_rows = [
            (
                row["username"],
                row["assigned_incidents"],
                row["open_incidents"],
                row["under_investigation_incidents"],
                row["pending_incidents"],
                row["resolved_incidents"],
                row["active_incidents"],
                f"{row['active_workload_percent']}%",
            )
            for row in analytics["analyst_workload"]["analysts"]
        ]
        if analytics["analyst_workload"]["unassigned_incidents"] is not None:
            workload_rows.append(
                (
                    "Unassigned",
                    analytics["analyst_workload"]["unassigned_incidents"],
                    "—",
                    "—",
                    "—",
                    "—",
                    analytics["analyst_workload"]["unassigned_active_incidents"],
                    "—",
                )
            )
        for row in workload_rows:
            workload_tree.insert("", "end", values=row)
        if not workload_rows:
            ttk.Label(
                operations_tab,
                text="No analyst workload is available for this account.",
                style="Muted.TLabel",
            ).pack(anchor="w", pady=6)

        rules = analytics["most_triggered_rules"]
        rule_summary = " · ".join(
            f"{rule['name']}: {rule['alert_count']}" for rule in rules
        )
        ttk.Label(
            operations_tab,
            text=f"Most-triggered rules in range: {rule_summary or 'No rule-generated alerts'}",
            style="Muted.TLabel",
            wraplength=800,
        ).pack(anchor="w", pady=(8, 6))

        ttk.Label(
            operations_tab,
            text="Recent critical and high alerts",
            style="Panel.TLabel",
            font=("Segoe UI Semibold", 12),
        ).pack(anchor="w", pady=(4, 6))
        alert_tree = self._make_tree(
            operations_tab,
            (
                ("id", "ID", 45),
                ("title", "Alert", 200),
                ("type", "Type", 150),
                ("severity", "Severity", 80),
                ("status", "Status", 85),
                ("origin", "Origin", 75),
                ("rule", "Rule", 160),
                ("created", "Created", 170),
            ),
            style_name="Dashboard.Treeview",
        )
        self._fill_tree(
            alert_tree,
            (
                (
                    alert["id"],
                    alert["title"],
                    alert["alert_type"].replace("_", " ").title(),
                    alert["severity"].title(),
                    alert["status"].title(),
                    "Automatic" if alert["auto_generated"] else "Manual",
                    alert["detection_rule_identifier"] or "—",
                    alert["created_at"],
                )
                for alert in analytics["recent_priority_alerts"]
            ),
        )

        ttk.Label(
            operations_tab,
            text="Recent incidents",
            style="Panel.TLabel",
            font=("Segoe UI Semibold", 12),
        ).pack(anchor="w", pady=(10, 6))
        incident_tree = self._make_tree(
            operations_tab,
            (
                ("id", "ID", 45),
                ("title", "Incident", 200),
                ("category", "Category", 130),
                ("severity", "Severity", 80),
                ("status", "Status", 130),
                ("reporter", "Reporter", 130),
                ("created", "Created", 170),
            ),
            style_name="Dashboard.Treeview",
        )
        self._fill_tree(
            incident_tree,
            (
                (
                    incident["id"],
                    incident["title"],
                    incident["category_display"],
                    incident["severity_display"],
                    incident["status_display"],
                    incident["reporter_username"],
                    incident["created_at"],
                )
                for incident in analytics["recent_incidents"]
            ),
        )

    def _add_line_chart(
        self,
        parent,
        title,
        points,
        series,
        row,
        column,
        *,
        preformatted=False,
    ):
        card = ttk.Frame(parent, style="Panel.TFrame", padding=10)
        card.grid(row=row, column=column, sticky="nsew", padx=4, pady=4)
        ttk.Label(
            card,
            text=title,
            style="Panel.TLabel",
            font=("Segoe UI Semibold", 11),
        ).pack(anchor="w", pady=(0, 4))
        canvas = tk.Canvas(
            card,
            height=190,
            background=COLORS["surface"],
            highlightthickness=0,
        )
        canvas.pack(fill="both", expand=True)

        def draw(_event=None):
            if preformatted:
                labels = points
                chart_series = series
            else:
                labels = [point["period"] for point in points]
                chart_series = [
                    {
                        "label": label,
                        "color": color,
                        "values": [point["count"] for point in points],
                    }
                    for label, color in series
                ]
            self._draw_analytics_line_chart(canvas, labels, chart_series)

        canvas.bind("<Configure>", draw)
        canvas.after_idle(draw)

    def _draw_analytics_line_chart(self, canvas, labels, series):
        canvas.delete("all")
        width = max(canvas.winfo_width(), 240)
        height = max(canvas.winfo_height(), 140)
        series = [item for item in series if item["values"]]
        if not labels or not series:
            canvas.create_text(
                width / 2,
                height / 2,
                text="No records in this date range.",
                fill=COLORS["textMuted"],
            )
            return

        left, right, top, bottom = 38, width - 18, 18, height - 30
        canvas.create_line(left, bottom, right, bottom, fill=COLORS["border"])
        maximum = max((max(item["values"], default=0) for item in series), default=0)
        maximum = max(maximum, 1)
        for item in series:
            values = item["values"]
            points = []
            for index, value in enumerate(values):
                x = left if len(values) == 1 else left + (right - left) * index / (len(values) - 1)
                y = bottom - (bottom - top) * value / maximum
                points.extend((x, y))
            if len(points) >= 4:
                canvas.create_line(
                    *points,
                    fill=item["color"],
                    width=2,
                    smooth=True,
                )
            for index in range(0, len(points), 2):
                canvas.create_oval(
                    points[index] - 2,
                    points[index + 1] - 2,
                    points[index] + 2,
                    points[index + 1] + 2,
                    fill=item["color"],
                    outline=item["color"],
                )
        canvas.create_text(
            left,
            height - 9,
            text=labels[0],
            anchor="w",
            fill=COLORS["textMuted"],
            font=("Segoe UI", 9),
        )
        canvas.create_text(
            right,
            height - 9,
            text=labels[-1],
            anchor="e",
            fill=COLORS["textMuted"],
            font=("Segoe UI", 9),
        )
        legend_x = left
        for item in series:
            canvas.create_line(
                legend_x,
                7,
                legend_x + 14,
                7,
                fill=item["color"],
                width=3,
            )
            canvas.create_text(
                legend_x + 19,
                7,
                text=item["label"],
                anchor="w",
                fill=COLORS["textMuted"],
                font=("Segoe UI", 9),
            )
            legend_x += 115

    def _add_bar_chart(self, parent, title, counts, color, row, column):
        card = ttk.Frame(parent, style="Panel.TFrame", padding=10)
        card.grid(row=row, column=column, sticky="nsew", padx=4, pady=4)
        ttk.Label(
            card,
            text=title,
            style="Panel.TLabel",
            font=("Segoe UI Semibold", 11),
        ).pack(anchor="w", pady=(0, 4))
        canvas = tk.Canvas(
            card,
            height=185,
            background=COLORS["surface"],
            highlightthickness=0,
        )
        canvas.pack(fill="both", expand=True)

        def draw(_event=None):
            self._draw_analytics_bar_chart(canvas, counts, color)

        canvas.bind("<Configure>", draw)
        canvas.after_idle(draw)

    def _draw_analytics_bar_chart(self, canvas, counts, color):
        canvas.delete("all")
        width = max(canvas.winfo_width(), 240)
        height = max(canvas.winfo_height(), 140)
        entries = list(counts.items())
        if not entries or not any(value for _, value in entries):
            canvas.create_text(
                width / 2,
                height / 2,
                text="No records in this date range.",
                fill=COLORS["textMuted"],
            )
            return
        label_width = min(150, max(88, width * 0.34))
        bar_width = max(width - label_width - 40, 50)
        row_height = min(23, (height - 12) / len(entries))
        maximum = max(value for _, value in entries) or 1
        for index, (label, value) in enumerate(entries):
            y = 8 + row_height * index + row_height / 2
            label_text = str(label).replace("_", " ").title()
            if len(label_text) > 20:
                label_text = label_text[:18] + "…"
            canvas.create_text(
                label_width - 8,
                y,
                text=label_text,
                anchor="e",
                fill=COLORS["textMuted"],
                font=("Segoe UI", 9),
            )
            size = bar_width * value / maximum
            canvas.create_rectangle(
                label_width,
                y - 6,
                label_width + size,
                y + 6,
                fill=color,
                outline=color,
            )
            canvas.create_text(
                label_width + size + 5,
                y,
                text=str(value),
                anchor="w",
                fill=COLORS["text"],
                font=("Segoe UI", 9),
            )

    @staticmethod
    def _format_analytics_duration(seconds):
        if seconds is None:
            return "Unavailable"
        if seconds < 60:
            return f"{round(seconds)} sec"
        if seconds < 3600:
            return f"{round(seconds / 60)} min"
        if seconds < 86400:
            return f"{seconds / 3600:.1f} hr"
        return f"{seconds / 86400:.1f} days"

    def show_profile(self):
        self._clear_content()
        self._page_heading("Account / Profile", "Your authenticated SentinelDesk account.")
        profile = ttk.Frame(self.content, style="Panel.TFrame", padding=20)
        profile.pack(fill="x", anchor="n", pady=10)
        ttk.Label(
            profile,
            text="Loading account information…",
            style="Panel.TLabel",
        ).pack(anchor="w")

        def display_profile(user):
            for child in profile.winfo_children():
                child.destroy()

            name_parts = user["display_name"].split()
            initials = "".join(part[0] for part in name_parts[:2]).upper()
            if not initials:
                initials = user["username"][:1].upper()

            identity = ttk.Frame(profile, style="Panel.TFrame")
            identity.pack(fill="x")
            ttk.Label(
                identity,
                text=initials,
                style="ProfileAvatar.TLabel",
                anchor="center",
            ).pack(side="left", padx=(0, 16))
            summary = ttk.Frame(identity, style="Panel.TFrame")
            summary.pack(side="left", fill="x", expand=True)
            ttk.Label(
                summary,
                text=user["display_name"],
                style="ProfileName.TLabel",
            ).pack(anchor="w")
            ttk.Label(
                summary,
                text=f"@{user['username']}",
                style="PanelMuted.TLabel",
            ).pack(anchor="w", pady=(3, 0))
            ttk.Label(
                identity,
                text=user["role"],
                style="ProfileRole.TLabel",
            ).pack(side="right", anchor="n")

            details = ttk.Frame(profile, style="Panel.TFrame")
            details.pack(fill="x", pady=(20, 0))
            fields = (
                ("User ID", user["id"]),
                ("Username", user["username"]),
                ("Display name", user["display_name"]),
                ("Role", user["role"]),
            )
            for index, (label, value) in enumerate(fields):
                row, column = divmod(index, 2)
                field = ttk.Frame(
                    details,
                    style="ProfileField.TFrame",
                    padding=(14, 12),
                )
                field.grid(
                    row=row,
                    column=column,
                    sticky="nsew",
                    padx=4,
                    pady=4,
                )
                ttk.Label(
                    field,
                    text=label,
                    style="ProfileFieldLabel.TLabel",
                ).pack(anchor="w")
                ttk.Label(
                    field,
                    text=str(value),
                    style="ProfileFieldValue.TLabel",
                ).pack(anchor="w", pady=(5, 0))
            details.columnconfigure(0, weight=1)
            details.columnconfigure(1, weight=1)

        self._run_api_async(
            lambda api: api.get_current_user(),
            display_profile,
            owner=profile,
            request_key="profile",
        )

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
        ttk.Label(
            self.content,
            text="Loading incidents…",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(0, 6))

        def load_page(api):
            if self.incident_assigned_only:
                return api.get_assigned_incidents(**filters)
            return api.get_incidents(**filters)

        self._run_api_async(
            load_page,
            self._render_incident_page,
            owner=self.content,
            request_key="incidents",
        )

    def _render_incident_page(self, page):
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

    def _make_tree(self, parent, columns, style_name="Treeview"):
        container = ttk.Frame(parent)
        container.pack(fill="both", expand=True)
        names = [column[0] for column in columns]
        tree = ttk.Treeview(
            container,
            columns=names,
            show="headings",
            selectmode="browse",
            style=style_name,
        )
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
        rule_var = tk.StringVar()
        self._filter_combo(controls, severity_var, ("",) + SEVERITY_CHOICES, 12)
        self._filter_combo(
            controls,
            type_var,
            (
                "",
                "repeated_failed_logins",
                "suspicious_login",
                "multiple_auth_failures",
                "unauthorized_activity",
                "repeated_incident_reports",
                "other",
            ),
            28,
        )
        loading = ttk.Label(
            self.content,
            text="Loading security alerts…",
            style="Muted.TLabel",
        )
        loading.pack(anchor="w", pady=8)

        def display_alerts(rules):
            loading.destroy()
            rule_ids = [rule["identifier"] for rule in rules]
            self._filter_combo(controls, rule_var, ("",) + tuple(rule_ids), 32)
            tree = self._make_tree(
                self.content,
                (
                    ("id", "ID", 55),
                    ("title", "Title", 250),
                    ("type", "Type", 190),
                    ("rule", "Detection rule", 210),
                    ("source", "Origin", 90),
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
                    "detection_rule": rule_var.get(),
                    "page": page_number[0],
                }

                def render(page_data):
                    self._fill_tree(
                        tree,
                        (
                            (
                                alert["id"],
                                alert["title"],
                                alert["alert_type"].replace("_", " ").title(),
                                alert.get("detection_rule_identifier") or "—",
                                "Automatic" if alert.get("auto_generated") else "Manual",
                                alert["severity"].title(),
                                alert["status"].title(),
                                alert["created_at"],
                            )
                            for alert in page_data["results"]
                        ),
                    )
                    self._render_pager(
                        pager_holder["frame"],
                        page_number[0],
                        page_data,
                        load,
                    )

                self._run_api_async(
                    lambda api: api.get_alerts(
                        **{key: value for key, value in filters.items() if value}
                    ),
                    render,
                    owner=self.content,
                    request_key="alerts",
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

        self._run_api_async(
            lambda api: api.get_detection_rules(),
            display_alerts,
            owner=self.content,
            request_key="alert-rules",
        )

    def show_detection_rules(self):
        if self.current_user["role"] != "Administrator":
            self._show_error(ApiError("Only administrators can manage detection rules.", 403))
            return

        self._clear_content()
        self._page_heading(
            "Detection rules",
            "Rules and statistics are managed by the Django backend.",
        )
        loading = ttk.Label(
            self.content,
            text="Loading detection rules…",
            style="Muted.TLabel",
        )
        loading.pack(anchor="w", pady=12)

        def display_rule_data(data):
            loading.destroy()
            self._render_detection_rules(*data)

        self._run_api_async(
            lambda api: (
                api.get_detection_rules(),
                api.get_detection_overview(),
            ),
            display_rule_data,
            owner=self.content,
            request_key="detection-rules",
        )

    def _render_detection_rules(self, rules, overview):

        if not rules:
            ttk.Label(
                self.content,
                text="No detection rules are configured.",
                style="Muted.TLabel",
            ).pack(anchor="w", pady=12)
            return

        summary = ttk.Frame(self.content, style="Panel.TFrame", padding=14)
        summary.pack(fill="x", pady=(0, 14))
        ttk.Label(
            summary,
            text=(
                f"{overview['enabled_rules']} of {overview['total_rules']} rules enabled  ·  "
                f"{overview['total_generated_alerts']} generated alerts"
            ),
            style="Panel.TLabel",
        ).pack(anchor="w")
        ttk.Label(
            summary,
            text=(
                "Generated alerts by severity: "
                + " · ".join(
                    f"{level.title()}: {count}"
                    for level, count in overview["alerts_by_severity"].items()
                )
            ),
            style="Panel.TLabel",
        ).pack(anchor="w", pady=(5, 0))
        ttk.Label(
            summary,
            text="These rules analyze recorded SentinelDesk application events only.",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(5, 0))

        rule_names = {rule["identifier"]: rule for rule in rules}
        selected_identifier = tk.StringVar(
            value=rules[0]["identifier"] if rules else ""
        )
        ttk.Label(self.content, text="Rule").pack(anchor="w")
        rule_combo = ttk.Combobox(
            self.content,
            textvariable=selected_identifier,
            values=tuple(rule_names),
            state="readonly",
            width=44,
        )
        rule_combo.pack(anchor="w", pady=(4, 12))

        editor = ttk.Frame(self.content, style="Panel.TFrame", padding=16)
        editor.pack(fill="x")
        description = ttk.Label(
            editor,
            text="",
            style="Muted.TLabel",
            wraplength=700,
        )
        description.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 12))
        enabled = tk.BooleanVar()
        threshold = tk.StringVar()
        window_seconds = tk.StringVar()
        severity = tk.StringVar()
        suppression_seconds = tk.StringVar()
        fields = (
            ("Enabled", enabled),
            ("Threshold", threshold),
            ("Window seconds", window_seconds),
            ("Severity", severity),
            ("Suppression seconds", suppression_seconds),
        )
        for row, (label, variable) in enumerate(fields, start=1):
            ttk.Label(editor, text=label, style="Panel.TLabel").grid(
                row=row, column=0, sticky="w", padx=(0, 14), pady=5
            )
            if label == "Enabled":
                widget = ttk.Checkbutton(editor, variable=variable)
            elif label == "Severity":
                widget = ttk.Combobox(
                    editor,
                    textvariable=variable,
                    values=SEVERITY_CHOICES,
                    state="readonly",
                    width=25,
                )
            else:
                widget = ttk.Entry(editor, textvariable=variable, width=28)
            widget.grid(row=row, column=1, sticky="w", pady=5)

        def populate(_event=None):
            rule = rule_names.get(selected_identifier.get())
            if not rule:
                return
            description.configure(text=rule["name"] + "\n" + rule["description"])
            enabled.set(rule["enabled"])
            threshold.set(str(rule["threshold"]))
            window_seconds.set(str(rule["window_seconds"]))
            severity.set(rule["severity"])
            suppression_seconds.set(str(rule["suppression_seconds"]))

        def save_rule():
            try:
                changes = {
                    "enabled": enabled.get(),
                    "threshold": int(threshold.get()),
                    "window_seconds": int(window_seconds.get()),
                    "severity": severity.get(),
                    "suppression_seconds": int(suppression_seconds.get()),
                }
            except ValueError:
                messagebox.showwarning(
                    "Detection rule",
                    "Threshold and time values must be whole numbers.",
                    parent=self,
                )
                return
            def updated(_rule):
                self.show_detection_rules()

            self._run_api_async(
                lambda api: api.update_detection_rule(
                    selected_identifier.get(),
                    changes,
                ),
                updated,
                owner=self.content,
                request_key="detection-rule-update",
            )

        rule_combo.bind("<<ComboboxSelected>>", populate)
        ttk.Button(
            editor,
            text="Save rule",
            style="Accent.TButton",
            command=save_rule,
        ).grid(row=len(fields) + 1, column=1, sticky="e", pady=(12, 0))
        populate()

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
        self._run_api_async(
            lambda api: api.update_alert(alert_id, status_value),
            lambda _alert: refresh(),
            owner=self.content,
            request_key=("alert-status-update", alert_id),
        )

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
            def render(data):
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

            self._run_api_async(
                lambda api: api.get_activity_logs(page=page_number[0]),
                render,
                owner=self.content,
                request_key="activity",
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
            def render(data):
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

            self._run_api_async(
                lambda api: api.get_analysts(page=page_number[0]),
                render,
                owner=self.content,
                request_key="analysts",
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
        self.summary_label = ttk.Label(
            self.container,
            text="",
            style="Muted.TLabel",
            wraplength=800,
            justify="left",
        )
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

        self.workspace_tabs = ttk.Notebook(self.container)
        self.workspace_tabs.pack(fill="both", expand=True, pady=(8, 0))
        notes_tab = ttk.Frame(self.workspace_tabs, padding=8)
        timeline_tab = ttk.Frame(self.workspace_tabs, padding=8)
        alerts_tab = ttk.Frame(self.workspace_tabs, padding=8)
        indicators_tab = ttk.Frame(self.workspace_tabs, padding=8)
        evidence_tab = ttk.Frame(self.workspace_tabs, padding=8)
        findings_tab = ttk.Frame(self.workspace_tabs, padding=8)
        related_tab = ttk.Frame(self.workspace_tabs, padding=8)
        self.workspace_tabs.add(notes_tab, text="Investigation notes")
        self.workspace_tabs.add(timeline_tab, text="Timeline")
        self.workspace_tabs.add(alerts_tab, text="Related alerts")
        self.workspace_tabs.add(indicators_tab, text="Indicators")
        self.workspace_tabs.add(evidence_tab, text="Evidence")
        self.workspace_tabs.add(findings_tab, text="Findings")
        self.workspace_tabs.add(related_tab, text="Related incidents")

        self.notes_text = tk.Text(
            notes_tab,
            height=6,
            wrap="word",
            state="disabled",
            background=COLORS["surface"],
            foreground=COLORS["text"],
            relief="flat",
        )
        self.notes_text.pack(fill="both", expand=True)
        self.note_entry = tk.Text(
            notes_tab,
            height=2,
            wrap="word",
            background=COLORS["surfaceRaised"],
            foreground=COLORS["text"],
            insertbackground=COLORS["text"],
            relief="flat",
        )
        self.note_entry.pack(fill="x", pady=(8, 4))
        self.add_note_button = ttk.Button(
            notes_tab,
            text="Add investigation note",
            command=self._add_note,
        )
        self.add_note_button.pack(anchor="e")
        self.timeline_text = tk.Text(
            timeline_tab,
            wrap="word",
            state="disabled",
            background=COLORS["surface"],
            foreground=COLORS["text"],
            relief="flat",
        )
        self.timeline_text.pack(fill="both", expand=True)
        self.alerts_text = tk.Text(
            alerts_tab,
            wrap="word",
            state="disabled",
            background=COLORS["surface"],
            foreground=COLORS["text"],
            relief="flat",
        )
        self.alerts_text.pack(fill="both", expand=True)
        ioc_form = ttk.Frame(indicators_tab)
        ioc_form.pack(fill="x", pady=(0, 8))
        self.ioc_type = tk.StringVar(value="domain")
        self.ioc_value = tk.StringVar()
        self.ioc_source = tk.StringVar()
        self.ioc_confidence = tk.StringVar(value="50")
        self.ioc_risk = tk.StringVar(value="unknown")
        ttk.Label(ioc_form, text="Type").grid(row=0, column=0, sticky="w")
        ttk.Combobox(
            ioc_form,
            textvariable=self.ioc_type,
            values=("ipv4", "domain", "url", "md5", "sha1", "sha256"),
            state="readonly",
            width=12,
        ).grid(row=1, column=0, padx=(0, 6), sticky="ew")
        ttk.Label(ioc_form, text="Value").grid(row=0, column=1, sticky="w")
        ttk.Entry(ioc_form, textvariable=self.ioc_value, width=28).grid(
            row=1, column=1, padx=(0, 6), sticky="ew"
        )
        ttk.Label(ioc_form, text="Source").grid(row=0, column=2, sticky="w")
        ttk.Entry(ioc_form, textvariable=self.ioc_source, width=20).grid(
            row=1, column=2, padx=(0, 6), sticky="ew"
        )
        ttk.Label(ioc_form, text="Confidence").grid(row=0, column=3, sticky="w")
        ttk.Entry(ioc_form, textvariable=self.ioc_confidence, width=8).grid(
            row=1, column=3, padx=(0, 6), sticky="ew"
        )
        ttk.Label(ioc_form, text="Risk").grid(row=0, column=4, sticky="w")
        ttk.Combobox(
            ioc_form,
            textvariable=self.ioc_risk,
            values=("unknown", "low", "medium", "high", "critical"),
            state="readonly",
            width=10,
        ).grid(row=1, column=4, padx=(0, 6), sticky="ew")
        ttk.Button(
            ioc_form,
            text="Add",
            style="Accent.TButton",
            command=self._add_indicator,
        ).grid(row=1, column=5, sticky="ew")
        self.indicator_tree = self.app._make_tree(
            indicators_tab,
            (
                ("id", "ID", 45),
                ("type", "Type", 100),
                ("value", "Indicator", 250),
                ("confidence", "Confidence", 90),
                ("risk", "Risk", 80),
                ("match", "Local match status", 150),
            ),
        )
        self.indicator_tree.bind(
            "<<TreeviewSelect>>",
            lambda _event: self._show_indicator_match(),
        )
        indicator_actions = ttk.Frame(indicators_tab)
        indicator_actions.pack(fill="x", pady=(8, 4))
        ttk.Button(
            indicator_actions,
            text="Check selected against local intelligence",
            command=self._check_selected_indicator,
        ).pack(side="left")
        self.indicator_match_text = tk.Text(
            indicators_tab,
            height=5,
            wrap="word",
            state="disabled",
            background=COLORS["surface"],
            foreground=COLORS["text"],
            relief="flat",
        )
        self.indicator_match_text.pack(fill="x")
        evidence_form = ttk.Frame(evidence_tab)
        evidence_form.pack(fill="x", pady=(0, 8))
        self.evidence_description = tk.StringVar()
        self.evidence_classification = tk.StringVar(value="internal")
        ttk.Label(evidence_form, text="Description").grid(row=0, column=0, sticky="w")
        ttk.Entry(
            evidence_form,
            textvariable=self.evidence_description,
            width=38,
        ).grid(row=1, column=0, padx=(0, 8), sticky="ew")
        ttk.Label(evidence_form, text="Classification").grid(
            row=0, column=1, sticky="w"
        )
        ttk.Combobox(
            evidence_form,
            textvariable=self.evidence_classification,
            values=("internal", "restricted"),
            state="readonly",
            width=14,
        ).grid(row=1, column=1, padx=(0, 8), sticky="ew")
        ttk.Button(
            evidence_form,
            text="Upload evidence",
            style="Accent.TButton",
            command=self._upload_evidence,
        ).grid(row=1, column=2, sticky="ew")
        self.evidence_tree = self.app._make_tree(
            evidence_tab,
            (
                ("id", "ID", 55),
                ("filename", "File", 180),
                ("size", "Size", 90),
                ("classification", "Classification", 120),
                ("uploaded", "Uploaded", 180),
                ("uploader", "Uploaded by", 130),
            ),
        )
        ttk.Button(
            evidence_tab,
            text="Download selected evidence",
            command=self._download_evidence,
        ).pack(anchor="e", pady=(8, 0))

        self.finding_fields = {}
        finding_form = ttk.Frame(findings_tab)
        finding_form.pack(fill="both", expand=True)
        finding_labels = (
            ("summary", "Summary"),
            ("findings", "Findings"),
            ("identified_indicators", "Identified indicators"),
            ("evidence_reviewed", "Evidence reviewed"),
            ("actions_performed", "Actions performed"),
            ("recommended_remediation", "Recommended remediation"),
        )
        for row, (field, label) in enumerate(finding_labels):
            ttk.Label(finding_form, text=label).grid(
                row=row, column=0, sticky="nw", pady=(0, 5)
            )
            text = tk.Text(
                finding_form,
                height=2 if field != "findings" else 3,
                wrap="word",
                background=COLORS["surface"],
                foreground=COLORS["text"],
                insertbackground=COLORS["text"],
                relief="flat",
            )
            text.grid(row=row, column=1, sticky="ew", padx=(8, 0), pady=(0, 5))
            self.finding_fields[field] = text
        ttk.Label(finding_form, text="Final disposition").grid(
            row=len(finding_labels), column=0, sticky="w", pady=(0, 5)
        )
        self.finding_disposition = tk.StringVar()
        self.finding_disposition_combo = ttk.Combobox(
            finding_form,
            textvariable=self.finding_disposition,
            values=("", "confirmed", "benign", "inconclusive", "other"),
            state="readonly",
            width=22,
        )
        self.finding_disposition_combo.grid(
            row=len(finding_labels), column=1, sticky="w", padx=(8, 0), pady=(0, 5)
        )
        finding_form.columnconfigure(1, weight=1)
        finding_actions = ttk.Frame(findings_tab)
        finding_actions.pack(fill="x", pady=(6, 0))
        self.findings_status = ttk.Label(finding_actions, text="", style="Muted.TLabel")
        self.findings_status.pack(side="left")
        self.save_findings_button = ttk.Button(
            finding_actions,
            text="Save draft",
            command=self._save_findings,
        )
        self.save_findings_button.pack(side="right", padx=(8, 0))
        self.finalize_findings_button = ttk.Button(
            finding_actions,
            text="Finalize",
            style="Accent.TButton",
            command=lambda: self._save_findings(finalize=True),
        )
        self.finalize_findings_button.pack(side="right")

        self.related_text = tk.Text(
            related_tab,
            wrap="word",
            state="disabled",
            background=COLORS["surface"],
            foreground=COLORS["text"],
            relief="flat",
        )
        self.related_text.pack(fill="both", expand=True)
        ttk.Button(
            related_tab,
            text="Refresh suggestions",
            command=self._load_related_incidents,
        ).pack(anchor="e", pady=(8, 0))

    def _load(self):
        self.loading_label = ttk.Label(
            self.container,
            text="Loading incident from Django…",
            style="Muted.TLabel",
        )
        self.loading_label.pack(anchor="w", pady=6)
        self.app._run_api_async(
            lambda api: api.get_incident(self.incident_id),
            self._display_incident,
            owner=self,
            request_key=("incident-detail", self.incident_id),
            on_error=self._incident_load_failed,
        )

    def _incident_load_failed(self, error):
        self.loading_label.configure(text="Incident details could not be loaded.")
        self.app._show_error(error)

    def _display_incident(self, incident):
        self.loading_label.destroy()
        self.incident = incident
        self.title_label.configure(text=incident["title"])
        self.summary_label.configure(
            text=(
                f"Incident #{incident['id']} · {incident.get('public_id', '')}\n"
                f"{incident['category'].replace('_', ' ').title()} · "
                f"{incident['severity'].title()} · "
                f"{incident['status'].replace('_', ' ').title()} · "
                f"Reporter: {incident['reporter_username']} · "
                f"Analyst: {incident.get('assigned_analyst_username') or 'Unassigned'}\n"
                f"Created: {incident['created_at']} · Updated: {incident['updated_at']}"
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
        self._load_timeline()
        self._load_related_alerts()
        self._load_indicators()
        self._load_evidence()
        self._load_findings()
        self._load_related_incidents()

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
        def updated(_incident):
            messagebox.showinfo("Incident", "Incident updated.", parent=self)
            self._load()

        self.app._run_api_async(
            lambda api: api.update_incident(self.incident_id, changes),
            updated,
            owner=self,
            request_key=("incident-update", self.incident_id),
        )

    def _load_assignment(self):
        def load_data(api):
            return (
                api.get_assignment(self.incident_id),
                api.get_analysts(page_size=100),
            )

        self.app._run_api_async(
            load_data,
            self._display_assignment,
            owner=self,
            request_key=("incident-assignment", self.incident_id),
        )

    def _display_assignment(self, data):
        assignment, analyst_page = data
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
        self.app._run_api_async(
            lambda api: api.assign_incident(self.incident_id, analyst_id),
            lambda _assignment: self._load(),
            owner=self,
            request_key=("incident-assignment-save", self.incident_id),
        )

    def _load_notes(self):
        self._set_text(self.notes_text, "Loading investigation notes…")
        self.notes_text.configure(state="disabled")
        self.app._run_api_async(
            lambda api: api.get_notes(self.incident_id),
            self._display_notes,
            owner=self,
            request_key=("incident-notes", self.incident_id),
        )

    def _display_notes(self, page):
        self._set_text(self.notes_text, "")
        if page["results"]:
            for note in page["results"]:
                self.notes_text.insert(
                    "end",
                    f"{note['created_at']} · {note['analyst_username']}\n"
                    f"{note['content']}\n\n",
                )
        else:
            self.notes_text.insert("end", "No investigation notes have been added.")
        if self.app.current_user["role"] == "Administrator" or (
            self.incident.get("assigned_analyst") == self.app.current_user["id"]
        ):
            self.add_note_button.configure(state="normal")
        else:
            self.add_note_button.configure(state="disabled")
        self.notes_text.configure(state="disabled")

    def _load_timeline(self):
        self._set_text(self.timeline_text, "Loading activity…")
        self.timeline_text.configure(state="disabled")
        self.app._run_api_async(
            lambda api: api.get_incident_timeline(self.incident_id),
            self._display_timeline,
            owner=self,
            request_key=("incident-timeline", self.incident_id),
        )

    def _display_timeline(self, page):
        self._set_text(self.timeline_text, "")
        events = sorted(page["results"], key=lambda row: row["created_at"])
        if events:
            for event in events:
                actor = event.get("actor_username") or "System"
                self.timeline_text.insert(
                    "end",
                    f"{event['created_at']} · {actor} · "
                    f"{event['action'].replace('_', ' ').title()}\n"
                    f"{event['description']}\n\n",
                )
        else:
            self.timeline_text.insert(
                "end",
                "No investigation events have been recorded.",
            )
        self.timeline_text.configure(state="disabled")

    def _load_related_alerts(self):
        self._set_text(self.alerts_text, "Loading related alerts…")
        self.alerts_text.configure(state="disabled")
        self.app._run_api_async(
            lambda api: api.get_incident_alerts(self.incident_id),
            self._display_related_alerts,
            owner=self,
            request_key=("incident-alerts", self.incident_id),
        )

    def _display_related_alerts(self, page):
        self._set_text(self.alerts_text, "")
        alerts = page["results"]
        if alerts:
            for alert in alerts:
                origin = "Automatic" if alert["auto_generated"] else "Manual"
                self.alerts_text.insert(
                    "end",
                    f"{alert['created_at']} · {alert['severity'].title()} · "
                    f"{alert['status'].title()} · {origin}\n"
                    f"{alert['title']} ({alert['alert_type'].replace('_', ' ').title()})\n"
                    f"{alert['description']}\n\n",
                )
        else:
            self.alerts_text.insert(
                "end",
                "No security alerts are associated with this incident.",
            )
        self.alerts_text.configure(state="disabled")

    def _load_indicators(self):
        self.app._run_api_async(
            lambda api: api.get_indicators(self.incident_id, page_size=100),
            self._display_indicators,
            owner=self,
            request_key=("incident-indicators", self.incident_id),
        )

    def _display_indicators(self, page):
        self.indicators = page["results"]
        self.app._fill_tree(
            self.indicator_tree,
            (
                (
                    indicator["id"],
                    indicator["indicator_type"].upper(),
                    indicator["value"],
                    f"{indicator['confidence']}%",
                    indicator["risk"].title(),
                    indicator["match_status"].replace("_", " ").title(),
                )
                for indicator in self.indicators
            ),
        )
        if self.indicators:
            first_item = self.indicator_tree.get_children()[0]
            self.indicator_tree.selection_set(first_item)
            self._show_indicator_match()
        else:
            self._set_text(
                self.indicator_match_text,
                "No indicators have been added to this investigation.",
            )
            self.indicator_match_text.configure(state="disabled")

    def _selected_indicator(self, *, warn=True):
        selection = self.indicator_tree.selection()
        if not selection:
            if warn:
                messagebox.showwarning(
                    "Indicators",
                    "Select an indicator first.",
                    parent=self,
                )
            return None
        indicator_id = int(self.indicator_tree.item(selection[0], "values")[0])
        return next(
            (item for item in self.indicators if item["id"] == indicator_id),
            None,
        )

    def _show_indicator_match(self):
        indicator = self._selected_indicator(warn=False)
        if indicator is None:
            return
        result = indicator["match_result"]
        lines = [result["explanation"]]
        for match in result["matches"]:
            lines.append(
                f"{match['source']} · {match['classification']} · "
                f"confidence {match['confidence']}% · updated {match['last_updated']}"
            )
            if match["notes"]:
                lines.append(match["notes"])
        self._set_text(self.indicator_match_text, "\n".join(lines))
        self.indicator_match_text.configure(state="disabled")

    def _add_indicator(self):
        value = self.ioc_value.get().strip()
        source = self.ioc_source.get().strip()
        if not value or not source:
            messagebox.showwarning(
                "Add indicator",
                "Enter both an indicator value and its source.",
                parent=self,
            )
            return
        try:
            confidence = int(self.ioc_confidence.get())
        except ValueError:
            messagebox.showwarning(
                "Add indicator",
                "Confidence must be a whole number from 0 to 100.",
                parent=self,
            )
            return
        values = {
            "indicator_type": self.ioc_type.get(),
            "value": value,
            "source": source,
            "confidence": confidence,
            "risk": self.ioc_risk.get(),
        }

        def added(_indicator):
            self.ioc_value.set("")
            self._load_indicators()

        self.app._run_api_async(
            lambda api: api.add_indicator(self.incident_id, values),
            added,
            owner=self,
            request_key=("incident-ioc-add", self.incident_id),
        )

    def _check_selected_indicator(self):
        indicator = self._selected_indicator()
        if indicator is None:
            return
        self.app._run_api_async(
            lambda api: api.check_indicator(indicator["id"]),
            lambda result: self._display_indicator_check(result),
            owner=self,
            request_key=("indicator-check", indicator["id"]),
        )

    def _display_indicator_check(self, result):
        lines = [result["explanation"]]
        for match in result["matches"]:
            lines.append(
                f"{match['source']} · {match['classification']} · "
                f"confidence {match['confidence']}% · updated {match['last_updated']}"
            )
            if match["notes"]:
                lines.append(match["notes"])
        self._set_text(self.indicator_match_text, "\n".join(lines))
        self.indicator_match_text.configure(state="disabled")
        self._load_indicators()

    def _load_evidence(self):
        self.app._run_api_async(
            lambda api: api.get_evidence(self.incident_id, page_size=100),
            self._display_evidence,
            owner=self,
            request_key=("incident-evidence", self.incident_id),
        )

    def _display_evidence(self, page):
        self.evidence_items = page["results"]
        self.app._fill_tree(
            self.evidence_tree,
            (
                (
                    item["id"],
                    item["original_filename"],
                    f"{item['file_size']} bytes",
                    item["classification"].title(),
                    item["uploaded_at"],
                    item["uploaded_by_username"],
                )
                for item in self.evidence_items
            ),
        )

    def _upload_evidence(self):
        path = filedialog.askopenfilename(
            parent=self,
            title="Select investigation evidence",
            filetypes=(
                ("Supported evidence", "*.png *.jpg *.jpeg *.txt *.log *.csv *.json"),
                ("All files", "*.*"),
            ),
        )
        if not path:
            return
        description = self.evidence_description.get().strip()
        if not description:
            messagebox.showwarning(
                "Evidence",
                "Enter a description for the evidence.",
                parent=self,
            )
            return
        classification = self.evidence_classification.get()

        def uploaded(_evidence):
            self.evidence_description.set("")
            self._load_evidence()
            self._load_timeline()

        self.app._run_api_async(
            lambda api: api.upload_evidence(
                self.incident_id,
                path,
                description,
                classification,
            ),
            uploaded,
            owner=self,
            request_key=("incident-evidence-upload", self.incident_id),
        )

    def _download_evidence(self):
        selection = self.evidence_tree.selection()
        if not selection:
            messagebox.showwarning(
                "Evidence",
                "Select an evidence file first.",
                parent=self,
            )
            return
        evidence_id = int(self.evidence_tree.item(selection[0], "values")[0])
        evidence = next(
            (item for item in self.evidence_items if item["id"] == evidence_id),
            None,
        )
        if evidence is None:
            return
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Save investigation evidence",
            initialfile=evidence["original_filename"],
        )
        if not path:
            return
        def download(api):
            content = api.download_evidence(evidence_id)
            with open(path, "wb") as downloaded_file:
                downloaded_file.write(content)
            return path

        self.app._run_api_async(
            download,
            lambda _path: messagebox.showinfo(
                "Evidence",
                "Evidence downloaded.",
                parent=self,
            ),
            owner=self,
            request_key=("evidence-download", evidence_id),
        )

    def _load_findings(self):
        self.app._run_api_async(
            lambda api: api.get_findings(self.incident_id),
            self._display_findings,
            owner=self,
            request_key=("incident-findings", self.incident_id),
        )

    def _display_findings(self, finding):
        finding = finding or {}
        for field, widget in self.finding_fields.items():
            self._set_text(widget, finding.get(field, ""))
            widget.configure(state="disabled" if finding.get("is_finalized") else "normal")
        finalized = finding.get("is_finalized", False)
        self.finding_disposition.set(finding.get("final_disposition", ""))
        self.finding_disposition_combo.configure(
            state="disabled" if finalized else "readonly"
        )
        self.findings_status.configure(
            text=(
                f"Finalized by {finding.get('finalized_by_username') or 'analyst'}"
                if finalized
                else "Draft findings are not final."
            )
        )
        self.save_findings_button.configure(state="disabled" if finalized else "normal")
        self.finalize_findings_button.configure(
            state="disabled" if finalized else "normal"
        )
        self.finding = finding

    def _save_findings(self, *, finalize=False):
        changes = {
            field: widget.get("1.0", "end").strip()
            for field, widget in self.finding_fields.items()
        }
        changes["final_disposition"] = self.finding_disposition.get()
        if finalize:
            changes["finalize"] = True
        self.app._run_api_async(
            lambda api: api.save_findings(self.incident_id, changes),
            lambda _finding: (
                self._load_findings(),
                self._load_timeline(),
            ),
            owner=self,
            request_key=("incident-findings-save", self.incident_id),
        )

    def _load_related_incidents(self):
        self.related_text.configure(state="normal")
        self._set_text(self.related_text, "Loading related incidents…")
        self.related_text.configure(state="disabled")
        self.app._run_api_async(
            lambda api: api.get_related_incidents(self.incident_id),
            self._display_related_incidents,
            owner=self,
            request_key=("incident-related", self.incident_id),
        )

    def _display_related_incidents(self, suggestions):
        self._set_text(self.related_text, "")
        if not suggestions:
            self.related_text.insert(
                "end",
                "No related-incident suggestions are available.",
            )
        for suggestion in suggestions:
            self.related_text.insert(
                "end",
                f"Incident #{suggestion['incident_id']} · "
                f"{suggestion['title']} · "
                f"{suggestion['severity'].title()} · "
                f"{suggestion['status'].replace('_', ' ').title()}\n"
                f"{suggestion['relationship']}\n"
                f"{' '.join(suggestion['reasons'])}\n\n",
            )
        self.related_text.configure(state="disabled")

    def _add_note(self):
        content = self.note_entry.get("1.0", "end").strip()
        if not content:
            messagebox.showwarning("Investigation note", "Enter a note first.", parent=self)
            return
        def added(_note):
            self.note_entry.delete("1.0", "end")
            self._load_notes()
            self._load_timeline()

        self.app._run_api_async(
            lambda api: api.add_note(self.incident_id, content),
            added,
            owner=self,
            request_key=("incident-note-add", self.incident_id),
        )
