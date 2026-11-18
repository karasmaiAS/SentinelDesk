import ipaddress
import mimetypes
from urllib.parse import urlsplit, urlunsplit

import requests


class ApiError(Exception):
    def __init__(self, message, status_code=None, fields=None):
        super().__init__(message)
        self.status_code = status_code
        self.fields = fields or {}


class SentinelDeskApi:
    def __init__(self, base_url, timeout=10):
        parsed_url = urlsplit(base_url.strip())
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.hostname:
            raise ValueError("Enter a valid HTTP or HTTPS API server URL.")
        if parsed_url.username or parsed_url.password:
            raise ValueError("Do not include credentials in the API server URL.")
        if parsed_url.query or parsed_url.fragment:
            raise ValueError("The API server URL cannot include a query or fragment.")
        if parsed_url.scheme == "http" and not self._is_loopback(parsed_url.hostname):
            raise ValueError("Use HTTPS for non-local SentinelDesk servers.")

        api_path = parsed_url.path.rstrip("/")
        if not api_path.endswith("/api"):
            api_path = f"{api_path}/api"
        self.base_url = urlunsplit(
            (
                parsed_url.scheme,
                parsed_url.netloc,
                api_path,
                "",
                "",
            )
        )
        self.timeout = timeout
        self._session = requests.Session()
        self._token = None

    @staticmethod
    def _is_loopback(hostname):
        if hostname.lower() == "localhost":
            return True
        try:
            return ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            return False

    @property
    def authenticated(self):
        return self._token is not None

    def _request(
        self,
        method,
        path,
        *,
        params=None,
        payload=None,
        files=None,
        data=None,
        raw=False,
    ):
        headers = {}
        if self._token:
            headers["Authorization"] = f"Token {self._token}"
        try:
            response = self._session.request(
                method,
                f"{self.base_url}/{path.lstrip('/')}",
                params=params,
                json=payload if files is None else None,
                files=files,
                data=data,
                headers=headers,
                timeout=self.timeout,
            )
        except requests.RequestException as error:
            raise ApiError(
                f"Could not connect to SentinelDesk at {self.base_url}. "
                "Check that the Django server is running."
            ) from error

        if response.status_code == 401:
            self._token = None

        if response.status_code == 204:
            return None

        if response.ok and raw:
            return response.content

        try:
            data = response.json()
        except ValueError as error:
            raise ApiError(
                f"The server returned an unreadable response "
                f"(HTTP {response.status_code}).",
                status_code=response.status_code,
            ) from error

        if not response.ok:
            if not isinstance(data, dict):
                raise ApiError(
                    f"The server returned an invalid error response "
                    f"(HTTP {response.status_code}).",
                    status_code=response.status_code,
                )
            error_data = data.get("error", {})
            if not isinstance(error_data, dict):
                error_data = {}
            message = error_data.get("detail", "The request could not be completed.")
            if isinstance(message, list):
                message = " ".join(str(item) for item in message)
            fields = error_data.get("fields", {})
            if fields:
                details = []
                for field, errors in fields.items():
                    if not isinstance(errors, (list, tuple)):
                        errors = [errors]
                    details.append(
                        f"{field}: {', '.join(str(item) for item in errors)}"
                    )
                message = f"{message}\n" + "\n".join(details)
            raise ApiError(
                str(message),
                status_code=response.status_code,
                fields=fields,
            )
        return data

    def login(self, username, password):
        response = self._request(
            "POST",
            "auth/login/",
            payload={"username": username, "password": password},
        )
        self._token = response["data"]["token"]
        return response["data"]["user"]

    def logout(self):
        try:
            if self._token:
                self._request("POST", "auth/logout/")
        finally:
            self._token = None

    def get_current_user(self):
        return self._request("GET", "auth/me/")["data"]["user"]

    def get_statistics(self):
        return self._request("GET", "dashboard/statistics/")["data"]

    def get_analytics(self, **filters):
        return self._request("GET", "analytics/", params=filters)["data"]

    def get_incidents(self, **filters):
        response = self._request("GET", "incidents/", params=filters)
        return response["data"]

    def get_assigned_incidents(self, **filters):
        response = self._request("GET", "incidents/assigned/", params=filters)
        return response["data"]

    def get_incident(self, incident_id):
        return self._request("GET", f"incidents/{incident_id}/")["data"]

    def update_incident(self, incident_id, changes):
        return self._request(
            "PATCH",
            f"incidents/{incident_id}/",
            payload=changes,
        )["data"]

    def get_assignment(self, incident_id):
        return self._request(
            "GET",
            f"incidents/{incident_id}/assignments/",
        )["data"]["assignment"]

    def assign_incident(self, incident_id, analyst_id):
        return self._request(
            "POST",
            f"incidents/{incident_id}/assign/",
            payload={"analyst_id": analyst_id},
        )["data"]["assignment"]

    def get_notes(self, incident_id):
        response = self._request("GET", f"incidents/{incident_id}/notes/")
        return response["data"]

    def add_note(self, incident_id, content):
        return self._request(
            "POST",
            f"incidents/{incident_id}/notes/",
            payload={"content": content},
        )["data"]

    def get_indicators(self, incident_id, **filters):
        response = self._request(
            "GET",
            f"incidents/{incident_id}/iocs/",
            params=filters,
        )
        return response["data"]

    def add_indicator(self, incident_id, values):
        return self._request(
            "POST",
            f"incidents/{incident_id}/iocs/",
            payload=values,
        )["data"]

    def update_indicator(self, indicator_id, changes):
        return self._request(
            "PATCH",
            f"iocs/{indicator_id}/",
            payload=changes,
        )["data"]

    def get_indicator_matches(self, indicator_id):
        return self._request(
            "GET",
            f"iocs/{indicator_id}/matches/",
        )["data"]

    def check_indicator(self, indicator_id):
        return self._request(
            "POST",
            f"iocs/{indicator_id}/matches/",
        )["data"]

    def get_related_incidents(self, incident_id):
        return self._request(
            "GET",
            f"incidents/{incident_id}/related/",
        )["data"]["suggestions"]

    def get_findings(self, incident_id):
        return self._request(
            "GET",
            f"incidents/{incident_id}/findings/",
        )["data"]

    def save_findings(self, incident_id, changes):
        return self._request(
            "PATCH",
            f"incidents/{incident_id}/findings/",
            payload=changes,
        )["data"]

    def get_evidence(self, incident_id, **filters):
        return self._request(
            "GET",
            f"incidents/{incident_id}/evidence/",
            params=filters,
        )["data"]

    def upload_evidence(
        self,
        incident_id,
        file_path,
        description,
        classification="internal",
    ):
        with open(file_path, "rb") as evidence_file:
            content_type = mimetypes.guess_type(file_path)[0]
            files = {
                "file": (
                    file_path.split("/")[-1].split("\\")[-1],
                    evidence_file,
                    content_type or "application/octet-stream",
                )
            }
            return self._request(
                "POST",
                f"incidents/{incident_id}/evidence/",
                files=files,
                data={
                    "description": description,
                    "classification": classification,
                },
            )["data"]

    def download_evidence(self, evidence_id):
        return self._request(
            "GET",
            f"evidence/{evidence_id}/download/",
            raw=True,
        )

    def get_incident_timeline(self, incident_id):
        response = self._request(
            "GET",
            "activity-logs/",
            params={"incident": incident_id, "page_size": 100},
        )
        return response["data"]

    def get_incident_alerts(self, incident_id):
        response = self._request(
            "GET",
            "alerts/",
            params={"related_incident": incident_id, "page_size": 100},
        )
        return response["data"]

    def get_analysts(self, **filters):
        response = self._request("GET", "analysts/", params=filters)
        return response["data"]

    def get_alerts(self, **filters):
        response = self._request("GET", "alerts/", params=filters)
        return response["data"]

    def get_detection_overview(self):
        return self._request("GET", "detection/overview/")["data"]

    def get_detection_rules(self):
        return self._request("GET", "detection/rules/")["data"]["rules"]

    def update_detection_rule(self, identifier, changes):
        return self._request(
            "PATCH",
            f"detection/rules/{identifier}/",
            payload=changes,
        )["data"]

    def update_alert(self, alert_id, status):
        return self._request(
            "PATCH",
            f"alerts/{alert_id}/",
            payload={"status": status},
        )["data"]

    def get_activity_logs(self, **filters):
        response = self._request("GET", "activity-logs/", params=filters)
        return response["data"]
