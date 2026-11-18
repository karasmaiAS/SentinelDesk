import tempfile
import unittest
from unittest.mock import Mock, patch

import requests

from .api_client import ApiError, SentinelDeskApi


class SentinelDeskApiTests(unittest.TestCase):
    def setUp(self):
        self.api = SentinelDeskApi("http://localhost:8000/api/")
        self.response = Mock()
        self.response.status_code = 200
        self.response.ok = True
        self.response.json.return_value = {"data": {"user": {"id": 3}}}

    def test_api_base_url_is_normalized_and_remote_http_is_rejected(self):
        api = SentinelDeskApi("http://127.0.0.1:8000")
        self.assertEqual(api.base_url, "http://127.0.0.1:8000/api")

        with self.assertRaisesRegex(ValueError, "Use HTTPS"):
            SentinelDeskApi("http://sentineldesk.example/api")

        with self.assertRaisesRegex(ValueError, "credentials"):
            SentinelDeskApi("https://user:password@sentineldesk.example/api")

    @patch("desktop.api_client.requests.Session.request")
    def test_api_calls_use_token_authorization_header(self, request):
        request.return_value = self.response
        self.api._token = "temporary-token"

        result = self.api.get_current_user()

        self.assertEqual(result, {"id": 3})
        self.assertEqual(
            request.call_args.kwargs["headers"],
            {"Authorization": "Token temporary-token"},
        )
        self.assertEqual(request.call_args.kwargs["timeout"], 10)

    @patch("desktop.api_client.requests.Session.request")
    def test_login_sends_credentials_over_http_and_keeps_token_in_memory(self, request):
        self.response.json.return_value = {
            "data": {
                "token": "issued-token",
                "user": {"id": 4, "role": "Security Analyst"},
            }
        }
        request.return_value = self.response

        user = self.api.login("analyst", "not-saved")

        self.assertEqual(user["role"], "Security Analyst")
        self.assertEqual(self.api._token, "issued-token")
        self.assertIsNone(self.api._session.auth)
        self.assertEqual(
            request.call_args.kwargs["json"],
            {"username": "analyst", "password": "not-saved"},
        )

    @patch("desktop.api_client.requests.Session.request")
    def test_api_errors_include_field_validation_and_status(self, request):
        self.response.status_code = 400
        self.response.ok = False
        self.response.json.return_value = {
            "error": {
                "detail": "Validation failed.",
                "fields": {"status": ["Invalid status."]},
            }
        }
        request.return_value = self.response

        with self.assertRaises(ApiError) as raised:
            self.api.update_incident(8, {"status": "invalid"})

        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("status: Invalid status.", str(raised.exception))

    @patch("desktop.api_client.requests.Session.request")
    def test_unauthorized_response_invalidates_the_local_token(self, request):
        self.api._token = "revoked-token"
        self.response.status_code = 401
        self.response.ok = False
        self.response.json.return_value = {
            "error": {
                "code": "authentication_required",
                "detail": "Authentication credentials were not provided or are invalid.",
            }
        }
        request.return_value = self.response

        with self.assertRaises(ApiError) as raised:
            self.api.get_statistics()

        self.assertEqual(raised.exception.status_code, 401)
        self.assertFalse(self.api.authenticated)

    @patch("desktop.api_client.requests.Session.request")
    def test_network_errors_are_reported_without_hiding_the_cause(self, request):
        request.side_effect = requests.ConnectionError("connection refused")

        with self.assertRaises(ApiError) as raised:
            self.api.get_statistics()

        self.assertIn("Check that the Django server is running", str(raised.exception))
        self.assertIsInstance(raised.exception.__cause__, requests.ConnectionError)

    @patch("desktop.api_client.requests.Session.request")
    def test_logout_clears_token_even_if_server_call_fails(self, request):
        self.api._token = "temporary-token"
        request.side_effect = requests.ConnectionError("connection refused")

        with self.assertRaises(ApiError):
            self.api.logout()

        self.assertFalse(self.api.authenticated)

    @patch("desktop.api_client.requests.Session.request")
    def test_paginated_directory_call_preserves_page_metadata(self, request):
        self.response.json.return_value = {
            "data": {
                "count": 31,
                "next": "http://localhost/api/analysts/?page=2",
                "previous": None,
                "results": [{"id": 5, "username": "analyst"}],
            }
        }
        request.return_value = self.response

        page = self.api.get_analysts(page=1, page_size=100)

        self.assertEqual(page["count"], 31)
        self.assertEqual(page["results"][0]["id"], 5)
        self.assertEqual(request.call_args.kwargs["params"], {"page": 1, "page_size": 100})

    @patch("desktop.api_client.requests.Session.request")
    def test_analytics_request_passes_date_range_and_granularity(self, request):
        self.response.json.return_value = {
            "data": {"filters": {"granularity": "weekly"}}
        }
        request.return_value = self.response

        result = self.api.get_analytics(
            start_date="2026-03-01",
            end_date="2026-03-31",
            granularity="weekly",
        )

        self.assertEqual(result["filters"]["granularity"], "weekly")
        self.assertEqual(
            request.call_args.args[0:2],
            ("GET", "http://localhost:8000/api/analytics/"),
        )
        self.assertEqual(
            request.call_args.kwargs["params"],
            {
                "start_date": "2026-03-01",
                "end_date": "2026-03-31",
                "granularity": "weekly",
            },
        )

    @patch("desktop.api_client.requests.Session.request")
    def test_investigation_workspace_fetches_scoped_timeline_and_alerts(self, request):
        request.side_effect = [
            Mock(
                status_code=200,
                ok=True,
                json=lambda: {"data": {"results": [{"id": 11}], "count": 1}},
            ),
            Mock(
                status_code=200,
                ok=True,
                json=lambda: {"data": {"results": [{"id": 12}], "count": 1}},
            ),
        ]

        timeline = self.api.get_incident_timeline(7)
        alerts = self.api.get_incident_alerts(7)

        self.assertEqual(timeline["results"][0]["id"], 11)
        self.assertEqual(alerts["results"][0]["id"], 12)
        self.assertEqual(
            [call.args[0:2] for call in request.call_args_list],
            [
                ("GET", "http://localhost:8000/api/activity-logs/"),
                ("GET", "http://localhost:8000/api/alerts/"),
            ],
        )
        self.assertEqual(
            request.call_args_list[0].kwargs["params"],
            {"incident": 7, "page_size": 100},
        )
        self.assertEqual(
            request.call_args_list[1].kwargs["params"],
            {"related_incident": 7, "page_size": 100},
        )

    @patch("desktop.api_client.requests.Session.request")
    def test_indicator_api_methods_use_incident_scoped_endpoints(self, request):
        request.side_effect = [
            Mock(
                status_code=200,
                ok=True,
                json=lambda: {"data": {"results": [{"id": 8}], "count": 1}},
            ),
            Mock(
                status_code=201,
                ok=True,
                json=lambda: {"data": {"id": 8, "value": "example.com"}},
            ),
            Mock(
                status_code=200,
                ok=True,
                json=lambda: {"data": {"id": 8, "value": "example.net"}},
            ),
            Mock(
                status_code=200,
                ok=True,
                json=lambda: {"data": {"status": "matched", "matches": []}},
            ),
            Mock(
                status_code=200,
                ok=True,
                json=lambda: {"data": {"status": "unmatched", "matches": []}},
            ),
        ]
        values = {
            "indicator_type": "domain",
            "value": "example.com",
            "source": "Analyst observation",
        }

        listed = self.api.get_indicators(7, page_size=100)
        created = self.api.add_indicator(7, values)
        updated = self.api.update_indicator(8, {"value": "example.net"})
        matches = self.api.get_indicator_matches(8)
        checked = self.api.check_indicator(8)

        self.assertEqual(listed["results"][0]["id"], 8)
        self.assertEqual(created["value"], "example.com")
        self.assertEqual(updated["value"], "example.net")
        self.assertEqual(matches["status"], "matched")
        self.assertEqual(checked["status"], "unmatched")
        self.assertEqual(
            [call.args[0:2] for call in request.call_args_list],
            [
                ("GET", "http://localhost:8000/api/incidents/7/iocs/"),
                ("POST", "http://localhost:8000/api/incidents/7/iocs/"),
                ("PATCH", "http://localhost:8000/api/iocs/8/"),
                ("GET", "http://localhost:8000/api/iocs/8/matches/"),
                ("POST", "http://localhost:8000/api/iocs/8/matches/"),
            ],
        )
        self.assertEqual(request.call_args_list[1].kwargs["json"], values)

    @patch("desktop.api_client.requests.Session.request")
    def test_evidence_api_uploads_multipart_and_downloads_bytes(self, request):
        request.side_effect = [
            Mock(
                status_code=201,
                ok=True,
                json=lambda: {
                    "data": {"id": 17, "original_filename": "evidence.txt"}
                },
            ),
            Mock(status_code=200, ok=True, content=b"evidence contents"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/evidence.txt"
            with open(path, "wb") as evidence:
                evidence.write(b"evidence contents")
            uploaded = self.api.upload_evidence(
                7,
                path,
                "Captured log",
                "restricted",
            )

        downloaded = self.api.download_evidence(17)

        self.assertEqual(uploaded["id"], 17)
        self.assertEqual(downloaded, b"evidence contents")
        upload_call, download_call = request.call_args_list
        self.assertEqual(
            upload_call.args[0:2],
            ("POST", "http://localhost:8000/api/incidents/7/evidence/"),
        )
        self.assertIn("file", upload_call.kwargs["files"])
        self.assertEqual(
            upload_call.kwargs["data"],
            {"description": "Captured log", "classification": "restricted"},
        )
        self.assertEqual(
            download_call.args[0:2],
            ("GET", "http://localhost:8000/api/evidence/17/download/"),
        )

    @patch("desktop.api_client.requests.Session.request")
    def test_findings_and_related_incident_methods_use_workspace_routes(self, request):
        request.side_effect = [
            Mock(
                status_code=200,
                ok=True,
                json=lambda: {"data": {"summary": "Draft"}},
            ),
            Mock(
                status_code=200,
                ok=True,
                json=lambda: {"data": {"summary": "Saved"}},
            ),
            Mock(
                status_code=200,
                ok=True,
                json=lambda: {"data": {"suggestions": [{"incident_id": 9}]}},
            ),
        ]

        finding = self.api.get_findings(7)
        saved = self.api.save_findings(7, {"summary": "Saved"})
        related = self.api.get_related_incidents(7)

        self.assertEqual(finding["summary"], "Draft")
        self.assertEqual(saved["summary"], "Saved")
        self.assertEqual(related[0]["incident_id"], 9)
        self.assertEqual(
            [call.args[0:2] for call in request.call_args_list],
            [
                ("GET", "http://localhost:8000/api/incidents/7/findings/"),
                ("PATCH", "http://localhost:8000/api/incidents/7/findings/"),
                ("GET", "http://localhost:8000/api/incidents/7/related/"),
            ],
        )

    @patch("desktop.api_client.requests.Session.request")
    def test_detection_api_methods_use_overview_rules_and_patch_endpoints(self, request):
        request.side_effect = [
            Mock(
                status_code=200,
                ok=True,
                json=lambda: {"data": {"total_generated_alerts": 2}},
            ),
            Mock(
                status_code=200,
                ok=True,
                json=lambda: {"data": {"rules": [{"identifier": "multiple_failed_logins"}]}},
            ),
            Mock(
                status_code=200,
                ok=True,
                json=lambda: {"data": {"identifier": "multiple_failed_logins"}},
            ),
        ]

        overview = self.api.get_detection_overview()
        rules = self.api.get_detection_rules()
        updated = self.api.update_detection_rule(
            "multiple_failed_logins",
            {"threshold": 7},
        )

        self.assertEqual(overview["total_generated_alerts"], 2)
        self.assertEqual(rules[0]["identifier"], "multiple_failed_logins")
        self.assertEqual(updated["identifier"], "multiple_failed_logins")
        self.assertEqual(
            [call.args[0:2] for call in request.call_args_list],
            [
                ("GET", "http://localhost:8000/api/detection/overview/"),
                ("GET", "http://localhost:8000/api/detection/rules/"),
                ("PATCH", "http://localhost:8000/api/detection/rules/multiple_failed_logins/"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
