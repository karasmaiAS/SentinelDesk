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


if __name__ == "__main__":
    unittest.main()
