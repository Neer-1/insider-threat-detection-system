import base64
import os
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

os.environ["SECRET_KEY"] = "test-only-signing-key-with-32-chars"
os.environ["SMTP_ENCRYPTION_KEY"] = base64.urlsafe_b64encode(b"0" * 32).decode("ascii")

from fastapi import HTTPException

from backend.auth.dependencies import get_current_admin
from backend.agent_logic.response_engine import recommend_actions
from backend.models.company import Company
from backend.models.devices import Device
from backend.routes.device import check_enrollment_status
from agent.main import wait_for_approval


class RecommendationTests(unittest.TestCase):
    def test_high_and_critical_actions_are_not_marked_executed(self):
        for level in ("high", "critical"):
            with self.subTest(level=level):
                result = recommend_actions(level, {"usb_inserted": True}, [])
                self.assertEqual(result["response_status"], "recommendation_only")
                self.assertTrue(result["actions"])


class DeviceStatusAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.device = SimpleNamespace(
            company_id=12,
            approval_status="approved",
            device_token="device-token-test-only",
        )
        self.company = SimpleNamespace(company_id=12, api_key="company-code-test-only", is_active=True)
        device_query = Mock()
        device_query.filter.return_value.first.return_value = self.device
        company_query = Mock()
        company_query.filter.return_value.first.return_value = self.company
        self.db = Mock()
        self.db.query.side_effect = [device_query, company_query]

    def test_valid_company_code_returns_approved_device_token(self):
        response = check_enrollment_status(
            "public-id-test-only",
            x_company_code="company-code-test-only",
            db=self.db,
        )

        self.assertEqual(response.approval_status, "approved")
        self.assertEqual(response.device_token, "device-token-test-only")
        self.db.query.assert_any_call(Device)
        self.db.query.assert_any_call(Company)

    def test_wrong_company_code_cannot_retrieve_device_token(self):
        with self.assertRaises(HTTPException) as raised:
            check_enrollment_status(
                "public-id-test-only",
                x_company_code="wrong-company-code",
                db=self.db,
            )

        self.assertEqual(raised.exception.status_code, 401)

    def test_inactive_company_cannot_retrieve_token(self):
        self.company.is_active = False
        with self.assertRaises(HTTPException) as raised:
            check_enrollment_status('public-id-test-only', x_company_code='company-code-test-only', db=self.db)
        self.assertEqual(raised.exception.status_code, 401)

    def test_non_ascii_company_code_is_rejected_without_server_error(self):
        with self.assertRaises(HTTPException) as raised:
            check_enrollment_status('public-id-test-only', x_company_code='invalid-\u00e9', db=self.db)
        self.assertEqual(raised.exception.status_code, 401)

    def test_pending_device_does_not_release_token(self):
        self.device.approval_status = 'pending'
        response = check_enrollment_status('public-id-test-only', x_company_code='company-code-test-only', db=self.db)
        self.assertIsNone(response.device_token)


class AdminSubjectTests(unittest.TestCase):
    def test_invalid_subject_returns_401_without_database_lookup(self):
        for subject in (None, 'not-an-id', [], {}, True, 0, -1):
            db = Mock()
            with self.subTest(subject=subject), patch('backend.auth.dependencies.decode_access_token', return_value={'sub': subject}):
                with self.assertRaises(HTTPException) as raised:
                    get_current_admin(token='synthetic-token', db=db)
                self.assertEqual(raised.exception.status_code, 401)
                db.query.assert_not_called()


class AgentStatusProofTests(unittest.TestCase):
    def test_agent_sends_company_code_header_when_polling(self):
        response = Mock()
        response.json.return_value = {
            "approval_status": "approved",
            "device_token": "device-token-test-only",
        }
        config = SimpleNamespace(
            server_url="http://localhost:8000",
            device_id="public-id-test-only",
            company_code="company-code-test-only",
        )

        with unittest.mock.patch("agent.main.requests.get", return_value=response) as get:
            token = wait_for_approval(config)

        self.assertEqual(token, "device-token-test-only")
        get.assert_called_once_with(
            "http://localhost:8000/device/public-id-test-only/status",
            headers={"X-Company-Code": "company-code-test-only"},
            timeout=15,
        )


class SecretConfigurationTests(unittest.TestCase):
    def test_missing_secret_key_fails_closed(self):
        env = os.environ.copy()
        env.pop("SECRET_KEY", None)
        env.pop("SMTP_ENCRYPTION_KEY", None)
        result = subprocess.run(
            [sys.executable, "-c", "import backend.core.config"],
            cwd=os.path.dirname(os.path.dirname(__file__)),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SECRET_KEY must be configured", result.stderr)

    def test_missing_fernet_key_fails_closed(self):
        env = os.environ.copy()
        env["SECRET_KEY"] = "test-only-signing-key-with-32-chars"
        env.pop("SMTP_ENCRYPTION_KEY", None)
        result = subprocess.run(
            [sys.executable, "-c", "import backend.core.config"],
            cwd=os.path.dirname(os.path.dirname(__file__)),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SMTP_ENCRYPTION_KEY must be configured", result.stderr)

    def test_invalid_fernet_key_fails_closed(self):
        env = os.environ.copy()
        env["SECRET_KEY"] = "test-only-signing-key-with-32-chars"
        env["SMTP_ENCRYPTION_KEY"] = "not-a-valid-fernet-key"
        result = subprocess.run(
            [sys.executable, "-c", "import backend.core.config"],
            cwd=os.path.dirname(os.path.dirname(__file__)),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SMTP_ENCRYPTION_KEY must be a valid Fernet key", result.stderr)


if __name__ == "__main__":
    unittest.main()