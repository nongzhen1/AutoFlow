import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from webui import app as app_module
from webui.login_pairing import PairingStore


class PairingStoreTests(unittest.TestCase):
    def test_approve_and_poll_exchange_the_identity_once(self):
        store = PairingStore()
        created = store.create(requester_ip="10.0.0.5")

        target = store.scan_target(created["scan_code"])
        self.assertIsNotNone(target)
        assert target is not None
        self.assertEqual("pending", target["status"])
        identity = {"username": "zxb", "role": "user", "account_refs": ["ref-1"], "auth_version": 3}
        self.assertEqual("approved", store.approve(created["scan_code"], identity))

        polled = store.poll(created["poll_token"])
        self.assertEqual("approved", polled["status"])
        self.assertEqual(identity, polled["identity"])
        self.assertEqual("used", store.poll(created["poll_token"])["status"])
        self.assertEqual("missing", store.approve(created["scan_code"], identity))

    def test_expired_codes_cannot_be_approved_or_polled(self):
        clock = [1000.0]
        store = PairingStore(clock=lambda: clock[0], ttl=60)
        created = store.create()

        clock[0] += 61

        self.assertIsNone(store.scan_target(created["scan_code"]))
        self.assertEqual("used", store.poll(created["poll_token"])["status"])
        self.assertEqual("missing", store.approve(created["scan_code"], {"username": "zxb"}))


class QrLoginRouteTests(unittest.TestCase):
    def test_login_page_renders_a_qr_for_a_bootstrapped_console(self):
        with patch.object(app_module, "is_bootstrapped", return_value=True):
            client = TestClient(app_module.create_app())
            response = client.get("/login")

        self.assertEqual(200, response.status_code)
        self.assertIn("data-login-qr", response.text)
        self.assertIn("data:image/svg+xml;base64,", response.text)
        self.assertEqual("no-store", response.headers["cache-control"])

    def test_approval_then_poll_signs_the_waiting_device_in(self):
        principal = {
            "username": "zxb",
            "role": "user",
            "account_refs": ["ref-1"],
            "session_id": "s-user",
            "auth_version": 3,
        }
        with (
            patch.object(app_module, "is_bootstrapped", return_value=True),
            patch.object(app_module, "current_user", return_value="zxb"),
            patch.object(app_module, "current_principal", return_value=principal),
            patch.object(app_module, "validate_csrf", return_value=True),
        ):
            client = TestClient(app_module.create_app())
            pairings = client.app.state.login_pairings
            created = pairings.create(requester_ip="10.0.0.5")

            approved = client.post(
                "/login/pair",
                data={"code": created["scan_code"], "csrf_token": "test"},
                follow_redirects=False,
            )
            self.assertEqual(303, approved.status_code)

            polled = client.get(f"/login/qr/status?token={created['poll_token']}")

        self.assertEqual(200, polled.status_code)
        self.assertEqual("approved", polled.json()["status"])
        self.assertIn("set-cookie", {key.lower() for key in polled.headers})


if __name__ == "__main__":
    unittest.main()
