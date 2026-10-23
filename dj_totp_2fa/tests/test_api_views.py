import json

from django.test import Client
from django.urls import reverse

from dj_totp_2fa import api, session as sess, totp as core
from dj_totp_2fa.models import TOTPDevice

from .base import TotpCase, code_for, login, make_user, verified_client
from .test_views import code_for_secret


def post_json(client, name, payload=None, **extra):
    return client.post(reverse("dj_totp_2fa:" + name), data=json.dumps(payload or {}), content_type="application/json", **extra)


class StatusApiTests(TotpCase):
    def test_anonymous(self):
        r = Client().get(reverse("dj_totp_2fa:api_status"))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["authenticated"], False)
        self.assertIn("no-store", r["Cache-Control"])

    def test_authenticated_states(self):
        self.client.force_login(self.user)
        data = self.client.get(reverse("dj_totp_2fa:api_status")).json()
        self.assertEqual((data["enabled"], data["verified"]), (True, False))
        c = verified_client(self.user, self.device)
        data = c.get(reverse("dj_totp_2fa:api_status")).json()
        self.assertEqual((data["enabled"], data["verified"]), (True, True))
        self.assertEqual(data["methods"], ["totp", "recovery"])


class VerifyApiTests(TotpCase):
    def test_password_then_json_verify(self):
        login(self.client, self.user)
        r = post_json(self.client, "api_verify", {"code": code_for(self.device)})
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body["ok"] and body["verified"])
        self.assertEqual(body["method"], "totp")
        self.assertEqual(body["next"], "/home/")
        self.assertTrue(sess.VERIFIED_KEY in self.client.session)

    def test_session_login_from_another_route_then_verify(self):
        """SPA flow: any login endpoint created the session; the API verifies it."""
        self.client.force_login(self.user)
        self.assertEqual(self.client.get("/api/ping/").status_code, 401)
        r = post_json(self.client, "api_verify", {"code": code_for(self.device)})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.client.get("/api/ping/").status_code, 200)

    def test_wrong_code_reports_attempts_left(self):
        login(self.client, self.user)
        r = post_json(self.client, "api_verify", {"code": "000000"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["code"], "invalid_code")
        self.assertEqual(r.json()["attempts_left"], 4)

    def test_pending_dies_after_five(self):
        login(self.client, self.user)
        for _ in range(4):
            post_json(self.client, "api_verify", {"code": "000000"})
        r = post_json(self.client, "api_verify", {"code": "000000"})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["code"], "pending_expired")

    def test_no_pending(self):
        r = post_json(Client(), "api_verify", {"code": "123456"})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["code"], "no_pending_login")

    def test_recovery_method(self):
        codes = api.generate_recovery_codes(self.user)
        login(self.client, self.user)
        r = post_json(self.client, "api_verify", {"code": codes[0], "method": "recovery"})
        self.assertEqual(r.json()["method"], "recovery")

    def test_form_encoded_body_works_too(self):
        login(self.client, self.user)
        r = self.client.post(reverse("dj_totp_2fa:api_verify"), {"code": code_for(self.device)})
        self.assertEqual(r.status_code, 200)

    def test_csrf_is_enforced(self):
        strict = Client(enforce_csrf_checks=True)
        login(self.client, self.user)
        strict.cookies = self.client.cookies
        r = post_json(strict, "api_verify", {"code": code_for(self.device)})
        self.assertEqual(r.status_code, 403)

    def test_lockout_returns_429_with_retry_after(self):
        from .test_ratelimit import fail
        fail(self.user, n=10)
        login(self.client, self.user)
        r = post_json(self.client, "api_verify", {"code": code_for(self.device)})
        self.assertEqual(r.status_code, 429)
        self.assertEqual(r.json()["code"], "locked")
        self.assertGreaterEqual(int(r["Retry-After"]), 1)

    def test_codes_in_the_query_string_are_refused(self):
        login(self.client, self.user)
        r = self.client.post(reverse("dj_totp_2fa:api_verify") + "?code=123456", data="{}", content_type="application/json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["code"], "code_in_url")

    def test_empty_code(self):
        login(self.client, self.user)
        self.assertEqual(post_json(self.client, "api_verify", {}).status_code, 400)

    def test_bad_json_is_treated_as_empty(self):
        login(self.client, self.user)
        r = self.client.post(reverse("dj_totp_2fa:api_verify"), data="{not json", content_type="application/json")
        self.assertEqual(r.status_code, 400)

    def test_trust_flag_sets_cookie(self):
        login(self.client, self.user)
        r = post_json(self.client, "api_verify", {"code": code_for(self.device), "trust": True})
        self.assertIn("dj_totp_trusted", r.cookies)

    def test_api_throttle(self):
        from django.test import override_settings
        login(self.client, self.user)
        with override_settings(TOTP_ENDPOINT_RATE_LIMITS={"api": (2, 60)}):
            post_json(self.client, "api_verify", {"code": "000000"})
            post_json(self.client, "api_verify", {"code": "000000"})
            r = post_json(self.client, "api_verify", {"code": "000000"})
        self.assertEqual(r.status_code, 429)
        self.assertEqual(r.json()["code"], "rate_limited")


class SetupApiTests(TotpCase):
    def setUp(self):
        super().setUp()
        self.other = make_user("spa")
        self.c = Client()
        self.c.force_login(self.other)

    def test_requires_authentication(self):
        r = post_json(Client(), "api_setup_start")
        self.assertEqual(r.status_code, 401)

    def test_start_and_confirm(self):
        r = post_json(self.c, "api_setup_start")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(len(data["secret"]), 32)
        self.assertTrue(data["otpauth_uri"].startswith("otpauth://totp/"))
        self.assertIn(data["secret"], data["otpauth_uri"])
        self.assertEqual((data["digits"], data["period"], data["algorithm"]), (6, 30, "SHA1"))
        bad = post_json(self.c, "api_setup_confirm", {"code": "000000"})
        self.assertEqual(bad.status_code, 400)
        good = post_json(self.c, "api_setup_confirm", {"code": code_for_secret(data["secret"]), "name": "SPA phone"})
        self.assertEqual(good.status_code, 201)
        self.assertEqual(len(good.json()["recovery_codes"]), 10)
        self.assertTrue(TOTPDevice.objects.get(user=self.other).confirmed)
        self.assertEqual(self.c.get("/api/ping/").status_code, 200)

    def test_confirm_without_start(self):
        r = post_json(self.c, "api_setup_confirm", {"code": "123456"})
        self.assertEqual(r.json()["code"], "no_setup")

    def test_enabled_users_must_verify_first(self):
        self.c.force_login(self.user)
        r = post_json(self.c, "api_setup_start")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["code"], "two_factor_required")

    def test_confirm_throttle_and_lockout(self):
        post_json(self.c, "api_setup_start")
        for _ in range(10):
            post_json(self.c, "api_setup_confirm", {"code": "000000"})
        r = post_json(self.c, "api_setup_confirm", {"code": "000000"})
        self.assertEqual(r.status_code, 429)
