from unittest import mock

from django.contrib.auth import SESSION_KEY
from django.core import signing
from django.test import Client, override_settings
from django.urls import reverse

from dj_totp_2fa import api, pending, session as sess
from dj_totp_2fa.models import Lockout, TrustedBrowser, TwoFactorEvent

from .base import TotpCase, code_for, enable, login, make_user

VERIFY = "dj_totp_2fa:verify"


def post_code(client, code, **extra):
    return client.post(reverse(VERIFY), dict({"code": code}, **extra))


class PlainLoginTests(TotpCase):
    def test_user_without_2fa_logs_in_normally(self):
        other = make_user("plain")
        client = Client()
        r = login(client, other)
        self.assertRedirects(r, "/home/", fetch_redirect_response=False)
        self.assertIn(SESSION_KEY, client.session)
        self.assertFalse(sess.is_verified(client.get("/home/").wsgi_request))

    def test_wrong_password_shows_the_normal_form_error(self):
        r = login(Client(), self.user, password="wrong")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "totp-error")

    def test_login_page_renders(self):
        r = Client().get(reverse("dj_totp_2fa:login"))
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'name="password"')


class TwoStepLoginTests(TotpCase):
    def test_password_step_does_not_authenticate(self):
        r = login(self.client, self.user)
        self.assertRedirects(r, reverse(VERIFY), fetch_redirect_response=False)
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertIn(sess.PENDING_KEY, self.client.session)

    def test_pending_state_is_signed_and_carries_expected_fields(self):
        login(self.client, self.user, next="/private/")
        data = signing.loads(self.client.session[sess.PENDING_KEY], salt=pending.SALT)
        self.assertEqual(data["uid"], str(self.user.pk))
        self.assertEqual(data["next"], "/private/")
        self.assertEqual(data["attempts"], 0)
        self.assertEqual(data["kind"], "login")
        self.assertIn("backend", data)
        self.assertIn("created", data)

    def test_correct_code_completes_login(self):
        login(self.client, self.user)
        before = self.client.session.session_key
        r = post_code(self.client, code_for(self.device))
        self.assertRedirects(r, "/home/", fetch_redirect_response=False)
        self.assertEqual(self.client.session[SESSION_KEY], str(self.user.pk))
        self.assertEqual(self.client.session[sess.METHOD_KEY], "totp")
        self.assertTrue(self.client.session[sess.VERIFIED_KEY])
        self.assertNotIn(sess.PENDING_KEY, self.client.session)
        self.assertNotEqual(self.client.session.session_key, before)  # session id rotated

    def test_session_fixation(self):
        self.client.get(reverse("dj_totp_2fa:login"))
        self.client.session["planted"] = "x"
        self.client.session.save()
        planted_key = self.client.session.session_key
        login(self.client, self.user)
        post_code(self.client, code_for(self.device))
        self.assertNotEqual(self.client.session.session_key, planted_key)

    def test_verify_without_pending_goes_to_login(self):
        r = Client().get(reverse(VERIFY))
        self.assertRedirects(r, "/account/2fa/login/", fetch_redirect_response=False)
        r = Client().post(reverse(VERIFY), {"code": "123456"})
        self.assertEqual(r.status_code, 302)

    def test_wrong_code_generic_message_and_attempt_counting(self):
        login(self.client, self.user)
        r = post_code(self.client, "000000")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "did not work")
        self.assertContains(r, "4 attempts left")
        self.assertNotIn(SESSION_KEY, self.client.session)

    def test_five_wrong_codes_destroy_the_pending_login(self):
        login(self.client, self.user)
        for i in range(4):
            self.assertEqual(post_code(self.client, "00000%d" % i).status_code, 200)
        r = post_code(self.client, "000009")
        self.assertRedirects(r, "/account/2fa/login/", fetch_redirect_response=False)
        self.assertNotIn(sess.PENDING_KEY, self.client.session)
        # even the right code now needs a new password step
        r = post_code(self.client, code_for(self.device))
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertTrue(TwoFactorEvent.objects.filter(event="pending_destroyed").exists())

    def test_replaying_a_destroyed_pending_blob_is_refused(self):
        login(self.client, self.user)
        blob = self.client.session[sess.PENDING_KEY]
        for i in range(5):
            post_code(self.client, "00000%d" % i)
        session = self.client.session
        session[sess.PENDING_KEY] = blob  # attacker restores the old signed state (e.g. replayed session cookie)
        session.save()
        r = self.client.get(reverse(VERIFY))
        self.assertEqual(r.status_code, 302)
        self.assertTrue(Lockout.objects.filter(scope="pending").exists())

    def test_pending_expires(self):
        login(self.client, self.user)
        with mock.patch("django.core.signing.time.time", return_value=__import__("time").time() + 301):
            r = self.client.get(reverse(VERIFY))
            self.assertEqual(r.status_code, 302)
        self.assertNotIn(sess.PENDING_KEY, self.client.session)

    def test_pending_ttl_is_configurable(self):
        with override_settings(TOTP_PENDING_TTL=5):
            login(self.client, self.user)
            with mock.patch("django.core.signing.time.time", return_value=__import__("time").time() + 6):
                self.assertEqual(self.client.get(reverse(VERIFY)).status_code, 302)

    def test_tampered_pending_is_rejected(self):
        login(self.client, self.user)
        session = self.client.session
        session[sess.PENDING_KEY] = session[sess.PENDING_KEY][:-3] + "abc"
        session.save()
        self.assertEqual(self.client.get(reverse(VERIFY)).status_code, 302)

    def test_pending_for_deleted_or_inactive_user(self):
        login(self.client, self.user)
        self.user.is_active = False
        self.user.save()
        self.assertEqual(self.client.get(reverse(VERIFY)).status_code, 302)

    def test_recovery_code_login(self):
        codes = api.generate_recovery_codes(self.user)
        login(self.client, self.user)
        r = self.client.get(reverse("dj_totp_2fa:verify_recovery"))
        self.assertContains(r, "recovery code")
        r = self.client.post(reverse("dj_totp_2fa:verify_recovery"), {"code": codes[0], "method": "recovery"})
        self.assertRedirects(r, "/home/", fetch_redirect_response=False)
        self.assertEqual(self.client.session[sess.METHOD_KEY], "recovery")
        self.assertEqual(api.recovery_codes_remaining(self.user), 9)

    def test_recovery_disabled_hides_toggle(self):
        with override_settings(TOTP_ALLOW_RECOVERY_CODES=False):
            login(self.client, self.user)
            r = self.client.get(reverse(VERIFY))
            self.assertNotContains(r, "verify/recovery")

    def test_cancel_returns_to_login(self):
        login(self.client, self.user)
        r = self.client.post(reverse("dj_totp_2fa:cancel"))
        self.assertEqual(r.status_code, 302)
        self.assertNotIn(sess.PENDING_KEY, self.client.session)

    def test_replayed_code_cannot_log_in(self):
        code = code_for(self.device)
        login(self.client, self.user)
        post_code(self.client, code)
        other = Client()
        login(other, self.user)
        r = post_code(other, code)
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(SESSION_KEY, other.session)

    def test_codes_in_the_url_are_refused_and_stripped(self):
        login(self.client, self.user)
        r = self.client.get(reverse(VERIFY) + "?code=123456&next=/x/")
        self.assertEqual(r.status_code, 302)
        self.assertNotIn("123456", r["Location"])
        self.assertTrue(TwoFactorEvent.objects.filter(event="code_in_url").exists())

    def test_get_never_verifies(self):
        login(self.client, self.user)
        self.client.get(reverse(VERIFY) + "?code=%s" % code_for(self.device))
        self.assertNotIn(SESSION_KEY, self.client.session)

    def test_headers(self):
        login(self.client, self.user)
        r = self.client.get(reverse(VERIFY))
        self.assertIn("no-store", r["Cache-Control"])
        self.assertEqual(r["X-Frame-Options"], "DENY")
        self.assertEqual(r["Referrer-Policy"], "no-referrer")

    def test_csrf_is_enforced(self):
        login(self.client, self.user)
        strict = Client(enforce_csrf_checks=True)
        strict.cookies = self.client.cookies
        r = strict.post(reverse(VERIFY), {"code": code_for(self.device)})
        self.assertEqual(r.status_code, 403)

    def test_logout_clears_flags(self):
        login(self.client, self.user)
        post_code(self.client, code_for(self.device))
        self.client.logout()
        self.assertNotIn(sess.VERIFIED_KEY, self.client.session)


class NextParameterTests(TotpCase):
    def go(self, nxt):
        login(self.client, self.user, next=nxt)
        return post_code(self.client, code_for(self.device))

    def test_safe_next_is_followed(self):
        self.assertRedirects(self.go("/private/"), "/private/", fetch_redirect_response=False)

    def test_open_redirects_are_refused(self):
        for evil in ("https://evil.example/", "//evil.example/", "javascript:alert(1)", "http://testserver.evil.example/", "///evil.example", "\\\\evil.example"):
            client = Client()
            login(client, self.user, next=evil)
            r = post_code(client, code_for(self.device))
            if r.status_code == 302:
                self.assertEqual(r["Location"], "/home/", evil)
            from dj_totp_2fa.models import TOTPDevice
            TOTPDevice.objects.filter(pk=self.device.pk).update(last_used_step=0)  # allow the next attempt in this loop

    def test_next_on_get_for_step_up_is_validated(self):
        client = Client()
        login(client, self.user)
        post_code(client, code_for(self.device))
        r = client.get(reverse(VERIFY) + "?fresh=1&next=https://evil.example/")
        self.assertEqual(r.status_code, 200)
        self.assertNotContains(r, "evil.example")


def logout_keep_cookie(client):
    """Client.logout() empties the whole cookie jar; a real browser keeps the trusted-browser cookie."""
    morsel = client.cookies.get("dj_totp_trusted")
    value = morsel.value if morsel else None
    client.logout()
    if value:
        client.cookies["dj_totp_trusted"] = value


class RememberAndTrustedBrowserTests(TotpCase):
    def trust(self, client):
        login(client, self.user)
        return post_code(client, code_for(self.device), trust="1")

    def test_cookie_attributes_and_hashed_storage(self):
        r = self.trust(self.client)
        cookie = r.cookies["dj_totp_trusted"]
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["samesite"], "Lax")
        self.assertEqual(cookie["max-age"], 30 * 86400)
        self.assertFalse(cookie["secure"])  # http request
        token = cookie.value
        self.assertGreaterEqual(len(token), 43)  # 256 bits
        row = TrustedBrowser.objects.get()
        self.assertNotEqual(row.token_hash, token)
        self.assertNotIn(token, row.token_hash)
        self.assertEqual(len(row.token_hash), 64)
        self.assertEqual(row.user, self.user)

    def test_cookie_is_secure_over_https(self):
        client = Client()
        login(client, self.user, secure=True)
        r = client.post(reverse(VERIFY), {"code": code_for(self.device), "trust": "1"}, secure=True)
        self.assertTrue(r.cookies["dj_totp_trusted"]["secure"])

    def test_trusted_browser_skips_the_code(self):
        self.trust(self.client)
        logout_keep_cookie(self.client)  # keeps the cookie jar
        r = login(self.client, self.user)
        self.assertRedirects(r, "/home/", fetch_redirect_response=False)
        self.assertEqual(self.client.session[sess.METHOD_KEY], "trusted_browser")
        self.assertTrue(TwoFactorEvent.objects.filter(event="trusted_login").exists())

    def test_cookie_is_bound_to_the_user(self):
        self.trust(self.client)
        other = make_user("mallory")
        enable(other)
        logout_keep_cookie(self.client)
        r = login(self.client, other)
        self.assertRedirects(r, reverse(VERIFY), fetch_redirect_response=False)

    def test_revoked_and_expired_cookies_are_useless(self):
        from django.utils import timezone
        from datetime import timedelta
        self.trust(self.client)
        logout_keep_cookie(self.client)
        TrustedBrowser.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertRedirects(login(self.client, self.user), reverse(VERIFY), fetch_redirect_response=False)
        logout_keep_cookie(self.client)
        TrustedBrowser.objects.all().delete()
        self.assertRedirects(login(self.client, self.user), reverse(VERIFY), fetch_redirect_response=False)

    def test_forged_cookie(self):
        self.client.cookies["dj_totp_trusted"] = "A" * 43
        self.assertRedirects(login(self.client, self.user), reverse(VERIFY), fetch_redirect_response=False)
        self.client.cookies["dj_totp_trusted"] = "A" * 500
        self.assertRedirects(login(self.client, self.user), reverse(VERIFY), fetch_redirect_response=False)

    def test_rotation(self):
        with override_settings(TOTP_ROTATE_TRUSTED_TOKEN=True):
            first = self.trust(self.client).cookies["dj_totp_trusted"].value
            logout_keep_cookie(self.client)
            r = login(self.client, self.user)
            second = r.cookies["dj_totp_trusted"].value
            self.assertNotEqual(first, second)
            logout_keep_cookie(self.client)
            self.assertRedirects(login(self.client, self.user), "/home/", fetch_redirect_response=False)

    def test_feature_can_be_disabled(self):
        with override_settings(TOTP_REMEMBER_BROWSER=0):
            login(self.client, self.user)
            r = self.client.get(reverse(VERIFY))
            self.assertNotContains(r, 'name="trust"')
            r = post_code(self.client, code_for(self.device), trust="1")
            self.assertNotIn("dj_totp_trusted", r.cookies)

    def test_notification_email_sent(self):
        from django.core import mail
        self.trust(self.client)
        self.assertTrue(any("trusted" in m.subject for m in mail.outbox))

    def test_browser_session_when_keep_signed_in_unticked(self):
        login(self.client, self.user, remember_present="1")
        post_code(self.client, code_for(self.device))
        self.assertTrue(self.client.session.get_expire_at_browser_close())

    def test_keep_signed_in_ticked_uses_default_age(self):
        login(self.client, self.user, remember_present="1", remember_me="1")
        post_code(self.client, code_for(self.device))
        self.assertFalse(self.client.session.get_expire_at_browser_close())


class SessionBackendTests(TotpCase):
    def run_flow(self):
        r = login(self.client, self.user)
        self.assertRedirects(r, reverse(VERIFY), fetch_redirect_response=False)
        r = post_code(self.client, code_for(self.device))
        self.assertRedirects(r, "/home/", fetch_redirect_response=False)
        self.assertEqual(self.client.get("/strict/").status_code, 200)

    def test_signed_cookie_sessions(self):
        with override_settings(SESSION_ENGINE="django.contrib.sessions.backends.signed_cookies"):
            self.run_flow()

    def test_cached_db_sessions(self):
        with override_settings(SESSION_ENGINE="django.contrib.sessions.backends.cached_db"):
            self.run_flow()

    def test_cache_sessions(self):
        with override_settings(SESSION_ENGINE="django.contrib.sessions.backends.cache"):
            self.run_flow()

    def test_session_cookie_age_is_respected(self):
        with override_settings(SESSION_COOKIE_AGE=600):
            login(self.client, self.user)
            post_code(self.client, code_for(self.device))
            self.assertLessEqual(self.client.session.get_expiry_age(), 600)

    def test_signed_cookie_replay_cannot_reset_attempts(self):
        """With cookie sessions the client could replay an old cookie; attempts are also counted in the cache."""
        with override_settings(SESSION_ENGINE="django.contrib.sessions.backends.signed_cookies"):
            login(self.client, self.user)
            old = self.client.cookies["sessionid"].value
            for i in range(3):
                post_code(self.client, "00000%d" % i)
            self.client.cookies["sessionid"] = old  # attacker restores the cookie from before the failures
            r = post_code(self.client, "000010")
            self.assertContains(r, "1 attempt left")
