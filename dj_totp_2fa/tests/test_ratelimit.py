import time
from datetime import timedelta
from unittest import mock

from django.core import mail
from django.core.cache import cache
from django.test import Client, RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from dj_totp_2fa import api, clientip, ratelimit
from dj_totp_2fa.models import Lockout, TwoFactorEvent
from dj_totp_2fa.signals import totp_locked_out

from .base import TotpCase, code_for, enable, login, make_user


def request_from(ip="203.0.113.7", **meta):
    request = RequestFactory().post("/x/", REMOTE_ADDR=ip, **meta)
    return request


def fail(user, request=None, n=1):
    last = None
    for _ in range(n):
        last = api.verify_code(user, "000000", request, method="totp")
    return last


def expire_locks():
    Lockout.objects.exclude(scope="pending").update(until=timezone.now() - timedelta(seconds=1))


class UserLockoutTests(TotpCase):
    def test_ten_failures_lock_the_user(self):
        for i in range(9):
            self.assertEqual(fail(self.user).reason, "invalid")
        last = fail(self.user)
        self.assertEqual(last.reason, "locked")
        self.assertTrue(55 <= last.retry_after <= 61)
        self.assertEqual(Lockout.objects.get(scope="user").user, self.user)
        self.assertTrue(TwoFactorEvent.objects.filter(event="lockout").exists())

    def test_locked_user_is_refused_even_with_the_right_code(self):
        fail(self.user, n=10)
        result = api.verify_code(self.user, code_for(self.device))
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "locked")
        self.device.refresh_from_db()
        self.assertEqual(self.device.last_used_step, 0)

    def test_right_and_wrong_codes_look_identical_while_locked(self):
        fail(self.user, n=10)
        good = api.verify_code(self.user, code_for(self.device))
        bad = api.verify_code(self.user, "000000")
        self.assertEqual((good.reason, good.message), (bad.reason, bad.message))
        self.assertAlmostEqual(good.retry_after, bad.retry_after, delta=1)

    def test_progressive_lockout_steps(self):
        durations = []
        fail(self.user, n=10)
        for _ in range(6):
            row = Lockout.objects.get(scope="user")
            durations.append(round((row.until - timezone.now()).total_seconds() / 10) * 10)
            expire_locks()
            fail(self.user)  # the window is still full, so one more failure escalates
        self.assertEqual(durations, [60, 300, 900, 3600, 86400, 86400])

    def test_custom_steps(self):
        with override_settings(TOTP_LOCKOUT_STEPS=[7, 11], TOTP_USER_FAILURE_LIMIT=2):
            fail(self.user, n=2)
            self.assertAlmostEqual((Lockout.objects.get().until - timezone.now()).total_seconds(), 7, delta=1.5)
            expire_locks()
            fail(self.user)
            self.assertAlmostEqual((Lockout.objects.get().until - timezone.now()).total_seconds(), 11, delta=1.5)

    def test_lockout_survives_a_cache_flush_and_other_workers(self):
        fail(self.user, n=10)
        cache.clear()
        self.assertEqual(api.verify_code(self.user, code_for(self.device)).reason, "locked")

    def test_lockout_ends_and_success_resets_counters(self):
        fail(self.user, n=10)
        expire_locks()
        result = api.verify_code(self.user, code_for(self.device))
        self.assertTrue(result.ok)
        cache.clear()
        fail(self.user, n=5)
        self.assertNotEqual(fail(self.user).reason, "locked")

    def test_escalation_level_resets_after_quiet_time(self):
        fail(self.user, n=10)
        Lockout.objects.update(until=timezone.now() - timedelta(days=3), level=3)
        cache.clear()
        fail(self.user, n=10)
        self.assertEqual(Lockout.objects.get().level, 0)

    def test_user_and_ip_independent(self):
        other = make_user("other")
        enable(other)
        fail(self.user, request_from("198.51.100.1"), n=10)
        self.assertTrue(api.verify_code(other, code_for(other.totp_devices.first()), request_from("198.51.100.2")).ok)

    def test_per_user_limit_spans_all_ips(self):
        for i in range(10):
            fail(self.user, request_from("198.51.100.%d" % (i + 1)))
        self.assertEqual(api.verify_code(self.user, "000000", request_from("192.0.2.99"), method="totp").reason, "locked")

    def test_signal_hook_email_and_staff_alert(self):
        seen, alerts, hook_calls = [], [], []
        receiver = lambda sender, **kw: seen.append(kw["scope"])  # noqa: E731
        totp_locked_out.connect(receiver)
        try:
            with override_settings(TOTP_STAFF_ALERT=lambda event, details: alerts.append(event),
                                   TOTP_ON_LOCKOUT=[lambda u, r, scope, until: hook_calls.append(scope)]):
                fail(self.user, n=10)
        finally:
            totp_locked_out.disconnect(receiver)
        self.assertEqual(seen, ["user"])
        self.assertEqual(hook_calls, ["user"])
        self.assertIn("lockout", alerts)
        self.assertTrue(any("failed two-factor" in m.subject for m in mail.outbox))

    def test_notifications_can_be_switched_off(self):
        with override_settings(TOTP_NOTIFY={"lockout": False}):
            fail(self.user, n=10)
        self.assertFalse(mail.outbox)

    def test_custom_notification_sender(self):
        sent = []
        with override_settings(TOTP_NOTIFY_SENDER=lambda user, event, ctx: sent.append(event)):
            fail(self.user, n=10)
        self.assertEqual(sent, ["lockout"])
        self.assertFalse(mail.outbox)

    def test_limits_can_be_disabled(self):
        with override_settings(TOTP_RATE_LIMITS_ENABLED=False):
            self.assertEqual(fail(self.user, n=40).reason, "invalid")
        self.assertFalse(Lockout.objects.exists())


class IpLimitTests(TestCase):
    def setUp(self):
        cache.clear()
        self.users = []
        for i in range(25):
            u = make_user("u%d" % i)
            enable(u)
            self.users.append(u)

    def test_twenty_failures_from_one_ip_lock_that_ip_for_everyone(self):
        request = request_from("198.51.100.9")
        for u in self.users[:19]:
            self.assertEqual(fail(u, request).reason, "invalid")
        self.assertEqual(fail(self.users[19], request).reason, "locked")
        victim = self.users[24]
        self.assertEqual(api.verify_code(victim, code_for(victim.totp_devices.first()), request).reason, "locked")
        self.assertTrue(api.verify_code(victim, code_for(victim.totp_devices.first()), request_from("198.51.100.10")).ok)
        self.assertEqual(Lockout.objects.filter(scope="ip").count(), 1)

    def test_ipv6_addresses_in_one_slash_64_share_a_budget(self):
        for i in range(20):
            fail(self.users[i], request_from("2001:db8:1:2::%x" % (i + 1)))
        self.assertTrue(Lockout.objects.filter(scope="ip").exists())
        self.assertEqual(api.verify_code(self.users[24], "000000", request_from("2001:db8:1:2:ffff::9"), method="totp").reason, "locked")
        self.assertNotEqual(api.verify_code(self.users[24], "000000", request_from("2001:db8:1:3::1"), method="totp").reason, "locked")

    def test_ip_group(self):
        self.assertEqual(clientip.ip_group("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), "2001:db8:1:2::/64")
        self.assertEqual(clientip.ip_group("192.0.2.1"), "192.0.2.1")
        with override_settings(TOTP_IPV6_PREFIX=48):
            self.assertEqual(clientip.ip_group("2001:db8:1:2::1"), "2001:db8:1::/48")

    def test_allowlist_bypasses_ip_throttling_not_user_limits(self):
        request = request_from("192.0.2.77")
        with override_settings(TOTP_IP_ALLOWLIST=["192.0.2.0/24"]):
            for u in self.users[:24]:
                self.assertEqual(fail(u, request).reason, "invalid")
            self.assertFalse(Lockout.objects.filter(scope="ip").exists())
            self.assertEqual(fail(self.users[0], request, n=10).reason, "locked")  # user limit still applies

    def test_denylist(self):
        request = request_from("203.0.113.50")
        user = self.users[0]
        with override_settings(TOTP_IP_DENYLIST=["203.0.113.0/24"]):
            result = api.verify_code(user, code_for(user.totp_devices.first()), request)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "denied")
        self.assertEqual(result.message, api.VerifyResult(False, "", "invalid").message)

    def test_denylisted_ip_cannot_pass_the_login_view(self):
        client = Client(REMOTE_ADDR="203.0.113.50")
        with override_settings(TOTP_IP_DENYLIST=["203.0.113.0/24"]):
            r = login(client, self.users[0])
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("_auth_user_id", client.session)


class ClientIpTests(TestCase):
    def ip(self, remote, forwarded=None, **settings_):
        meta = {"REMOTE_ADDR": remote}
        if forwarded is not None:
            meta["HTTP_X_FORWARDED_FOR"] = forwarded
        with override_settings(**settings_):
            return clientip.client_ip(RequestFactory().get("/", **meta))

    def test_header_ignored_without_trusted_proxies(self):
        self.assertEqual(self.ip("203.0.113.5", "1.2.3.4"), "203.0.113.5")

    def test_header_ignored_from_untrusted_peer(self):
        self.assertEqual(self.ip("203.0.113.5", "1.2.3.4", TOTP_TRUSTED_PROXIES=["10.0.0.0/8"]), "203.0.113.5")

    def test_header_used_from_trusted_proxy(self):
        self.assertEqual(self.ip("10.0.0.5", "1.2.3.4", TOTP_TRUSTED_PROXIES=["10.0.0.0/8"]), "1.2.3.4")

    def test_spoofed_leftmost_entries_are_ignored(self):
        self.assertEqual(self.ip("10.0.0.5", "6.6.6.6, 1.2.3.4", TOTP_TRUSTED_PROXIES=["10.0.0.0/8"]), "1.2.3.4")
        self.assertEqual(self.ip("10.0.0.5", "6.6.6.6, 1.2.3.4, 10.0.0.9", TOTP_TRUSTED_PROXIES=["10.0.0.0/8"]), "1.2.3.4")

    def test_garbage_header_falls_back_to_the_socket(self):
        self.assertEqual(self.ip("10.0.0.5", "not-an-ip", TOTP_TRUSTED_PROXIES=["10.0.0.0/8"]), "10.0.0.5")
        self.assertEqual(self.ip("10.0.0.5", "1.2.3.4, garbage", TOTP_TRUSTED_PROXIES=["10.0.0.0/8"]), "10.0.0.5")

    def test_custom_header_and_ipv6_proxy(self):
        request = RequestFactory().get("/", REMOTE_ADDR="2001:db8::1", HTTP_X_REAL_IP="198.51.100.4")
        with override_settings(TOTP_TRUSTED_PROXIES=["2001:db8::/32"], TOTP_CLIENT_IP_HEADER="X-Real-IP"):
            self.assertEqual(clientip.client_ip(request), "198.51.100.4")

    def test_ipv4_mapped_ipv6(self):
        self.assertEqual(self.ip("::ffff:192.0.2.9"), "192.0.2.9")

    def test_custom_resolver(self):
        self.assertEqual(self.ip("1.1.1.1", TOTP_IP_RESOLVER=lambda request: "9.9.9.9"), "9.9.9.9")

    def test_anonymize_and_privacy_flags(self):
        self.assertEqual(clientip.anonymize("192.0.2.77"), "192.0.2.0")
        self.assertEqual(clientip.anonymize("2001:db8:1:2:3:4:5:6"), "2001:db8:1::")
        request = RequestFactory().get("/", REMOTE_ADDR="192.0.2.77", HTTP_USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0")
        user = make_user("priv")
        from dj_totp_2fa import events
        with override_settings(TOTP_ANONYMIZE_IP=True):
            self.assertEqual(events.record("failed", request, user=user).ip, "192.0.2.0")
        with override_settings(TOTP_STORE_IP=False, TOTP_STORE_USER_AGENT=False):
            e = events.record("failed", request, user=user)
            self.assertIsNone(e.ip)
            self.assertEqual(e.user_agent, "")
        e = events.record("failed", request, user=user)
        self.assertEqual(e.ip, "192.0.2.77")
        self.assertIn("Firefox", e.user_agent)

    def test_spoofed_header_does_not_dodge_ip_limit(self):
        users = []
        for i in range(21):
            u = make_user("s%d" % i)
            enable(u)
            users.append(u)
        for i, u in enumerate(users[:20]):
            request = RequestFactory().post("/", REMOTE_ADDR="203.0.113.5", HTTP_X_FORWARDED_FOR="9.9.9.%d" % i)
            fail(u, request)
        self.assertTrue(Lockout.objects.filter(scope="ip").exists())


class CircuitBreakerTests(TestCase):
    def setUp(self):
        cache.clear()

    def test_global_threshold_opens_the_breaker(self):
        alerts = []
        users = []
        for i in range(8):
            u = make_user("g%d" % i)
            enable(u)
            users.append(u)
        with override_settings(TOTP_GLOBAL_FAILURE_THRESHOLD=6, TOTP_STAFF_ALERT=lambda e, d: alerts.append(e)):
            for i, u in enumerate(users[:6]):
                fail(u, request_from("198.51.100.%d" % (i + 1)))
            self.assertTrue(ratelimit.circuit_open())
        self.assertIn("global_alert", alerts)
        self.assertTrue(TwoFactorEvent.objects.filter(event="global_alert").exists())

    def test_challenge_hook_runs_while_open(self):
        user = make_user("c")
        device = enable(user)
        calls = []

        def challenge(request, u):
            calls.append(u.pk)
            return False

        with override_settings(TOTP_GLOBAL_FAILURE_THRESHOLD=2, TOTP_CHALLENGE=challenge):
            fail(user, n=2)
            self.assertTrue(ratelimit.circuit_open())
            result = api.verify_code(user, code_for(device))
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "throttled")
        self.assertEqual(calls, [user.pk])

    def test_challenge_not_called_while_closed(self):
        user = make_user("c2")
        device = enable(user)
        with override_settings(TOTP_CHALLENGE=lambda r, u: False):
            self.assertTrue(api.verify_code(user, code_for(device)).ok)

    def test_breaker_disabled_with_zero(self):
        user = make_user("c3")
        enable(user)
        with override_settings(TOTP_GLOBAL_FAILURE_THRESHOLD=0):
            fail(user, n=5)
            self.assertFalse(ratelimit.circuit_open())


class EndpointAndPageTests(TotpCase):
    def test_verify_endpoint_throttle_returns_429_with_retry_after(self):
        login(self.client, self.user)
        with override_settings(TOTP_ENDPOINT_RATE_LIMITS={"verify": (3, 60)}):
            for _ in range(3):
                self.assertEqual(self.client.post(reverse("dj_totp_2fa:verify"), {"code": "000000"}).status_code, 200)
            r = self.client.post(reverse("dj_totp_2fa:verify"), {"code": "000000"})
        self.assertEqual(r.status_code, 429)
        self.assertGreaterEqual(int(r["Retry-After"]), 1)
        self.assertContains(r, "data-retry-after", status_code=429)
        self.assertContains(r, "Too many attempts", status_code=429)

    def test_recovery_endpoint_has_its_own_budget(self):
        login(self.client, self.user)
        with override_settings(TOTP_ENDPOINT_RATE_LIMITS={"verify": (100, 60), "recovery": (2, 60)}):
            for _ in range(2):
                self.client.post(reverse("dj_totp_2fa:verify_recovery"), {"code": "AAAAA-BBBBB", "method": "recovery"})
            r = self.client.post(reverse("dj_totp_2fa:verify_recovery"), {"code": "AAAAA-BBBBB", "method": "recovery"})
            self.assertEqual(r.status_code, 429)
            self.assertEqual(self.client.post(reverse("dj_totp_2fa:verify"), {"code": "000000"}).status_code, 200)

    def test_locked_account_shows_countdown_page(self):
        login(self.client, self.user)
        fail(self.user, n=10)
        r = self.client.get(reverse("dj_totp_2fa:verify"))
        self.assertEqual(r.status_code, 429)
        self.assertIn("Retry-After", r)
        self.assertContains(r, "data-countdown", status_code=429)
        self.assertContains(r, "<fieldset disabled", status_code=429)
        r = self.client.post(reverse("dj_totp_2fa:verify"), {"code": code_for(self.device)})
        self.assertEqual(r.status_code, 429)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_failures_through_the_view_lock_the_account(self):
        for i in range(10):
            client = Client()
            login(client, self.user)
            client.post(reverse("dj_totp_2fa:verify"), {"code": "00000%d" % (i % 10)})
        r = Client()
        login(r, self.user)
        resp = r.post(reverse("dj_totp_2fa:verify"), {"code": code_for(self.device)})
        self.assertEqual(resp.status_code, 429)

    def test_fail_delay(self):
        with override_settings(TOTP_FAIL_DELAY_MS=80):
            started = time.monotonic()
            api.verify_code(self.user, "000000")
            self.assertGreaterEqual(time.monotonic() - started, 0.06)
            started = time.monotonic()
            api.verify_code(self.user, code_for(self.device))
            self.assertLess(time.monotonic() - started, 0.06)  # success is not delayed


class HoneypotTests(TotpCase):
    def post(self, **extra):
        login(self.client, self.user)
        return self.client.post(reverse("dj_totp_2fa:verify"), dict({"code": code_for(self.device)}, **extra))

    def test_filled_honeypot_fails_even_with_the_right_code(self):
        r = self.post(website="http://spam.example")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "did not work")
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertTrue(TwoFactorEvent.objects.filter(event="bot_suspected").exists())

    def test_empty_honeypot_is_fine_and_field_is_rendered_hidden(self):
        r = self.post(website="")
        self.assertEqual(r.status_code, 302)
        login(Client(), self.user)

    def test_honeypot_name_and_disable(self):
        with override_settings(TOTP_HONEYPOT_FIELD="nickname"):
            login(self.client, self.user)
            page = self.client.get(reverse("dj_totp_2fa:verify"))
            self.assertContains(page, 'name="nickname"')
            self.assertNotContains(page, 'name="website"')
        with override_settings(TOTP_HONEYPOT_FIELD=""):
            page = self.client.get(reverse("dj_totp_2fa:verify"))
            self.assertNotContains(page, "totp-hp")
            r = self.client.post(reverse("dj_totp_2fa:verify"), {"code": code_for(self.device), "website": "x"})
            self.assertEqual(r.status_code, 302)

    def test_min_time_to_submit(self):
        with override_settings(TOTP_MIN_SUBMIT_SECONDS=2):
            login(self.client, self.user)
            page = self.client.get(reverse("dj_totp_2fa:verify"))
            token = page.context["form_token"]
            r = self.client.post(reverse("dj_totp_2fa:verify"), {"code": code_for(self.device), "form_token": token})
            self.assertEqual(r.status_code, 200)  # too fast
            self.assertNotIn("_auth_user_id", self.client.session)
            r = self.client.post(reverse("dj_totp_2fa:verify"), {"code": code_for(self.device)})  # no token at all
            self.assertEqual(r.status_code, 200)
            r = self.client.post(reverse("dj_totp_2fa:verify"), {"code": code_for(self.device), "form_token": "forged"})
            self.assertEqual(r.status_code, 200)
            with mock.patch("dj_totp_2fa.ui.time.time", return_value=time.time() + 5):
                r = self.client.post(reverse("dj_totp_2fa:verify"), {"code": code_for(self.device), "form_token": token})
            self.assertEqual(r.status_code, 302)
