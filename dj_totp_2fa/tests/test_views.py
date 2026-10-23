import re

from django.core import mail
from django.test import Client, override_settings
from django.urls import reverse
from django.utils import timezone

from dj_totp_2fa import api, session as sess, totp as core
from dj_totp_2fa.models import RecoveryCode, TOTPDevice, TrustedBrowser, TwoFactorEvent

from .base import PASSWORD, TotpCase, code_for, enable, login, make_user, verified_client


def url(name, *args):
    return reverse("dj_totp_2fa:" + name, args=args)


def code_for_secret(secret_b32, offset=0, digits=6):
    return core.hotp(core.b32decode(secret_b32), core.time_step(None, 30) + offset, digits, "SHA1")


class LoginRequiredTests(TotpCase):
    def test_every_account_page_requires_login(self):
        for name, args in (("overview", ()), ("setup", ()), ("devices", ()), ("recovery", ()), ("disable", ()), ("trusted", ()),
                           ("add_device", ()), ("rename_device", (self.device.pk,)), ("remove_device", (self.device.pk,)), ("done", ())):
            r = Client().get(url(name, *args))
            self.assertEqual(r.status_code, 302, name)
            self.assertIn("/account/2fa/login/", r["Location"], name)

    def test_unverified_sessions_cannot_manage_an_enabled_account(self):
        self.client.force_login(self.user)
        for name in ("devices", "recovery", "disable", "trusted", "overview"):
            r = self.client.get(url(name))
            self.assertEqual(r.status_code, 302, name)
            self.assertIn("/verify/", r["Location"], name)
        r = self.client.post(url("disable"), {"password": PASSWORD, "confirm": "1"})
        self.assertEqual(r.status_code, 302)
        self.assertTrue(TOTPDevice.objects.filter(user=self.user, confirmed=True).exists())


class SetupWizardTests(TotpCase):
    def setUp(self):
        super().setUp()
        self.user2 = make_user("newbie")
        self.c = Client()
        self.c.force_login(self.user2)

    def secret_from(self, response):
        return self.c.session[sess.SETUP_KEY]["secret"]

    def test_page_shows_qr_data_manual_key_and_deep_link(self):
        r = self.c.get(url("setup"))
        self.assertEqual(r.status_code, 200)
        secret = self.secret_from(r)
        self.assertContains(r, 'data-uri="otpauth://totp/')
        self.assertContains(r, "secret=" + secret)
        self.assertContains(r, " ".join(secret[i:i + 4] for i in range(0, 32, 4)))
        self.assertContains(r, 'href="otpauth://totp/')
        self.assertContains(r, "js/vendor/qrcode.min.js")
        for app in ("Google Authenticator", "Microsoft Authenticator", "Authy", "1Password", "Aegis", "Bitwarden"):
            self.assertContains(r, app)
        self.assertEqual(TOTPDevice.objects.filter(user=self.user2).count(), 0)  # nothing persisted before confirmation

    def test_wrong_code_does_not_create_a_device(self):
        self.c.get(url("setup"))
        r = self.c.post(url("setup"), {"code": "000000", "name": "Phone"})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "did not match")
        self.assertEqual(TOTPDevice.objects.filter(user=self.user2).count(), 0)
        self.assertIn(sess.SETUP_KEY, self.c.session)  # same secret is kept so the user can retry

    def test_full_setup_confirms_and_shows_recovery_codes_once(self):
        self.c.get(url("setup"))
        secret = self.c.session[sess.SETUP_KEY]["secret"]
        r = self.c.post(url("setup"), {"code": code_for_secret(secret), "name": "My phone", "next": "/private/"})
        self.assertEqual(r.status_code, 200)
        codes = re.findall(r"<code>([A-Z2-9]{5}-[A-Z2-9]{5})</code>", r.content.decode())
        self.assertEqual(len(codes), 10)
        self.assertContains(r, "only time")
        self.assertContains(r, "data-download-codes")
        self.assertContains(r, "data-print")
        self.assertContains(r, 'data-copy-codes')
        self.assertIn("no-store", r["Cache-Control"])
        device = TOTPDevice.objects.get(user=self.user2)
        self.assertTrue(device.confirmed and device.primary)
        self.assertEqual(device.name, "My phone")
        self.assertTrue(sess.is_verified(r.wsgi_request))
        self.assertNotIn(sess.SETUP_KEY, self.c.session)
        self.assertContains(r, "/account/2fa/done/?next=%2Fprivate%2F")
        # the codes verify, and are stored only hashed
        self.assertTrue(api.verify_code(self.user2, codes[0]).ok)
        self.assertFalse(any(codes[1].replace("-", "") in h for h in RecoveryCode.objects.values_list("code_hash", flat=True)))
        # they are never shown again
        later = self.c.get(url("recovery"))
        self.assertNotContains(later, codes[1])

    def test_setup_events_and_email(self):
        self.c.get(url("setup"))
        secret = self.c.session[sess.SETUP_KEY]["secret"]
        self.c.post(url("setup"), {"code": code_for_secret(secret)})
        names = set(TwoFactorEvent.objects.filter(user=self.user2).values_list("event", flat=True))
        self.assertTrue({"setup_started", "device_added", "recovery_regenerated"} <= names)
        self.assertTrue(any("new authenticator" in m.subject for m in mail.outbox))

    def test_restart_generates_a_new_secret(self):
        self.c.get(url("setup"))
        first = self.c.session[sess.SETUP_KEY]["secret"]
        self.c.post(url("setup"), {"action": "restart"})
        self.assertNotEqual(self.c.session[sess.SETUP_KEY]["secret"], first)

    def test_stale_setup_state_is_replaced(self):
        self.c.get(url("setup"))
        session = self.c.session
        first = session[sess.SETUP_KEY]["secret"]
        session[sess.SETUP_KEY]["t"] -= 4000
        session.save()
        self.c.get(url("setup"))
        self.assertNotEqual(self.c.session[sess.SETUP_KEY]["secret"], first)

    def test_second_device_needs_a_verified_session_and_keeps_codes(self):
        client = verified_client(self.user, self.device)
        api.generate_recovery_codes(self.user)
        client.get(url("add_device"))
        secret = client.session[sess.SETUP_KEY]["secret"]
        r = client.post(url("setup"), {"code": code_for_secret(secret), "name": "Tablet"})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.user.totp_devices.filter(confirmed=True).count(), 2)
        self.assertEqual(api.recovery_codes_remaining(self.user), 10)  # untouched

    def test_max_devices_redirects(self):
        client = verified_client(self.user, self.device)
        with override_settings(TOTP_MAX_DEVICES=1):
            r = client.get(url("setup"))
            self.assertRedirects(r, url("devices"), fetch_redirect_response=False)

    def test_setup_endpoint_throttle(self):
        self.c.get(url("setup"))
        with override_settings(TOTP_ENDPOINT_RATE_LIMITS={"setup": (2, 60)}):
            for _ in range(2):
                self.c.post(url("setup"), {"code": "000000"})
            r = self.c.post(url("setup"), {"code": "000000"})
        self.assertEqual(r.status_code, 429)

    def test_setup_failures_count_towards_lockout(self):
        self.c.get(url("setup"))
        for _ in range(10):
            self.c.post(url("setup"), {"code": "000000"})
        secret = self.c.session[sess.SETUP_KEY]["secret"]
        r = self.c.post(url("setup"), {"code": code_for_secret(secret)})
        self.assertEqual(r.status_code, 429)
        self.assertEqual(TOTPDevice.objects.filter(user=self.user2).count(), 0)

    def test_forced_enrolment_banner(self):
        with override_settings(TOTP_REQUIRED=True):
            r = self.c.get(url("setup"))
        self.assertContains(r, "is required")

    def test_done_page(self):
        r = self.c.get(url("done") + "?next=https://evil.example/")
        self.assertNotContains(r, "evil.example")
        self.assertContains(r, "protected")


class DeviceManagementTests(TotpCase):
    def setUp(self):
        super().setUp()
        self.c = verified_client(self.user, self.device)

    def test_devices_page_lists_devices_with_dialogs(self):
        r = self.c.get(url("devices"))
        self.assertContains(r, "<dialog")
        self.assertContains(r, self.device.name)
        self.assertContains(r, 'data-dialog-open="rename-%d"' % self.device.pk)

    def test_rename_requires_reauth(self):
        r = self.c.post(url("rename_device", self.device.pk), {"name": "Renamed", "password": "wrong"})
        self.assertContains(r, "not correct")
        self.device.refresh_from_db()
        self.assertEqual(self.device.name, "Phone")
        r = self.c.post(url("rename_device", self.device.pk), {"name": "Renamed", "password": PASSWORD})
        self.assertRedirects(r, url("devices"), fetch_redirect_response=False)
        self.device.refresh_from_db()
        self.assertEqual(self.device.name, "Renamed")

    def test_rename_with_a_code_instead_of_password(self):
        r = self.c.post(url("rename_device", self.device.pk), {"name": "ByCode", "code": code_for(self.device, 1)})
        self.assertEqual(r.status_code, 302)

    def test_recovery_codes_are_not_accepted_for_reauth(self):
        codes = api.generate_recovery_codes(self.user)
        r = self.c.post(url("rename_device", self.device.pk), {"name": "X", "code": codes[0]})
        self.assertContains(r, "not correct")

    def test_remove_second_device(self):
        second = enable(self.user, name="Tablet")
        r = self.c.post(url("remove_device", second.pk), {"password": PASSWORD})
        self.assertRedirects(r, url("devices"), fetch_redirect_response=False)
        self.assertFalse(TOTPDevice.objects.filter(pk=second.pk).exists())
        self.assertTrue(any("removed" in m.subject for m in mail.outbox))
        self.assertTrue(TwoFactorEvent.objects.filter(event="device_removed").exists())

    def test_last_device_cannot_be_removed(self):
        r = self.c.post(url("remove_device", self.device.pk), {"password": PASSWORD})
        self.assertRedirects(r, url("disable"), fetch_redirect_response=False)
        self.assertTrue(TOTPDevice.objects.filter(pk=self.device.pk).exists())

    def test_nojs_confirmation_pages(self):
        self.assertContains(self.c.get(url("rename_device", self.device.pk)), "Rename device")
        self.assertContains(self.c.get(url("remove_device", self.device.pk)), "turn off two-step verification")

    def test_cannot_touch_someone_elses_device(self):
        other = make_user("other")
        theirs = enable(other)
        self.assertEqual(self.c.get(url("rename_device", theirs.pk)).status_code, 404)
        self.assertEqual(self.c.post(url("remove_device", theirs.pk), {"password": PASSWORD}).status_code, 404)

    def test_reauth_failures_lock_out(self):
        for _ in range(10):
            self.c.post(url("rename_device", self.device.pk), {"name": "x", "password": "nope"})
        r = self.c.post(url("rename_device", self.device.pk), {"name": "x", "password": PASSWORD})
        self.assertEqual(r.status_code, 429)

    def test_form_without_credentials_is_rejected(self):
        r = self.c.post(url("rename_device", self.device.pk), {"name": "x"})
        self.assertContains(r, "Enter")


class RecoveryPageTests(TotpCase):
    def setUp(self):
        super().setUp()
        self.codes = api.generate_recovery_codes(self.user)
        self.c = verified_client(self.user, self.device)

    def test_page_shows_counts_only(self):
        r = self.c.get(url("recovery"))
        self.assertContains(r, "<strong>10</strong>")
        self.assertNotContains(r, self.codes[0])

    def test_regenerate_needs_reauth_and_replaces_codes(self):
        r = self.c.post(url("recovery"), {"password": "nope"})
        self.assertContains(r, "not correct")
        self.assertTrue(api.verify_code(self.user, self.codes[2]).ok is True)
        r = self.c.post(url("recovery"), {"password": PASSWORD})
        new = re.findall(r"<code>([A-Z2-9]{5}-[A-Z2-9]{5})</code>", r.content.decode())
        self.assertEqual(len(new), 10)
        self.assertFalse(api.verify_code(self.user, self.codes[3]).ok)
        self.assertTrue(api.verify_code(self.user, new[0]).ok)
        self.assertTrue(any("regenerated" in m.subject for m in mail.outbox))

    def test_low_codes_badge(self):
        for code in self.codes[:8]:
            api.verify_code(self.user, code)
        self.assertContains(self.c.get(url("recovery")), "Running low")


class DisableTests(TotpCase):
    def setUp(self):
        super().setUp()
        api.generate_recovery_codes(self.user)
        self.c = verified_client(self.user, self.device)

    def test_confirmation_page(self):
        r = self.c.get(url("disable"))
        self.assertContains(r, 'name="confirm"')

    def test_requires_confirm_box_and_reauth(self):
        r = self.c.post(url("disable"), {"password": PASSWORD})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(api.is_enabled(self.user))
        r = self.c.post(url("disable"), {"password": "wrong", "confirm": "1"})
        self.assertContains(r, "not correct")
        self.assertTrue(api.is_enabled(self.user))

    def test_disable_removes_everything_and_notifies(self):
        TrustedBrowser.objects.create(user=self.user, token_hash="x" * 64, expires_at=timezone.now() + timezone.timedelta(days=1))
        self.c.cookies["dj_totp_trusted"] = "abc"
        r = self.c.post(url("disable"), {"password": PASSWORD, "confirm": "1"})
        self.assertRedirects(r, url("overview"), fetch_redirect_response=False)
        self.assertFalse(api.is_enabled(self.user))
        self.assertEqual(RecoveryCode.objects.filter(user=self.user).count(), 0)
        self.assertEqual(TrustedBrowser.objects.filter(user=self.user).count(), 0)
        self.assertEqual(r.cookies["dj_totp_trusted"].value, "")
        self.assertTrue(any("turned off" in m.subject for m in mail.outbox))
        self.assertTrue(TwoFactorEvent.objects.filter(event="disabled", user=self.user).exists())


class TrustedPageTests(TotpCase):
    def setUp(self):
        super().setUp()
        self.c = Client()
        login(self.c, self.user)
        self.c.post(url("verify"), {"code": code_for(self.device), "trust": "1"})

    def test_list_marks_this_browser(self):
        r = self.c.get(url("trusted"))
        self.assertContains(r, "This browser")
        self.assertContains(r, "Revoke")

    def test_revoke_one_and_all(self):
        row = TrustedBrowser.objects.get()
        other = TrustedBrowser.objects.create(user=self.user, token_hash="y" * 64, expires_at=row.expires_at)
        self.c.post(url("trusted_revoke", other.pk))
        self.assertEqual(TrustedBrowser.objects.count(), 1)
        r = self.c.post(url("trusted_revoke_all"))
        self.assertEqual(TrustedBrowser.objects.count(), 0)
        self.assertEqual(r.cookies["dj_totp_trusted"].value, "")

    def test_cannot_revoke_someone_elses(self):
        other_user = make_user("zed")
        theirs = TrustedBrowser.objects.create(user=other_user, token_hash="z" * 64, expires_at=timezone.now() + timezone.timedelta(days=1))
        self.assertEqual(self.c.post(url("trusted_revoke", theirs.pk)).status_code, 404)
        self.assertTrue(TrustedBrowser.objects.filter(pk=theirs.pk).exists())


class OverviewTests(TotpCase):
    def test_enabled_overview(self):
        api.generate_recovery_codes(self.user)
        c = verified_client(self.user, self.device)
        r = c.get(url("overview"))
        self.assertContains(r, "Your account is protected")
        self.assertContains(r, "Recent security activity")
        self.assertContains(r, "10 remaining")

    def test_disabled_overview(self):
        other = make_user("bare")
        c = Client()
        c.force_login(other)
        r = c.get(url("overview"))
        self.assertContains(r, "Add a second layer of security")
        self.assertContains(r, url("setup"))
