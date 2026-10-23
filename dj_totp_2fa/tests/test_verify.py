import threading
from unittest import mock

from django.core import mail
from django.db import connection
from django.test import override_settings

from dj_totp_2fa import api, totp as core
from dj_totp_2fa.models import RecoveryCode, TOTPDevice, TwoFactorEvent
from dj_totp_2fa.signals import totp_failed, totp_recovery_code_used, totp_verified

from .base import TotpCase, TotpTransactionCase, code_for, enable, make_user, next_code

STEP = 1_000_000


def frozen(step=STEP):
    return mock.patch("dj_totp_2fa.totp.time_step", side_effect=lambda for_time=None, period=30: step)


class VerifyBasicsTests(TotpCase):
    def test_valid_code_succeeds(self):
        result = api.verify_code(self.user, code_for(self.device))
        self.assertTrue(result.ok)
        self.assertEqual(result.method, "totp")
        self.assertTrue(result)
        self.assertEqual(result.device, self.device)

    def test_wrong_code_fails_generically(self):
        good = code_for(self.device)
        bad = "%06d" % ((int(good) + 1) % 10 ** 6)
        result = api.verify_code(self.user, bad)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "invalid")
        self.assertIn("did not work", result.message)

    def test_formatting_is_forgiven(self):
        code = code_for(self.device)
        self.assertTrue(api.verify_code(self.user, " %s-%s " % (code[:3], code[3:])).ok)

    def test_malformed_codes_fail(self):
        for bad in ("", "abc", "12345", "1234567", "12 34 5x", None):
            self.assertFalse(api.verify_code(self.user, bad, method="totp").ok, bad)

    def test_unconfirmed_device_is_ignored(self):
        user = make_user("bob")
        device = api.create_device(user)
        self.assertFalse(api.verify_code(user, code_for(device)).ok)
        self.assertFalse(api.is_enabled(user))

    def test_unknown_inactive_and_anonymous_users(self):
        self.assertFalse(api.verify_code(None, "123456").ok)
        self.user.is_active = False
        self.user.save()
        self.assertFalse(api.verify_code(self.user, code_for(self.device)).ok)

    def test_failure_count_and_reset(self):
        api.verify_code(self.user, "000000")
        api.verify_code(self.user, "111111")
        self.device.refresh_from_db()
        self.assertGreaterEqual(self.device.failure_count, 1)
        self.assertTrue(api.verify_code(self.user, code_for(self.device)).ok)
        self.device.refresh_from_db()
        self.assertEqual(self.device.failure_count, 0)

    def test_events_recorded(self):
        api.verify_code(self.user, "000000")
        api.verify_code(self.user, code_for(self.device))
        names = list(TwoFactorEvent.objects.filter(user=self.user).values_list("event", flat=True))
        self.assertIn("failed", names)
        self.assertIn("verified", names)

    def test_submitted_code_never_logged_or_stored(self):
        with self.assertLogs("dj_totp_2fa", level="DEBUG") as logs:
            api.verify_code(self.user, "987654")
        self.assertNotIn("987654", "\n".join(logs.output))
        for event in TwoFactorEvent.objects.all():
            self.assertNotIn("987654", str(event.details))


class ReplayTests(TotpCase):
    def test_same_code_twice_is_refused(self):
        code = code_for(self.device)
        self.assertTrue(api.verify_code(self.user, code).ok)
        second = api.verify_code(self.user, code)
        self.assertFalse(second.ok)
        self.assertEqual(second.reason, "replay")

    def test_next_step_code_is_accepted_after_use(self):
        with frozen():
            self.assertTrue(api.verify_code(self.user, code_for(self.device)).ok)
            self.assertTrue(api.verify_code(self.user, next_code(self.device)).ok)

    def test_earlier_step_refused_after_later_used(self):
        with frozen():
            self.assertTrue(api.verify_code(self.user, code_for(self.device)).ok)
            older = code_for(self.device, -1)
            self.assertFalse(api.verify_code(self.user, older).ok)

    def test_last_used_step_is_stored(self):
        with frozen():
            api.verify_code(self.user, code_for(self.device, 1))
        self.device.refresh_from_db()
        self.assertEqual(self.device.last_used_step, STEP + 1)

    def test_claim_is_atomic_for_two_racing_requests(self):
        """Both requests computed the same step before either wrote: only one UPDATE may win."""
        with frozen():
            code = code_for(self.device)
            step, offset = api._device_step(self.device, code)
            self.assertTrue(api._claim_step(self.device, step, offset))
            self.assertFalse(api._claim_step(self.device, step, offset))

    def test_lost_race_is_reported_as_replay(self):
        code = code_for(self.device)
        original = api._claim_step

        def racing(device, step, offset):
            TOTPDevice.objects.filter(pk=device.pk).update(last_used_step=step)  # the "other request" got there first
            return original(device, step, offset)

        with mock.patch.object(api, "_claim_step", side_effect=racing):
            result = api.verify_code(self.user, code)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "replay")


class ConcurrentReplayTests(TotpTransactionCase):
    def test_two_threads_cannot_both_use_one_code(self):
        if connection.vendor == "sqlite":
            # shared-cache in-memory SQLite serialises writers with table locks; lock errors count as "not accepted"
            pass
        code = code_for(self.device)
        barrier = threading.Barrier(4)
        results = []

        def attempt():
            from django.db import connection as conn
            try:
                barrier.wait(5)
                results.append(api.verify_code(self.user, code).ok)
            except Exception:
                results.append(False)
            finally:
                conn.close()

        threads = [threading.Thread(target=attempt) for _ in range(4)]
        [t.start() for t in threads]
        [t.join(15) for t in threads]
        self.assertLessEqual(sum(results), 1)
        self.assertEqual(len(results), 4)


class WindowTests(TotpCase):
    def check(self, offset, **settings_):
        self._n = getattr(self, "_n", 0) + 1
        user = make_user("w%d" % self._n)
        device = enable(user, name="d")
        with frozen(), override_settings(**settings_):
            return api.verify_code(user, code_for(device, offset)).ok

    def test_default_window_is_one(self):
        self.assertTrue(self.check(0))
        self.assertTrue(self.check(-1))
        self.assertTrue(self.check(1))
        self.assertFalse(self.check(-2))
        self.assertFalse(self.check(2))
        self.assertFalse(self.check(5))

    def test_window_zero(self):
        self.assertTrue(self.check(0, TOTP_WINDOW=0))
        self.assertFalse(self.check(1, TOTP_WINDOW=0))
        self.assertFalse(self.check(-1, TOTP_WINDOW=0))

    def test_window_two_and_cap(self):
        self.assertTrue(self.check(2, TOTP_WINDOW=2))
        self.assertTrue(self.check(-2, TOTP_WINDOW=2))
        self.assertFalse(self.check(3, TOTP_WINDOW=2))
        self.assertFalse(self.check(3, TOTP_WINDOW=9))  # capped at 2

    def test_per_device_window(self):
        user = make_user("wd")
        device = enable(user)
        TOTPDevice.objects.filter(pk=device.pk).update(window=0)
        device.refresh_from_db()
        with frozen():
            self.assertFalse(api.verify_code(user, code_for(device, 1)).ok)
            self.assertTrue(api.verify_code(user, code_for(device, 0)).ok)


class DriftTests(TotpCase):
    def test_no_resync_by_default(self):
        with frozen():
            api.verify_code(self.user, code_for(self.device, 1))
        self.device.refresh_from_db()
        self.assertEqual(self.device.drift_steps, 0)

    def test_resync_follows_phone_clock_with_cap(self):
        with override_settings(TOTP_ALLOW_DRIFT_RESYNC=True, TOTP_DRIFT_RESYNC_MAX=2, TOTP_WINDOW=2):
            with frozen(STEP):
                self.assertTrue(api.verify_code(self.user, code_for(self.device, 1)).ok)
            self.device.refresh_from_db()
            self.assertEqual(self.device.drift_steps, 1)
            with frozen(STEP + 5):  # phone is consistently one step ahead: now it matches at offset 0
                self.assertTrue(api.verify_code(self.user, code_for(self.device, 1)).ok)
            self.device.refresh_from_db()
            self.assertEqual(self.device.drift_steps, 1)
            with frozen(STEP + 10):
                self.assertTrue(api.verify_code(self.user, code_for(self.device, 3)).ok)
            self.device.refresh_from_db()
            self.assertEqual(self.device.drift_steps, 2)  # capped


class AlgorithmTests(TotpCase):
    def test_all_hash_modes_and_digit_counts(self):
        for algorithm in ("SHA1", "SHA256", "SHA512"):
            for digits in (6, 7, 8):
                user = make_user("u-%s-%d" % (algorithm, digits))
                device = enable(user, algorithm=algorithm, digits=digits, period=30)
                code = code_for(device)
                self.assertEqual(len(code), digits)
                self.assertTrue(api.verify_code(user, code).ok, (algorithm, digits))

    def test_custom_period(self):
        user = make_user("p15")
        device = enable(user, period=15)
        self.assertTrue(api.verify_code(user, code_for(device)).ok)


class RecoveryVerifyTests(TotpCase):
    def setUp(self):
        super().setUp()
        self.codes = api.generate_recovery_codes(self.user)

    def test_code_works_once(self):
        result = api.verify_code(self.user, self.codes[0])
        self.assertTrue(result.ok)
        self.assertEqual(result.method, "recovery")
        self.assertFalse(api.verify_code(self.user, self.codes[0]).ok)
        self.assertEqual(api.recovery_codes_remaining(self.user), 9)
        row = RecoveryCode.objects.filter(user=self.user, used_at__isnull=False).get()
        self.assertEqual(row.used_ip, None)

    def test_forgiving_format(self):
        self.assertTrue(api.verify_code(self.user, self.codes[1].lower().replace("-", " ")).ok)

    def test_wrong_and_foreign_codes(self):
        other = make_user("carol")
        enable(other)
        foreign = api.generate_recovery_codes(other)
        self.assertFalse(api.verify_code(self.user, foreign[0]).ok)
        self.assertFalse(api.verify_code(self.user, "AAAAA-BBBBB").ok)
        self.assertFalse(api.verify_code(self.user, "SHORT").ok)

    def test_disabled_by_setting(self):
        with override_settings(TOTP_ALLOW_RECOVERY_CODES=False):
            result = api.verify_code(self.user, self.codes[0])
        self.assertFalse(result.ok)
        self.assertEqual(api.recovery_codes_remaining(self.user), 10)

    def test_notifications_and_low_warning(self):
        for code in self.codes[:7]:
            api.verify_code(self.user, code)
        subjects = [m.subject for m in mail.outbox]
        self.assertEqual(sum("recovery code was used" in s for s in subjects), 7)
        self.assertTrue(any("running low" in s for s in subjects))

    def test_signal(self):
        seen = []
        receiver = lambda sender, **kw: seen.append(kw["remaining"])  # noqa: E731
        totp_recovery_code_used.connect(receiver)
        try:
            api.verify_code(self.user, self.codes[0])
        finally:
            totp_recovery_code_used.disconnect(receiver)
        self.assertEqual(seen, [9])

    def test_explicit_method_is_respected(self):
        code = code_for(self.device)
        self.assertFalse(api.verify_code(self.user, code, method="recovery").ok)
        self.assertTrue(api.verify_code(self.user, code, method="totp").ok)


class HooksTests(TotpCase):
    def test_signals_and_hooks(self):
        calls = []
        ok = lambda sender, **kw: calls.append(("ok", kw["method"]))  # noqa: E731
        bad = lambda sender, **kw: calls.append(("bad", kw["reason"]))  # noqa: E731
        totp_verified.connect(ok)
        totp_failed.connect(bad)
        try:
            with override_settings(TOTP_ON_VERIFIED=["dj_totp_2fa.tests.test_verify.on_ok"], TOTP_ON_FAILED=[lambda u, r, why: calls.append(("hook-bad", why))]):
                api.verify_code(self.user, "000000")
                api.verify_code(self.user, code_for(self.device))
        finally:
            totp_verified.disconnect(ok)
            totp_failed.disconnect(bad)
        self.assertIn(("bad", "invalid"), calls)
        self.assertIn(("ok", "totp"), calls)
        self.assertIn(("hook-bad", "invalid"), calls)
        self.assertIn(("hook-ok", "totp"), HOOK_LOG)

    def test_rules_veto_without_counting(self):
        with override_settings(TOTP_RULES=[lambda user, request: False]):
            result = api.verify_code(self.user, code_for(self.device))
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "vetoed")
        self.device.refresh_from_db()
        self.assertEqual(self.device.failure_count, 0)
        self.assertEqual(self.device.last_used_step, 0)  # the code was not consumed

    def test_code_validator(self):
        with override_settings(TOTP_CODE_VALIDATOR=lambda user, code, request: False):
            self.assertFalse(api.verify_code(self.user, code_for(self.device)).ok)
        self.device.refresh_from_db()
        self.assertEqual(self.device.last_used_step, 0)
        with override_settings(TOTP_CODE_VALIDATOR=lambda user, code, request: True):
            self.assertTrue(api.verify_code(self.user, code_for(self.device)).ok)


HOOK_LOG = []


def on_ok(user, request, method):
    HOOK_LOG.append(("hook-ok", method))


class SetupConfirmTests(TotpCase):
    def test_confirm_device_flow(self):
        user = make_user("dave")
        device = api.create_device(user, "Laptop")
        self.assertFalse(device.confirmed)
        bad = api.confirm_device(device, "000000")
        self.assertFalse(bad.ok)
        good = api.confirm_device(device, code_for(device))
        self.assertTrue(good.ok)
        device.refresh_from_db()
        self.assertTrue(device.confirmed and device.primary and device.confirmed_at)
        self.assertEqual(api.confirm_device(device, code_for(device)).reason, "already_confirmed")

    def test_confirm_secret_creates_device_only_on_success(self):
        user = make_user("erin")
        secret = api.new_secret()
        probe = TOTPDevice(user=user, name="x", **api.default_params())
        probe.secret = secret
        self.assertFalse(api.confirm_secret(user, secret, "000000")[0].ok)
        self.assertEqual(TOTPDevice.objects.filter(user=user).count(), 0)
        result, device = api.confirm_secret(user, secret, code_for(probe), name="Phone")
        self.assertTrue(result.ok)
        self.assertEqual(device.name, "Phone")
        self.assertTrue(device.primary)
        # the code used at confirmation cannot be replayed to log in
        self.assertFalse(api.verify_code(user, code_for(probe)).ok)

    def test_max_devices(self):
        with override_settings(TOTP_MAX_DEVICES=1):
            result, device = api.confirm_secret(self.user, api.new_secret(), "123456")
        self.assertEqual(result.reason, "max_devices")

    def test_unique_names(self):
        a = api.create_device(self.user, "Phone")
        b = api.create_device(self.user, "Phone")
        self.assertNotEqual(a.name, b.name)

    def test_remove_rename_disable_and_export(self):
        api.generate_recovery_codes(self.user)
        data = api.export_user_data(self.user)
        self.assertEqual(data["recovery_codes"]["unused"], 10)
        self.assertNotIn("secret", str(data))
        new_name = api.rename_device(self.device, "Work phone")
        self.assertEqual(new_name, "Work phone")
        api.disable(self.user)
        self.assertFalse(api.is_enabled(self.user))
        self.assertEqual(api.recovery_codes_remaining(self.user), 0)
        self.assertTrue(any("turned off" in m.subject for m in mail.outbox))

    def test_user_deletion_cascades(self):
        api.generate_recovery_codes(self.user)
        api.verify_code(self.user, "000000")
        self.user.delete()
        self.assertEqual(TOTPDevice.objects.count(), 0)
        self.assertEqual(RecoveryCode.objects.count(), 0)
        self.assertEqual(TwoFactorEvent.objects.count(), 0)

    def test_uri_uses_issuer_and_username(self):
        with override_settings(TOTP_ISSUER="Example Co"):
            uri = self.device.uri()
        self.assertTrue(uri.startswith("otpauth://totp/Example%20Co:alice?secret="))
        self.assertIn("issuer=Example%20Co", uri)

    def test_issuer_falls_back_to_host(self):
        from django.test import RequestFactory
        request = RequestFactory().get("/", HTTP_HOST="shop.example.org")
        self.assertEqual(api.get_issuer(request), "shop.example.org")
        with override_settings(TOTP_ACCOUNT_LABEL=lambda u: "custom-" + u.get_username()):
            self.assertEqual(api.account_label(self.user), "custom-alice")
