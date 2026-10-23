import io
import json
from datetime import timedelta
from unittest import mock

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings
from django.utils import timezone

from dj_totp_2fa import api, totp as core
from dj_totp_2fa.models import Lockout, RecoveryCode, TOTPDevice, TrustedBrowser, TwoFactorEvent

from .base import code_for, enable, make_user
from .test_ratelimit import fail


def run(*args, **kwargs):
    out, err = io.StringIO(), io.StringIO()
    call_command(*args, stdout=out, stderr=err, **kwargs)
    return out.getvalue()


class DebugCommandsTests(TestCase):
    def setUp(self):
        from django.core.cache import cache
        cache.clear()
        self.user = make_user("dev")

    def test_enable_test_refuses_without_debug(self):
        with self.assertRaises(CommandError):
            run("totp_enable_test", "dev")
        self.assertFalse(api.is_enabled(self.user))

    def test_enable_test_in_debug_prints_uri_and_valid_code(self):
        with override_settings(DEBUG=True):
            out = run("totp_enable_test", "dev")
        self.assertIn("otpauth://totp/", out)
        device = TOTPDevice.objects.get(user=self.user)
        self.assertTrue(device.confirmed)
        code = out.split("Current code:")[1].strip()
        self.assertTrue(api.verify_code(self.user, code).ok)

    def test_code_only(self):
        with override_settings(DEBUG=True):
            code = run("totp_enable_test", "dev", "--code-only").strip()
        self.assertRegex(code, r"^\d{6}$")

    def test_force_and_setting_override_the_debug_guard(self):
        run("totp_enable_test", "dev", "--force")
        self.assertTrue(api.is_enabled(self.user))
        other = make_user("dev2")
        with override_settings(TOTP_DEBUG_COMMANDS=True):
            run("totp_enable_test", "dev2")
        self.assertTrue(api.is_enabled(other))

    def test_totp_code(self):
        device = enable(self.user)
        with self.assertRaises(CommandError):
            run("totp_code", "dev")
        with override_settings(DEBUG=True):
            code = run("totp_code", "dev").strip()
        self.assertTrue(core.hotp(device.secret_bytes, core.time_step(None, 30), 6) == code or code in (code_for(device, -1), code_for(device, 1)))
        with override_settings(DEBUG=True):
            with self.assertRaises(CommandError):
                run("totp_code", "nobody")
            other = make_user("nodevice")
            with self.assertRaises(CommandError):
                run("totp_code", "nodevice")


class AdminCommandsTests(TestCase):
    def setUp(self):
        from django.core.cache import cache
        cache.clear()
        self.user = make_user("ops")
        self.device = enable(self.user)
        api.generate_recovery_codes(self.user)

    def test_status_for_user_by_name_id_and_email(self):
        for ident in ("ops", str(self.user.pk), "ops@example.com"):
            out = run("totp_status", ident)
            self.assertIn("2FA enabled: True", out)
            self.assertIn("Recovery codes left: 10", out)
            self.assertIn("Phone", out)
            self.assertNotIn(self.device.secret, out)

    def test_status_summary(self):
        out = run("totp_status")
        self.assertIn("with 2FA: 1", out)

    def test_status_unknown_user(self):
        with self.assertRaises(CommandError):
            run("totp_status", "ghost")

    def test_disable_is_audited(self):
        run("totp_disable", "ops")
        self.assertFalse(api.is_enabled(self.user))
        self.assertEqual(RecoveryCode.objects.count(), 0)
        self.assertTrue(TwoFactorEvent.objects.filter(event="admin_disabled").exists())

    def test_reset_lockout_user_ip_and_all(self):
        fail(self.user, n=10)
        self.assertTrue(Lockout.objects.exists())
        self.assertIn("Cleared 1", run("totp_reset_lockout", "ops"))
        self.assertTrue(api.verify_code(self.user, code_for(self.device)).ok)
        Lockout.objects.create(scope="ip", key_hash=__import__("dj_totp_2fa.ratelimit", fromlist=["x"]).key_hash("ip", "192.0.2.1"), until=timezone.now() + timedelta(hours=1))
        self.assertIn("Cleared 1", run("totp_reset_lockout", "--ip", "192.0.2.1"))
        Lockout.objects.create(scope="user", key_hash="f" * 64, until=timezone.now() + timedelta(hours=1))
        self.assertIn("Cleared 1", run("totp_reset_lockout", "--all"))
        with self.assertRaises(CommandError):
            run("totp_reset_lockout")

    def test_purge_events_respects_retention(self):
        old = TwoFactorEvent.objects.create(event="failed")
        TwoFactorEvent.objects.filter(pk=old.pk).update(created_at=timezone.now() - timedelta(days=400))
        recent = TwoFactorEvent.objects.create(event="failed")
        out = run("totp_purge_events", "--dry-run")
        self.assertIn("Would delete 1", out)
        self.assertTrue(TwoFactorEvent.objects.filter(pk=old.pk).exists())
        run("totp_purge_events")
        self.assertFalse(TwoFactorEvent.objects.filter(pk=old.pk).exists())
        self.assertTrue(TwoFactorEvent.objects.filter(pk=recent.pk).exists())

    def test_purge_events_custom_days_and_keep_forever(self):
        e = TwoFactorEvent.objects.create(event="failed")
        TwoFactorEvent.objects.filter(pk=e.pk).update(created_at=timezone.now() - timedelta(days=10))
        run("totp_purge_events", "--days", "30")
        self.assertTrue(TwoFactorEvent.objects.filter(pk=e.pk).exists())
        run("totp_purge_events", "--days", "5")
        self.assertFalse(TwoFactorEvent.objects.filter(pk=e.pk).exists())
        with override_settings(TOTP_EVENT_RETENTION_DAYS=None):
            self.assertIn("kept", run("totp_purge_events"))

    def test_purge_removes_stale_lockout_rows(self):
        Lockout.objects.create(scope="user", key_hash="a" * 64, until=timezone.now() - timedelta(days=5))
        Lockout.objects.update(updated_at=timezone.now() - timedelta(days=5))
        run("totp_purge_events")
        self.assertFalse(Lockout.objects.exists())

    def test_settings_command(self):
        out = run("totp_settings")
        self.assertIn("WINDOW", out)
        self.assertIn("LOCKOUT_STEPS", out)
        md = run("totp_settings", "--markdown")
        self.assertIn("# Settings reference", md)
        self.assertIn("| `THEME` |", md)

    def test_settings_command_warns_about_typos(self):
        with override_settings(DJ_TOTP_2FA={"WINDWO": 2}):
            out = run("totp_settings")
        self.assertIn("did you mean WINDOW", out)


class DoctorTests(TestCase):
    def test_doctor_runs_and_reports(self):
        out = run("totp_doctor", "--no-network")
        self.assertIn("crypto self-test", out)
        self.assertIn("OK", out)
        self.assertIn("SKIP", out)

    def test_json_output(self):
        data = json.loads(run("totp_doctor", "--json", "--no-network"))
        names = {r["check"] for r in data["results"]}
        self.assertIn("database tables", names)
        self.assertIn("templates", names)
        self.assertIn("static files", names)
        self.assertTrue(data["ok"])

    def test_strict_fails_on_warnings(self):
        with self.assertRaises(SystemExit) as cm:
            run("totp_doctor", "--strict", "--no-network")
        self.assertEqual(cm.exception.code, 1)

    def test_clock_check_unreachable_is_a_warning(self):
        with mock.patch("dj_totp_2fa.management.commands.totp_doctor.ntp_offset", side_effect=OSError("offline")):
            out = run("totp_doctor")
        self.assertIn("could not reach an NTP server", out)

    def test_clock_check_reports_offset(self):
        with mock.patch("dj_totp_2fa.management.commands.totp_doctor.ntp_offset", return_value=0.2):
            self.assertIn("+0.20 s", run("totp_doctor"))
        with mock.patch("dj_totp_2fa.management.commands.totp_doctor.ntp_offset", return_value=40.0):
            self.assertIn("WARN  clock", run("totp_doctor"))

    def test_failing_config_fails_the_doctor(self):
        with override_settings(TOTP_DIGITS=3):
            with self.assertRaises(SystemExit):
                run("totp_doctor", "--no-network")

    def test_ntp_packet_parser(self):
        import struct
        from dj_totp_2fa.management.commands.totp_doctor import NTP_EPOCH, ntp_offset
        now = __import__("time").time()
        reply = bytearray(48)
        reply[40:48] = struct.pack("!II", int(now) + NTP_EPOCH, int((now % 1) * 2 ** 32))

        class FakeSocket:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def settimeout(self, t):
                pass

            def sendto(self, data, addr):
                self.sent = data

            def recvfrom(self, n):
                return bytes(reply), ("x", 123)

        with mock.patch("socket.socket", return_value=FakeSocket()):
            self.assertLess(abs(ntp_offset()), 1.0)


class SimulateTests(TestCase):
    def test_simulation_passes_and_leaves_nothing_behind(self):
        out = run("totp_simulate")
        self.assertIn("All steps passed", out)
        self.assertNotIn("FAIL", out)
        self.assertEqual(TOTPDevice.objects.count(), 0)
        from django.contrib.auth import get_user_model
        self.assertEqual(get_user_model().objects.count(), 0)

    def test_simulation_with_existing_user(self):
        user = make_user("real")
        device = enable(user)
        before = device.last_used_step
        out = run("totp_simulate", "--user", "real")
        self.assertIn("All steps passed", out)
        device.refresh_from_db()
        self.assertEqual(device.last_used_step, before)  # rolled back
        self.assertTrue(user.__class__.objects.filter(pk=user.pk).exists())
        self.assertFalse(user.__class__.objects.get(pk=user.pk).check_password("whatever"))

    def test_simulation_user_without_device(self):
        make_user("empty")
        with self.assertRaises(SystemExit):
            out = run("totp_simulate", "--user", "empty")
