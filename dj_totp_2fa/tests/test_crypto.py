import io
from unittest import skipUnless

from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.test import TestCase, override_settings

from dj_totp_2fa import api, crypto
from dj_totp_2fa.models import TOTPDevice

from .base import code_for, enable, make_user

HAS_CRYPTO = crypto.cryptography_available()


def _key():
    return crypto.generate_key()


class PlaintextTests(TestCase):
    def test_default_auto_without_keys_is_plaintext(self):
        self.assertEqual(crypto.active_mode(), "none")
        device = enable(make_user())
        self.assertTrue(device.secret_encrypted.startswith("p1$"))
        self.assertEqual(device.secret_encrypted[3:], device.secret)

    def test_unknown_format_is_rejected(self):
        with self.assertRaises(crypto.SecretError):
            crypto.decrypt("zz$whatever")

    def test_invalid_mode(self):
        with override_settings(TOTP_SECRET_ENCRYPTION="rot13"):
            with self.assertRaises(ImproperlyConfigured):
                crypto.active_mode()

    def test_secret_never_in_repr_str_or_admin_fields(self):
        device = enable(make_user())
        for text in (repr(device), str(device)):
            self.assertNotIn(device.secret, text)
        from django.contrib import admin
        model_admin = admin.site._registry[TOTPDevice]
        for field in list(model_admin.get_fields(None, device)) + list(model_admin.get_readonly_fields(None, device)):
            self.assertNotIn("secret", field)

    def test_log_scrubbing(self):
        from dj_totp_2fa.redact import mask, scrub
        self.assertEqual(mask("ABCDEF"), "****")
        self.assertNotIn("JBSWY3DPEHPK3PXP", scrub("device secret=JBSWY3DPEHPK3PXP created"))
        self.assertNotIn("123456", scrub("code=123456"))


class CustomPairTests(TestCase):
    def test_custom_callables(self):
        with override_settings(TOTP_SECRET_ENCRYPTION=["dj_totp_2fa.tests.test_crypto.reverse_enc", "dj_totp_2fa.tests.test_crypto.reverse_dec"]):
            self.assertEqual(crypto.active_mode(), "custom")
            device = enable(make_user())
            self.assertTrue(device.secret_encrypted.startswith("c1$"))
            self.assertEqual(device.secret_encrypted[3:], device.secret[::-1])
            self.assertEqual(len(device.secret_bytes), 20)


def reverse_enc(text):
    return text[::-1]


def reverse_dec(text):
    return text[::-1]


@skipUnless(HAS_CRYPTO, "cryptography is not installed")
class FernetTests(TestCase):
    def test_roundtrip_and_ciphertext(self):
        with override_settings(TOTP_ENCRYPTION_KEYS=[_key()]):
            self.assertEqual(crypto.active_mode(), "fernet")
            device = enable(make_user())
            self.assertTrue(device.secret_encrypted.startswith("f1$"))
            self.assertNotIn(device.secret, device.secret_encrypted)
            self.assertEqual(len(device.secret_bytes), 20)
            self.assertTrue(api.verify_code(device.user, code_for(device)))

    def test_forced_fernet_without_keys_errors(self):
        with override_settings(TOTP_SECRET_ENCRYPTION="fernet", TOTP_ENCRYPTION_KEYS=[]):
            with self.assertRaises(ImproperlyConfigured):
                crypto.encrypt("ABC")

    def test_invalid_key(self):
        with override_settings(TOTP_ENCRYPTION_KEYS=["not-a-key"]):
            with self.assertRaises(ImproperlyConfigured):
                crypto.encrypt("ABC")

    def test_tampered_ciphertext_fails(self):
        with override_settings(TOTP_ENCRYPTION_KEYS=[_key()]):
            device = enable(make_user())
            token = device.secret_encrypted
            tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
            with self.assertRaises(crypto.SecretError):
                crypto.decrypt(tampered)
            TOTPDevice.objects.filter(pk=device.pk).update(secret_encrypted=tampered)
            device.refresh_from_db()
            self.assertFalse(api.verify_code(device.user, "123456"))

    def test_wrong_key_cannot_decrypt(self):
        with override_settings(TOTP_ENCRYPTION_KEYS=[_key()]):
            device = enable(make_user())
            stored = device.secret_encrypted
        with override_settings(TOTP_ENCRYPTION_KEYS=[_key()]):
            with self.assertRaises(crypto.SecretError):
                crypto.decrypt(stored)

    def test_rotation_with_command(self):
        old, new = _key(), _key()
        user = make_user()
        with override_settings(TOTP_ENCRYPTION_KEYS=[old]):
            device = enable(user)
            plain = device.secret
        legacy = enable(make_user("legacy"))  # stored as plaintext (written before encryption was on)
        self.assertTrue(legacy.secret_encrypted.startswith("p1$"))
        with override_settings(TOTP_ENCRYPTION_KEYS=[new, old]):
            self.assertTrue(api.verify_code(user, code_for(device)))  # old key still decrypts
            out = io.StringIO()
            call_command("totp_rotate_keys", stdout=out)
            self.assertIn("Re-encrypted: 2", out.getvalue())
            device.refresh_from_db()
            legacy.refresh_from_db()
            self.assertEqual(device.secret, plain)
            self.assertTrue(legacy.secret_encrypted.startswith("f1$"))
        with override_settings(TOTP_ENCRYPTION_KEYS=[new]):  # old key can now be dropped
            device.refresh_from_db()
            self.assertEqual(device.secret, plain)

    def test_rotate_dry_run_and_idempotent(self):
        old, new = _key(), _key()
        with override_settings(TOTP_ENCRYPTION_KEYS=[old]):
            enable(make_user())
        with override_settings(TOTP_ENCRYPTION_KEYS=[new, old]):
            out = io.StringIO()
            call_command("totp_rotate_keys", "--dry-run", stdout=out)
            self.assertIn("Re-encrypted: 1", out.getvalue())
            call_command("totp_rotate_keys", stdout=io.StringIO())
            out = io.StringIO()
            call_command("totp_rotate_keys", stdout=out)
            self.assertIn("already current: 1", out.getvalue())

    def test_generate_key_command(self):
        out = io.StringIO()
        call_command("totp_rotate_keys", "--generate-key", stdout=out)
        from cryptography.fernet import Fernet
        Fernet(out.getvalue().strip().encode())

    def test_rotate_reports_undecryptable(self):
        with override_settings(TOTP_ENCRYPTION_KEYS=[_key()]):
            enable(make_user())
        with override_settings(TOTP_ENCRYPTION_KEYS=[_key()]):
            from django.core.management.base import CommandError
            with self.assertRaises(CommandError):
                call_command("totp_rotate_keys", stdout=io.StringIO(), stderr=io.StringIO())
