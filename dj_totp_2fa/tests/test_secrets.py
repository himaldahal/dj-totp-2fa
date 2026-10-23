import collections

from django.test import SimpleTestCase, TestCase

from dj_totp_2fa import api, totp as core
from dj_totp_2fa.models import RecoveryCode

from .base import make_user


class SecretGenerationTests(SimpleTestCase):
    def test_unique_across_thousands(self):
        seen = {api.new_secret() for _ in range(5000)}
        self.assertEqual(len(seen), 5000)

    def test_length_and_alphabet(self):
        secret = api.new_secret()
        self.assertEqual(len(secret), 32)  # 20 bytes -> 32 base32 chars, no padding
        self.assertTrue(set(secret) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"))

    def test_bit_distribution_is_roughly_uniform(self):
        n = 4000
        ones = 0
        per_bit = [0] * 8
        for _ in range(n):
            raw = core.generate_secret()
            for byte in raw:
                ones += bin(byte).count("1")
                for bit in range(8):
                    per_bit[bit] += (byte >> bit) & 1
        total_bits = n * 20 * 8
        self.assertAlmostEqual(ones / total_bits, 0.5, delta=0.005)
        for count in per_bit:
            self.assertAlmostEqual(count / (n * 20), 0.5, delta=0.02)

    def test_byte_values_cover_the_range(self):
        counts = collections.Counter(b for _ in range(2000) for b in core.generate_secret())
        self.assertEqual(len(counts), 256)

    def test_no_use_of_the_random_module(self):
        import inspect
        from dj_totp_2fa import totp, api as api_module
        self.assertNotIn("import random\n", inspect.getsource(totp))
        # api uses random only for timing jitter, never for secrets or codes
        source = inspect.getsource(api_module)
        self.assertNotIn("random.choice", source)
        self.assertNotIn("random.randint", source)


class RecoveryCodeTests(TestCase):
    def setUp(self):
        self.user = make_user()

    def test_format_count_and_alphabet(self):
        codes = api.generate_recovery_codes(self.user)
        self.assertEqual(len(codes), 10)
        for code in codes:
            self.assertRegex(code, r"^[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}$")

    def test_entropy_bits(self):
        import math
        self.assertGreaterEqual(10 * math.log2(len(api.RECOVERY_ALPHABET)), 50)

    def test_unique_and_never_all_digits(self):
        seen = set()
        for _ in range(300):
            seen.update(api.generate_recovery_codes(self.user, count=10))
        self.assertEqual(len(seen), 3000)
        self.assertFalse(any(c.replace("-", "").isdigit() for c in seen))

    def test_only_salted_hashes_are_stored(self):
        codes = api.generate_recovery_codes(self.user)
        stored = list(RecoveryCode.objects.filter(user=self.user).values_list("code_hash", flat=True))
        self.assertEqual(len(stored), 10)
        for code in codes:
            raw = code.replace("-", "")
            for h in stored:
                self.assertNotIn(raw, h)
                self.assertNotIn(code, h)
        self.assertEqual(len(set(stored)), 10)  # salted: even equal inputs would differ

    def test_regenerate_replaces_old_codes(self):
        first = api.generate_recovery_codes(self.user)
        api.generate_recovery_codes(self.user)
        self.assertEqual(RecoveryCode.objects.filter(user=self.user).count(), 10)
        self.assertFalse(api.verify_code(self.user, first[0]))

    def test_custom_count_and_length(self):
        from django.test import override_settings
        with override_settings(TOTP_RECOVERY_CODE_COUNT=4, TOTP_RECOVERY_CODE_LENGTH=15):
            codes = api.generate_recovery_codes(self.user)
        self.assertEqual(len(codes), 4)
        self.assertEqual(len(codes[0].replace("-", "")), 15)

    def test_minimum_length_is_enforced(self):
        from django.test import override_settings
        with override_settings(TOTP_RECOVERY_CODE_LENGTH=4):
            codes = api.generate_recovery_codes(self.user, count=1)
        self.assertEqual(len(codes[0].replace("-", "")), 10)
