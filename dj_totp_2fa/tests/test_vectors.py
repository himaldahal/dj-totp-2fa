import base64

from django.test import SimpleTestCase

from dj_totp_2fa import totp as core

RFC4226_SECRET = b"12345678901234567890"
RFC4226_CODES = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
# RFC 6238 Appendix B: (time, SHA1, SHA256, SHA512), 8 digits
RFC6238 = [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]
SEEDS = {"SHA1": b"12345678901234567890", "SHA256": b"12345678901234567890123456789012",
         "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234"}


class Rfc4226Tests(SimpleTestCase):
    def test_appendix_d_vectors(self):
        for counter, expected in enumerate(RFC4226_CODES):
            self.assertEqual(core.hotp(RFC4226_SECRET, counter, 6, "SHA1"), expected)

    def test_truncation_intermediate_values(self):
        # Appendix D lists the 31-bit truncated integers too: count 0 -> 1284755224
        import hmac, struct, hashlib
        mac = hmac.new(RFC4226_SECRET, struct.pack(">Q", 0), hashlib.sha1).digest()
        self.assertEqual(mac.hex(), "cc93cf18508d94934c64b65d8ba7667fb7cde4b0")
        offset = mac[-1] & 0xF
        self.assertEqual(offset, 0)
        self.assertEqual(struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF, 1284755224)


class Rfc6238Tests(SimpleTestCase):
    def test_appendix_b_vectors_all_hashes(self):
        for stamp, sha1, sha256, sha512 in RFC6238:
            for algo, expected in (("SHA1", sha1), ("SHA256", sha256), ("SHA512", sha512)):
                self.assertEqual(core.totp(SEEDS[algo], stamp, 8, 30, algo), expected, (stamp, algo))

    def test_six_digit_is_suffix_of_eight(self):
        self.assertEqual(core.totp(SEEDS["SHA1"], 59, 6, 30, "SHA1"), "287082")

    def test_other_periods(self):
        self.assertEqual(core.time_step(59, 30), 1)
        self.assertEqual(core.time_step(60, 30), 2)
        self.assertEqual(core.time_step(59, 15), 3)


class HelpersTests(SimpleTestCase):
    def test_base32_roundtrip_without_padding(self):
        for n in (16, 20, 21, 32):
            raw = bytes(range(n))
            text = core.b32encode(raw)
            self.assertNotIn("=", text)
            self.assertEqual(core.b32decode(text), raw)
            self.assertEqual(core.b32decode(" ".join(text[i:i + 4] for i in range(0, len(text), 4)).lower()), raw)

    def test_b32_rejects_garbage(self):
        with self.assertRaises(ValueError):
            core.b32decode("not base32!!")

    def test_secret_minimum_size(self):
        with self.assertRaises(ValueError):
            core.generate_secret(15)
        self.assertEqual(len(core.generate_secret()), 20)

    def test_clean_code(self):
        self.assertEqual(core.clean_code(" 123-456 "), "123456")

    def test_match_steps_window_edges(self):
        key = RFC4226_SECRET
        now = 1000
        for offset in (-2, -1, 0, 1, 2):
            code = core.hotp(key, now + offset, 6)
            hit = core.match_steps(key, code, now, 1, 6)
            self.assertEqual(hit, [now + offset] if abs(offset) <= 1 else [], offset)
        self.assertEqual(core.match_steps(key, core.hotp(key, now + 2, 6), now, 2, 6), [now + 2])
        self.assertEqual(core.match_steps(key, core.hotp(key, now, 6), now, 0, 6), [now])

    def test_match_steps_rejects_malformed(self):
        for bad in ("", "12345", "1234567", "abcdef", "12 3456x", "١٢٣٤٥٦"):
            self.assertEqual(core.match_steps(RFC4226_SECRET, bad, 5, 1, 6), [], bad)

    def test_match_steps_ignores_spaces_and_hyphens(self):
        code = core.hotp(RFC4226_SECRET, 7, 6)
        self.assertEqual(core.match_steps(RFC4226_SECRET, code[:3] + " " + code[3:], 7, 0, 6), [7])
        self.assertEqual(core.match_steps(RFC4226_SECRET, code[:3] + "-" + code[3:], 7, 0, 6), [7])

    def test_negative_steps_are_safe(self):
        self.assertEqual(core.match_steps(RFC4226_SECRET, "000000", 0, 2, 6).count(-1), 0)


class UriTests(SimpleTestCase):
    def test_google_key_uri(self):
        uri = core.otpauth_uri("JBSWY3DPEHPK3PXP", "alice@example.com", "Example Co", "SHA1", 6, 30)
        self.assertEqual(uri, "otpauth://totp/Example%20Co:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example%20Co&algorithm=SHA1&digits=6&period=30")

    def test_percent_encoding_and_colon_stripping(self):
        uri = core.otpauth_uri("ABC", "a b&c=d:e", "My:Site & Co", "SHA256", 8, 60)
        self.assertIn("otpauth://totp/MySite%20%26%20Co:a%20b%26c%3Dde?", uri)
        self.assertIn("issuer=MySite%20%26%20Co", uri)
        self.assertTrue(uri.endswith("algorithm=SHA256&digits=8&period=60"))

    def test_no_issuer(self):
        self.assertTrue(core.otpauth_uri("ABC", "bob", "").startswith("otpauth://totp/bob?secret=ABC"))
        self.assertNotIn("issuer=", core.otpauth_uri("ABC", "bob", ""))
