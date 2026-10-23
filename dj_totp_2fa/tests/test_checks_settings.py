from django.core import checks
from django.test import SimpleTestCase, TestCase, override_settings

from dj_totp_2fa import checks as totp_checks, conf, settings_registry
from dj_totp_2fa.settings_registry import REGISTRY


def ids(messages):
    return {m.id for m in messages}


class RegistryTests(SimpleTestCase):
    def test_every_entry_is_documented(self):
        for name, s in REGISTRY.items():
            self.assertTrue(s.description, name)
            self.assertTrue(s.category, name)
            self.assertTrue(s.since, name)
            self.assertEqual(name, name.upper())

    def test_defaults_are_independent_copies(self):
        a = settings_registry.defaults()
        a["EXTRA_CSS"].append("x")
        self.assertEqual(settings_registry.defaults()["EXTRA_CSS"], [])

    def test_markdown_lists_everything(self):
        md = settings_registry.as_markdown()
        for name in REGISTRY:
            self.assertIn("`%s`" % name, md)

    def test_generated_docs_are_up_to_date(self):
        import os
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "docs", "settings.md")
        if not os.path.exists(path):  # installed package without the docs folder
            self.skipTest("docs/settings.md not available")
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(fh.read().strip(), settings_registry.as_markdown().strip())

    def test_required_settings_exist(self):
        for name in ("THEME", "BRAND_NAME", "LOGO_URL", "BASE_TEMPLATE", "EXTRA_CSS", "ISSUER", "SECRET_ENCRYPTION", "ENCRYPTION_KEYS",
                     "WINDOW", "ALLOW_DRIFT_RESYNC", "REQUIRED", "ENROLMENT_GRACE_DAYS", "EXEMPT_USERS", "EXEMPT_URLS", "ALLOW_RECOVERY_CODES",
                     "MAX_DEVICES", "REMEMBER_BROWSER", "REQUIRE_REVERIFY_FOR", "VERIFIED_MAX_AGE", "PROTECT_ADMIN", "PENDING_TTL",
                     "LOCKOUT_STEPS", "GLOBAL_FAILURE_THRESHOLD", "FAIL_DELAY_MS", "TRUSTED_PROXIES", "CLIENT_IP_HEADER", "IP_ALLOWLIST",
                     "IP_DENYLIST", "CHALLENGE", "NOTIFY", "LOG_LEVEL", "LOGGER_NAME", "LOG_FORMAT", "STORE_IP", "ANONYMIZE_IP",
                     "STORE_USER_AGENT", "EVENT_RETENTION_DAYS", "ON_VERIFIED", "ON_FAILED", "ON_LOCKOUT", "RULES", "CODE_VALIDATOR",
                     "IP_RESOLVER", "NOTIFY_SENDER", "STAFF_ALERT", "CACHE_ALIAS"):
            self.assertIn(name, REGISTRY)


class ConfLayerTests(SimpleTestCase):
    def test_prefixed_setting_beats_dict_beats_default(self):
        self.assertEqual(conf.get("PERIOD"), 30)
        with override_settings(DJ_TOTP_2FA={"PERIOD": 60}):
            self.assertEqual(conf.get("PERIOD"), 60)
            with override_settings(TOTP_PERIOD=45):
                self.assertEqual(conf.get("PERIOD"), 45)

    def test_dotted_callables_are_imported(self):
        with override_settings(TOTP_REQUIRED="dj_totp_2fa.tests.test_enforcement.only_staff"):
            self.assertTrue(callable(conf.get("REQUIRED")))
        with override_settings(TOTP_ON_VERIFIED="dj_totp_2fa.tests.test_verify.on_ok"):
            self.assertEqual(len(conf.get("ON_VERIFIED")), 1)

    def test_nested_dict_defaults_merge(self):
        with override_settings(TOTP_NOTIFY={"lockout": False}):
            merged = conf.get("NOTIFY")
            self.assertFalse(merged["lockout"])
            self.assertTrue(merged["disabled"])
        with override_settings(TOTP_ENDPOINT_RATE_LIMITS={"verify": (1, 1)}):
            self.assertEqual(conf.get("ENDPOINT_RATE_LIMITS")["setup"], (20, 300))

    def test_unknown_name(self):
        with self.assertRaises(KeyError):
            conf.get("NOPE")
        with self.assertRaises(AttributeError):
            conf.conf.NOPE

    def test_attribute_access(self):
        self.assertEqual(conf.conf.WINDOW, 1)

    def test_typo_detection(self):
        with override_settings(DJ_TOTP_2FA={"WINDWO": 1, "THEME": "clean"}, TOTP_LOCKOUT_STEP=[1]):
            found = {(w, k): s for w, k, s in conf.unknown_keys()}
        self.assertEqual(found[("DJ_TOTP_2FA", "WINDWO")], "WINDOW")
        self.assertEqual(found[("settings", "TOTP_LOCKOUT_STEP")], "LOCKOUT_STEPS")
        self.assertNotIn(("DJ_TOTP_2FA", "THEME"), found)

    def test_window_is_capped(self):
        with override_settings(TOTP_WINDOW=7):
            self.assertEqual(conf.window(), 2)
        with override_settings(TOTP_WINDOW=-1):
            self.assertEqual(conf.window(), 0)


class SystemCheckTests(TestCase):
    def config(self, **settings_):
        with override_settings(**settings_):
            return ids(totp_checks.check_config())

    def deploy(self, **settings_):
        with override_settings(**settings_):
            return ids(totp_checks.check_deploy())

    def test_clean_default_configuration(self):
        self.assertEqual(self.config(), set())

    def test_typo_warning(self):
        self.assertIn("dj_totp_2fa.W001", self.config(DJ_TOTP_2FA={"WINDWO": 1}))

    def test_parameter_errors(self):
        self.assertIn("dj_totp_2fa.E001", self.config(TOTP_ALGORITHM="MD5"))
        self.assertIn("dj_totp_2fa.E002", self.config(TOTP_DIGITS=5))
        self.assertIn("dj_totp_2fa.E002", self.config(TOTP_DIGITS=9))
        self.assertIn("dj_totp_2fa.E003", self.config(TOTP_PERIOD=5))
        self.assertIn("dj_totp_2fa.E004", self.config(TOTP_SECRET_BYTES=10))
        self.assertIn("dj_totp_2fa.E005", self.config(TOTP_WINDOW=3))
        self.assertIn("dj_totp_2fa.E006", self.config(TOTP_THEME="neon"))
        self.assertIn("dj_totp_2fa.E007", self.config(TOTP_LOCKOUT_STEPS=[]))
        self.assertIn("dj_totp_2fa.E007", self.config(TOTP_LOCKOUT_STEPS=[60, -1]))
        self.assertIn("dj_totp_2fa.E008", self.config(TOTP_RECOVERY_CODE_LENGTH=6))

    def test_encryption_errors(self):
        self.assertIn("dj_totp_2fa.E010", self.config(TOTP_SECRET_ENCRYPTION="bogus"))
        self.assertIn("dj_totp_2fa.E010", self.config(TOTP_SECRET_ENCRYPTION="fernet", TOTP_ENCRYPTION_KEYS=[]))
        self.assertIn("dj_totp_2fa.E010", self.config(TOTP_ENCRYPTION_KEYS=["bad-key"]))

    def test_middleware_checks(self):
        from django.conf import settings
        without = [m for m in settings.MIDDLEWARE if "dj_totp_2fa" not in m]
        self.assertIn("dj_totp_2fa.W002", self.config(MIDDLEWARE=without))
        wrong_order = ["dj_totp_2fa.middleware.TwoFactorMiddleware"] + without
        self.assertIn("dj_totp_2fa.E011", self.config(MIDDLEWARE=wrong_order))

    def test_deploy_warnings(self):
        found = self.deploy()
        for expected in ("W010", "W012", "W013", "W014", "W020"):
            self.assertIn("dj_totp_2fa." + expected, found)

    def test_deploy_flags_each_weakness(self):
        self.assertIn("dj_totp_2fa.W011", self.deploy(TOTP_WINDOW=2))
        self.assertIn("dj_totp_2fa.W015", self.deploy(DEBUG=True))
        self.assertIn("dj_totp_2fa.W016", self.deploy(TOTP_PROTECT_ADMIN=False))
        self.assertIn("dj_totp_2fa.W017", self.deploy(SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https")))
        self.assertNotIn("dj_totp_2fa.W017", self.deploy(SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"), TOTP_TRUSTED_PROXIES=["10.0.0.0/8"]))
        self.assertIn("dj_totp_2fa.W018", self.deploy(EMAIL_BACKEND="django.core.mail.backends.console.EmailBackend"))
        self.assertIn("dj_totp_2fa.W019", self.deploy(TOTP_RATE_LIMITS_ENABLED=False))
        self.assertIn("dj_totp_2fa.W021", self.deploy(TOTP_REMEMBER_BROWSER=365))

    def test_deploy_is_quiet_when_hardened(self):
        found = self.deploy(
            TOTP_ENCRYPTION_KEYS=[__import__("dj_totp_2fa.crypto", fromlist=["x"]).generate_key()], TOTP_ISSUER="Example",
            SESSION_COOKIE_SECURE=True, CSRF_COOKIE_SECURE=True,
            CACHES={"default": {"BACKEND": "django.core.cache.backends.db.DatabaseCache", "LOCATION": "x"}},
            EMAIL_BACKEND="django.core.mail.backends.smtp.EmailBackend")
        self.assertEqual(found, set())

    def test_registered_with_django(self):
        found = checks.run_checks(include_deployment_checks=True)
        self.assertTrue(any(m.id and m.id.startswith("dj_totp_2fa.") for m in found))
