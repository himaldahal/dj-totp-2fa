"""System checks. Configuration problems are errors; weak-but-working setups are warnings (most only under --deploy)."""
from django.conf import settings
from django.core import checks
from django.core.exceptions import ImproperlyConfigured

from . import conf, crypto, totp as core

P = "dj_totp_2fa"
MIDDLEWARE = "dj_totp_2fa.middleware.TwoFactorMiddleware"


def _warn(id_, msg, hint=""):
    return checks.Warning(msg, hint=hint, id="%s.%s" % (P, id_))


def _err(id_, msg, hint=""):
    return checks.Error(msg, hint=hint, id="%s.%s" % (P, id_))


@checks.register()
def check_config(app_configs=None, **kwargs):
    out = []
    for where, key, suggestion in conf.unknown_keys():
        hint = "Did you mean %r?" % suggestion if suggestion else "See `manage.py totp_settings` for the list."
        out.append(_warn("W001", "Unknown dj_totp_2fa setting %s %r." % (where, key), hint))
    if str(conf.get("ALGORITHM")).upper() not in core.ALGORITHMS:
        out.append(_err("E001", "ALGORITHM must be SHA1, SHA256 or SHA512."))
    if not 6 <= int(conf.get("DIGITS")) <= 8:
        out.append(_err("E002", "DIGITS must be between 6 and 8."))
    if not 15 <= int(conf.get("PERIOD")) <= 120:
        out.append(_err("E003", "PERIOD must be between 15 and 120 seconds."))
    if int(conf.get("SECRET_BYTES")) < 16:
        out.append(_err("E004", "SECRET_BYTES must be at least 16."))
    if not 0 <= int(conf.get("WINDOW")) <= 2:
        out.append(_err("E005", "WINDOW must be between 0 and 2."))
    if str(conf.get("THEME")).lower() not in ("clean", "midnight", "aurora", "auto"):
        out.append(_err("E006", "THEME must be clean, midnight, aurora or auto."))
    steps = conf.get("LOCKOUT_STEPS")
    if not steps or not all(isinstance(s, int) and s > 0 for s in steps):
        out.append(_err("E007", "LOCKOUT_STEPS must be a non-empty list of positive integers (seconds)."))
    if int(conf.get("RECOVERY_CODE_LENGTH")) < 10:
        out.append(_err("E008", "RECOVERY_CODE_LENGTH must be at least 10 (50 bits)."))
    try:
        mode = crypto.active_mode()
        if str(conf.get("SECRET_ENCRYPTION")).lower() == "fernet":
            if not crypto.cryptography_available():
                out.append(_err("E009", "SECRET_ENCRYPTION='fernet' needs the cryptography package.", "pip install dj-totp-2fa[crypto]"))
            else:
                crypto._multifernet()
        elif mode == "fernet":
            crypto._multifernet()
    except ImproperlyConfigured as exc:
        out.append(_err("E010", str(exc)))
    if MIDDLEWARE not in settings.MIDDLEWARE:
        out.append(_warn("W002", "TwoFactorMiddleware is not installed, so 2FA is only enforced on the built-in login views.",
                         "Add '%s' after AuthenticationMiddleware." % MIDDLEWARE))
    elif "django.contrib.auth.middleware.AuthenticationMiddleware" in settings.MIDDLEWARE and \
            settings.MIDDLEWARE.index(MIDDLEWARE) < settings.MIDDLEWARE.index("django.contrib.auth.middleware.AuthenticationMiddleware"):
        out.append(_err("E011", "TwoFactorMiddleware must come after AuthenticationMiddleware."))
    if "django.contrib.sessions" not in settings.INSTALLED_APPS and "django.contrib.sessions.middleware.SessionMiddleware" not in settings.MIDDLEWARE:
        out.append(_err("E012", "dj_totp_2fa needs Django sessions."))
    return out


@checks.register(checks.Tags.security, deploy=True)
def check_deploy(app_configs=None, **kwargs):
    out = []
    if crypto.active_mode() == "none":
        out.append(_warn("W010", "TOTP secrets are stored in plaintext. A database leak would let an attacker generate valid codes.",
                         "pip install dj-totp-2fa[crypto] and set TOTP_ENCRYPTION_KEYS (see docs/security.md)."))
    if conf.window() > 1:
        out.append(_warn("W011", "WINDOW is greater than 1, which widens the set of accepted codes.", "Use 1 or 0."))
    alias = conf.get("CACHE_ALIAS")
    cache = (settings.CACHES.get(alias) or {}).get("BACKEND", "")
    if conf.get("RATE_LIMITS_ENABLED") and ("locmem" in cache.lower() or "dummy" in cache.lower()):
        out.append(_warn("W012", "Rate limit counters use %s, which is not shared between workers (or does nothing)." % cache.rsplit(".", 1)[-1],
                         "Use Redis or Memcached. Database lockouts still apply, but per-window counters are per process."))
    if not settings.SESSION_COOKIE_SECURE:
        out.append(_warn("W013", "SESSION_COOKIE_SECURE is False; the verified session cookie can travel over plain HTTP."))
    if not settings.CSRF_COOKIE_SECURE:
        out.append(_warn("W014", "CSRF_COOKIE_SECURE is False."))
    if settings.DEBUG:
        out.append(_warn("W015", "DEBUG is True; totp_code and totp_enable_test can print valid codes."))
    if not conf.get("PROTECT_ADMIN"):
        out.append(_warn("W016", "PROTECT_ADMIN is False: the Django admin login does not require 2FA."))
    if (getattr(settings, "SECURE_PROXY_SSL_HEADER", None) or conf.get("CLIENT_IP_HEADER") != "X-Forwarded-For") and not conf.get("TRUSTED_PROXIES") and not conf.get("IP_RESOLVER"):
        out.append(_warn("W017", "You appear to be behind a proxy but TRUSTED_PROXIES is empty, so every client shares the proxy's IP for rate limits.",
                         "Set TOTP_TRUSTED_PROXIES to your proxy addresses."))
    if "console" in getattr(settings, "EMAIL_BACKEND", "") or "dummy" in getattr(settings, "EMAIL_BACKEND", ""):
        out.append(_warn("W018", "EMAIL_BACKEND does not deliver mail, so security notifications go nowhere."))
    if not conf.get("RATE_LIMITS_ENABLED"):
        out.append(_warn("W019", "RATE_LIMITS_ENABLED is False: codes can be guessed without limits."))
    if not conf.get("ISSUER"):
        out.append(_warn("W020", "No ISSUER is set; apps will show the site name or host. Set TOTP_ISSUER for a stable label."))
    if int(conf.get("REMEMBER_BROWSER") or 0) > 90:
        out.append(_warn("W021", "REMEMBER_BROWSER is over 90 days; trusted cookies live very long."))
    return out
