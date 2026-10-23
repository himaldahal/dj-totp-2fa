"""Central registry of every setting: default, type, meaning, security note, category, version.

It drives three things: the defaults read by ``conf.py``, typo detection (system checks) and the generated
reference (``manage.py totp_settings --markdown`` -> ``docs/settings.md``).

Every key can be written as a top-level Django setting with a ``TOTP_`` prefix (``TOTP_WINDOW = 1``) or inside
one dict (``DJ_TOTP_2FA = {"WINDOW": 1}``). The prefixed setting wins when both exist.
"""
from collections import OrderedDict, namedtuple

Setting = namedtuple("Setting", "name default type description category security since imp")

# imp: None (plain value), "callable" (dotted string is imported), "callables" (list of dotted strings),
#      "maybe" (a string containing a dot is imported, other values are kept as they are)
REGISTRY = OrderedDict()


def _add(category, name, default, type_, description, security="", imp=None, since="0.1.0"):
    REGISTRY[name] = Setting(name, default, type_, description, category, security, since, imp)


C = "Branding and appearance"
_add(C, "THEME", "clean", "str", '"clean" (light), "midnight" (dark), "aurora" (gradient) or "auto" (clean or midnight following the visitor\'s system preference).')
_add(C, "BRAND_NAME", "", "str", "Name shown in the page header. Empty means the issuer.")
_add(C, "LOGO_URL", "", "str", "URL of a logo image shown next to the brand name.")
_add(C, "BASE_TEMPLATE", "dj_totp_2fa/base.html", "str", "Template every page extends. Use it to wrap the pages in your own layout (it must define the blocks totp_head, title, totp_content and totp_scripts).")
_add(C, "EXTRA_CSS", [], "list[str]", "Extra stylesheet URLs loaded after the theme (a place to override CSS variables).")
_add(C, "ISSUER", "", "str", "Issuer shown in authenticator apps. Empty means the current Site name, then the HTTP host, then the project name.", "Changing it later does not break existing devices, but users will see two labels.")
_add(C, "ACCOUNT_LABEL", None, "callable", "fn(user) -> str. The account name shown in the authenticator app. Default: the username.", "", "callable")

C = "TOTP parameters"
_add(C, "ALGORITHM", "SHA1", "str", '"SHA1" (works with every app, including Google Authenticator), "SHA256" or "SHA512".', "SHA1 is fine for HMAC based codes; some apps ignore other values.")
_add(C, "DIGITS", 6, "int", "Number of digits in a code (6 to 8). Most apps expect 6.")
_add(C, "PERIOD", 30, "int", "Seconds per code (15 to 120). Most apps expect 30.")
_add(C, "SECRET_BYTES", 20, "int", "Size of a new shared secret in bytes (at least 16). 20 bytes is 160 bits, the RFC 4226 recommendation.", "Never go below 16.")
_add(C, "WINDOW", 1, "int", "How many steps either side of the current one are accepted (0 to 2). It absorbs clock drift.", "Each extra step raises the guess chance per attempt. Keep 1.")
_add(C, "ALLOW_DRIFT_RESYNC", False, "bool", "Remember a device's clock offset after a successful code from a neighbouring step.", "Off by default. The offset is capped by DRIFT_RESYNC_MAX.")
_add(C, "DRIFT_RESYNC_MAX", 2, "int", "Largest stored offset in steps when ALLOW_DRIFT_RESYNC is on.")

C = "Secrets and recovery codes"
_add(C, "SECRET_ENCRYPTION", "auto", "str|list", '"none", "fernet", "auto" (Fernet when cryptography is installed and ENCRYPTION_KEYS is set, otherwise plaintext) or a pair ["dotted.encrypt", "dotted.decrypt"].', "Plaintext secrets mean a database leak lets an attacker generate codes. Use fernet in production.", "maybe")
_add(C, "ENCRYPTION_KEYS", [], "list[str]", "Fernet keys. The first one encrypts, all of them decrypt (rotation). Create one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\".", "Keep them outside the database and the repository.")
_add(C, "RECOVERY_CODE_COUNT", 10, "int", "Recovery codes created per batch.")
_add(C, "RECOVERY_CODE_LENGTH", 10, "int", "Characters per recovery code (at least 10, which is 50 bits).", "Codes are stored only as salted hashes.")
_add(C, "RECOVERY_HASHER", None, "str|None", "Django password hasher name used for recovery codes. None means the first entry of PASSWORD_HASHERS.")
_add(C, "RECOVERY_LOW_THRESHOLD", 3, "int", "Notify the user when this many (or fewer) recovery codes remain.")
_add(C, "ALLOW_RECOVERY_CODES", True, "bool", "Accept recovery codes at verification.")
_add(C, "MAX_DEVICES", 5, "int", "Most devices one user can register.")

C = "Login flow and sessions"
_add(C, "PENDING_TTL", 300, "int", "Seconds the password step stays valid while the user enters a code.")
_add(C, "PENDING_MAX_ATTEMPTS", 5, "int", "Wrong codes allowed per pending login before it is destroyed.")
_add(C, "VERIFIED_MAX_AGE", None, "int|None", "Seconds before a verified session must verify again. None means for the life of the session.")
_add(C, "REMEMBER_BROWSER", 30, "int", 'Days a "trust this browser" cookie skips the code step. 0 disables the feature.', "A stolen cookie plus the password skips the second factor until it expires or is revoked.")
_add(C, "REMEMBER_COOKIE_NAME", "dj_totp_trusted", "str", "Name of the trusted browser cookie.")
_add(C, "ROTATE_TRUSTED_TOKEN", False, "bool", "Issue a new random token every time the cookie is used.")
_add(C, "FRESH_MAX_AGE", 300, "int", "Default age in seconds for otp_fresh when no value is given.")
_add(C, "REDIRECT_AFTER_VERIFY", "", "str", "Fallback destination after verification when there is no next parameter. Empty means LOGIN_REDIRECT_URL.")

C = "Enforcement policy"
_add(C, "REQUIRED", False, "bool|str|list|callable", 'Who must use 2FA: False, True, "staff", "superuser", a list of group names, or fn(user, request) -> bool.', "", "maybe")
_add(C, "ENROLMENT_GRACE_DAYS", 0, "int", "Days required users may sign in without 2FA, with a reminder, before enrolment is forced.")
_add(C, "EXEMPT_USERS", [], "list|callable", "Usernames or ids that never need 2FA, or fn(user) -> bool.", "Exemptions weaken the policy. Keep the list short.", "maybe")
_add(C, "EXEMPT_URLS", [], "list[str]", "URL names or regular expressions (matched against the path) that skip enforcement.")
_add(C, "REQUIRE_REVERIFY_FOR", [], "list[str]", "URL names or path regexes that need a fresh code (step-up) even for verified sessions.")
_add(C, "REVERIFY_MAX_AGE", 300, "int", "Seconds a code check counts as fresh for REQUIRE_REVERIFY_FOR.")
_add(C, "PROTECT_ADMIN", True, "bool", "Make the Django admin login require 2FA.", "Turning it off leaves the most powerful login without a second factor.")
_add(C, "API_PREFIXES", ["/api/"], "list[str]", "Path prefixes that always get JSON answers from the middleware (besides requests that ask for JSON).")

C = "Rate limiting and lockouts"
_add(C, "RATE_LIMITS_ENABLED", True, "bool", "Master switch for failure counters, lockouts and endpoint throttles.", "Never disable in production.")
_add(C, "CACHE_ALIAS", "default", "str", "Cache used for counters. Use a shared cache (Redis, Memcached) with several workers.", "LocMemCache is per process and weakens limits.")
_add(C, "USER_FAILURE_LIMIT", 10, "int", "Failures per user (all IPs and sessions) inside USER_FAILURE_WINDOW before a lockout.")
_add(C, "USER_FAILURE_WINDOW", 900, "int", "Seconds of the per-user sliding window.")
_add(C, "IP_FAILURE_LIMIT", 20, "int", "Failures per client IP inside IP_FAILURE_WINDOW before an IP lockout.")
_add(C, "IP_FAILURE_WINDOW", 900, "int", "Seconds of the per-IP sliding window.")
_add(C, "LOCKOUT_STEPS", [60, 300, 900, 3600, 86400], "list[int]", "Progressive lockout durations in seconds. The last one repeats.")
_add(C, "LOCKOUT_RESET_AFTER", 86400, "int", "Seconds without a new lockout after which the escalation level starts again.")
_add(C, "GLOBAL_FAILURE_THRESHOLD", 300, "int", "Failures from everyone inside GLOBAL_FAILURE_WINDOW that trip the circuit breaker (distributed brute force). 0 disables.")
_add(C, "GLOBAL_FAILURE_WINDOW", 300, "int", "Seconds of the global window.")
_add(C, "ENDPOINT_RATE_LIMITS", {"verify": (30, 300), "setup": (20, 300), "recovery": (10, 300), "api": (60, 300), "reauth": (15, 300)}, "dict", "Requests allowed per client IP and endpoint as (count, seconds).")
_add(C, "FAIL_DELAY_MS", 0, "int", "Minimum delay (with a little jitter) added to every failed check to blunt timing attacks and tight loops.")
_add(C, "HONEYPOT_FIELD", "website", "str", "Name of the hidden decoy field on the verify form. Empty disables the honeypot.")
_add(C, "MIN_SUBMIT_SECONDS", 1, "float", "A verify form submitted sooner than this after it was rendered is rejected as a bot. 0 disables.")
_add(C, "CHALLENGE", None, "callable", "fn(request, user) -> bool|None. Return False to demand a CAPTCHA style challenge: the attempt is refused and nothing is counted. Called when the circuit breaker is open.", "", "callable")

C = "Client IP and network rules"
_add(C, "TRUSTED_PROXIES", [], "list[str]", "IPs or networks of reverse proxies whose forwarded header can be believed.", "Empty means the header is ignored, which is right unless you are behind a proxy.")
_add(C, "CLIENT_IP_HEADER", "X-Forwarded-For", "str", "Header carrying the client IP when the request comes from a trusted proxy.")
_add(C, "IP_RESOLVER", None, "callable", "fn(request) -> str. Replace the built-in client IP logic.", "", "callable")
_add(C, "IPV6_PREFIX", 64, "int", "IPv6 addresses are grouped by this prefix length for limits.")
_add(C, "IP_ALLOWLIST", [], "list[str]", "Networks exempt from IP based throttling (per-user limits still apply). For office networks.", "Do not list wide public ranges.")
_add(C, "IP_DENYLIST", [], "list[str]", "Networks that can never verify a code.")

C = "Notifications"
_add(C, "NOTIFY", {"lockout": True, "trusted_browser": True, "disabled": True, "device_added": True, "device_removed": True, "recovery_used": True, "recovery_low": True, "recovery_regenerated": True}, "dict", "Email the user about these events (set a key to False to silence it).")
_add(C, "NOTIFY_SENDER", None, "callable", "fn(user, event, context) -> None. Replace the built-in email sending.", "", "callable")
_add(C, "EMAIL_FROM", "", "str", "From address for notices. Empty means DEFAULT_FROM_EMAIL.")
_add(C, "STAFF_ALERT", None, "callable", "fn(event, details) -> None. Called for suspicious activity (lockouts, circuit breaker, admin resets).", "", "callable")

C = "Hooks and rules"
_add(C, "ON_VERIFIED", [], "list[callable]", "hook(user, request, method) after a successful verification.", "", "callables")
_add(C, "ON_FAILED", [], "list[callable]", "hook(user, request, reason) after a failed verification.", "", "callables")
_add(C, "ON_LOCKOUT", [], "list[callable]", "hook(user, request, scope, until) after a lockout starts.", "", "callables")
_add(C, "RULES", [], "list[callable]", "rule(user, request) -> bool. A falsy result vetoes the verification attempt (nothing is counted).", "", "callables")
_add(C, "CODE_VALIDATOR", None, "callable", "fn(user, code, request) -> bool. Extra check that runs after a code is cryptographically valid. Return False to refuse.", "", "callable")

C = "Logging, audit and privacy"
_add(C, "LOG_LEVEL", "INFO", "str", "Level of the dj_totp_2fa logger when no LOGGING entry configures it.")
_add(C, "LOGGER_NAME", "dj_totp_2fa", "str", "Root logger name. Children: .auth, .security, .setup, .admin.")
_add(C, "LOG_FORMAT", "plain", "str", '"plain" or "json" (one JSON object per line).')
_add(C, "STORE_IP", True, "bool", "Store the client IP on audit events and lockouts.", "Needed for forensics; consider privacy law.")
_add(C, "ANONYMIZE_IP", False, "bool", "Store IPs truncated (IPv4 /24, IPv6 /48).")
_add(C, "STORE_USER_AGENT", True, "bool", "Store a shortened User-Agent on events and trusted browsers.")
_add(C, "EVENT_RETENTION_DAYS", 365, "int|None", "Events older than this are removed by totp_purge_events. None keeps everything.")
_add(C, "DEBUG_COMMANDS", False, "bool", "Allow totp_enable_test and totp_code outside DEBUG (never do this in production).", "Leaks valid codes.")


def defaults():
    out = {}
    for name, s in REGISTRY.items():
        v = s.default
        out[name] = dict(v) if isinstance(v, dict) else (list(v) if isinstance(v, list) else v)
    return out


def import_kind(name):
    s = REGISTRY.get(name)
    return s.imp if s else None


def categories():
    out = OrderedDict()
    for s in REGISTRY.values():
        out.setdefault(s.category, []).append(s)
    return out


def as_markdown():
    lines = ["# Settings reference", "",
             "Generated by `python manage.py totp_settings --markdown`. Every key can be set as `TOTP_<NAME>` in your Django settings",
             "or inside one dict, `DJ_TOTP_2FA = {\"<NAME>\": ...}`. The prefixed setting wins.", ""]
    for cat, items in categories().items():
        lines += ["## " + cat, "", "| Setting | Default | Type | Description |", "|---|---|---|---|"]
        for s in items:
            desc = s.description.replace("|", "\\|")
            if s.security:
                desc += " **Security:** " + s.security.replace("|", "\\|")
            lines.append("| `%s` | `%r` | %s | %s |" % (s.name, s.default, s.type.replace("|", "\\|"), desc))
        lines.append("")
    return "\n".join(lines)
