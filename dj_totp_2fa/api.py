"""Programmatic API. Everything the views, commands and admin do goes through here.

    from dj_totp_2fa import api
    device = api.create_device(user)                      # unconfirmed, secret generated
    api.confirm_device(device, "123456", request)         # -> VerifyResult
    result = api.verify_code(user, "123456", request)     # -> VerifyResult(ok, method, reason, retry_after)
    codes = api.generate_recovery_codes(user)             # plaintext list, shown once
    api.is_enabled(user); api.disable(user)
"""
import random
import secrets
import time

from django.contrib.auth.hashers import check_password, make_password
from django.db import transaction
from django.db.models import F
from django.utils import timezone
from django.utils.translation import gettext as _

from . import conf, crypto, events, notify as notifier, ratelimit, totp as core, trusted
from .clientip import client_ip, is_denied, storable_ip
from .models import RecoveryCode, TOTPDevice, TrustedBrowser, TwoFactorEvent
from .signals import (totp_device_confirmed, totp_device_removed, totp_disabled, totp_failed, totp_locked_out,
                      totp_recovery_code_used, totp_verified)

RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # 32 symbols, no 0/O/1/I; 5 bits per character

# Reasons that are shown to the user in the same generic words. Only locked/throttled carry extra information
# (a wait time), which the attacker could see anyway from a failed attempt.
GENERIC_REASONS = {"invalid", "format", "replay", "vetoed", "no_device", "bot", "expired", "disabled_method", "denied"}


class VerifyResult:
    __slots__ = ("ok", "method", "reason", "retry_after", "device", "step", "locked_scopes")

    def __init__(self, ok, method="", reason="", retry_after=0, device=None, step=None):
        self.ok, self.method, self.reason, self.retry_after, self.device, self.step = ok, method, reason, retry_after, device, step
        self.locked_scopes = []

    def __bool__(self):
        return bool(self.ok)

    def __repr__(self):
        return "<VerifyResult ok=%s method=%r reason=%r retry_after=%s>" % (self.ok, self.method, self.reason, self.retry_after)

    @property
    def locked(self):
        return self.reason in ("locked", "throttled")

    @property
    def message(self):
        if self.ok:
            return ""
        if self.locked:
            return _("Too many attempts. Please wait before trying again.")
        return _("That code did not work. Check the code and try again.")


# ---------------------------------------------------------------- parameters and URIs

def get_issuer(request=None):
    issuer = conf.get("ISSUER")
    if issuer:
        return str(issuer)
    try:
        from django.contrib.sites.models import Site
        from django.apps import apps
        if apps.is_installed("django.contrib.sites"):
            return Site.objects.get_current(request).name
    except Exception:
        pass
    if request is not None:
        try:
            return request.get_host()
        except Exception:
            pass
    from django.conf import settings
    return (settings.SETTINGS_MODULE or "Django").split(".")[0] if getattr(settings, "SETTINGS_MODULE", None) else "Django"


def account_label(user):
    fn = conf.get("ACCOUNT_LABEL")
    return str(fn(user)) if fn else user.get_username()


def build_uri(device, request=None):
    return core.otpauth_uri(device.secret, account_label(device.user), get_issuer(request), device.algorithm,
                            device.digits, device.period)


def default_params():
    algorithm = str(conf.get("ALGORITHM")).upper()
    if algorithm not in core.ALGORITHMS:
        algorithm = "SHA1"
    return {"algorithm": algorithm, "digits": conf.int_setting("DIGITS", 6, 8), "period": conf.int_setting("PERIOD", 15, 120)}


def new_secret():
    return core.b32encode(core.generate_secret(conf.int_setting("SECRET_BYTES", 16)))


def group4(text):
    return " ".join(text[i:i + 4] for i in range(0, len(text), 4))


# ---------------------------------------------------------------- devices

def is_enabled(user):
    return bool(user and getattr(user, "pk", None)) and TOTPDevice.objects.filter(user=user, confirmed=True).exists()


def confirmed_devices(user):
    return list(TOTPDevice.objects.filter(user=user, confirmed=True))


def _unique_name(user, name):
    name = (name or "Authenticator").strip()[:56] or "Authenticator"
    existing = set(TOTPDevice.objects.filter(user=user).values_list("name", flat=True))
    candidate, n = name, 2
    while candidate in existing:
        candidate = "%s %d" % (name, n)
        n += 1
    return candidate


def create_device(user, name="Authenticator", secret=None, **params):
    """Create an UNCONFIRMED device with a fresh random secret (or ``secret``, base32)."""
    values = default_params()
    values.update(params)
    device = TOTPDevice(user=user, name=_unique_name(user, name), confirmed=False, **values)
    device.secret = secret or new_secret()
    device.save()
    return device


def max_devices_reached(user):
    return TOTPDevice.objects.filter(user=user, confirmed=True).count() >= conf.int_setting("MAX_DEVICES", 1)


def _device_step(device, code, now=None):
    """The accepted step for ``code`` on ``device`` (or None), plus the offset k it matched at. No side effects."""
    window = device.window if device.window is not None else conf.window()
    window = min(2, max(0, int(window)))
    now_step = core.time_step(now, device.period) + device.drift_steps
    try:
        key = device.secret_bytes
    except (crypto.SecretError, ValueError):
        return None, 0
    matches = core.match_steps(key, code, now_step, window, device.digits, device.algorithm)
    fresh = [s for s in matches if s > device.last_used_step]
    if not fresh:
        return ("replay" if matches else None), 0
    step = max(fresh)
    return step, step - now_step


def _burn(method="totp"):
    """Spend about the same CPU as a real check, for unknown/locked/blocked callers."""
    if method == "recovery":
        for _unused in range(max(1, conf.int_setting("RECOVERY_CODE_COUNT", 1))):
            _burn_hash()
    else:
        core.match_steps(b"\x00" * 20, "000000", int(time.time() // 30), 1, 6, "SHA1")


_DUMMY_HASH = []


def _burn_hash():
    if not _DUMMY_HASH:
        _DUMMY_HASH.append(make_password("dj-totp-2fa-dummy", hasher=conf.get("RECOVERY_HASHER") or "default"))
    check_password("dj-totp-2fa-not-the-code", _DUMMY_HASH[0])


def _claim_step(device, step, offset):
    """Atomically mark ``step`` as used. False when another request got there first (replay)."""
    updates = {"last_used_step": step, "last_used_at": timezone.now(), "failure_count": 0}
    if conf.get("ALLOW_DRIFT_RESYNC") and offset:
        cap = conf.int_setting("DRIFT_RESYNC_MAX", 0, 10)
        updates["drift_steps"] = max(-cap, min(cap, device.drift_steps + offset))
    return TOTPDevice.objects.filter(pk=device.pk, last_used_step__lt=step).update(**updates) == 1


def detect_method(code):
    cleaned = core.clean_code(code)
    return "totp" if cleaned.isascii() and cleaned.isdigit() and 6 <= len(cleaned) <= 8 else "recovery"


def _delay(started):
    ms = int(conf.get("FAIL_DELAY_MS") or 0)
    if ms > 0:
        target = ms / 1000.0 * (0.9 + random.random() * 0.2)
        remaining = target - (time.monotonic() - started)
        if remaining > 0:
            time.sleep(remaining)


def _fail(user, request, reason, count=True, method=""):
    result = VerifyResult(False, method, reason)
    if reason in ("locked", "throttled"):
        return result
    if user is not None and getattr(user, "pk", None):
        if count:
            TOTPDevice.objects.filter(user=user, confirmed=True).update(failure_count=F("failure_count") + 1)
            started = ratelimit.register_failure(user, request, reason)
            for scope, row in started:
                result.locked_scopes.append(scope)
                result.retry_after = max(result.retry_after, ratelimit.retry_after(row))
                events.record("lockout", request, user=user, scope=scope, until=row.until.isoformat(), level=row.level)
                totp_locked_out.send(sender=type(user), user=user, request=request, scope=scope, until=row.until)
                for hook in conf.get("ON_LOCKOUT"):
                    hook(user, request, scope, row.until)
                if scope == "user":
                    notifier.notify(user, "lockout", request, minutes=max(1, int(ratelimit.retry_after(row) / 60)))
                notifier.alert_staff("lockout", {"user": user.pk, "scope": scope})
            if result.locked_scopes:
                result.reason = "locked"
        events.record("failed", request, user=user, reason=reason, method=method)
    totp_failed.send(sender=type(user) if user is not None else None, user=user, request=request, reason=result.reason)
    for hook in conf.get("ON_FAILED"):
        hook(user, request, result.reason)
    return result


def verify_code(user, code, request=None, method="auto", count_failures=True):
    """Check a TOTP or recovery code for ``user``. Never raises on bad input.

    Order: IP denylist, lockouts, circuit breaker challenge, veto rules, then the cryptographic check.
    Failures are counted per user, IP and site; a success resets the user's counter.
    """
    started = time.monotonic()
    try:
        result = _verify(user, code, request, method, count_failures)
    except Exception:
        _delay(started)
        raise
    if not result.ok:
        _delay(started)
    return result


def _verify(user, code, request, method, count_failures):
    cleaned = core.clean_code(code)
    if method == "auto":
        method = detect_method(cleaned)
    if user is None or not getattr(user, "pk", None) or not getattr(user, "is_active", False):
        _burn(method)
        return VerifyResult(False, method, "invalid")
    ip = client_ip(request) if request is not None else ""
    if ip and is_denied(ip):
        _burn(method)
        events.record("ip_denied", request, user=user)
        return VerifyResult(False, method, "denied")
    gate = ratelimit.check_gate(user, request)
    if not gate:
        _burn(method)
        return VerifyResult(False, method, "locked", gate.retry_after)
    if ratelimit.circuit_open():
        challenge = conf.get("CHALLENGE")
        if challenge and challenge(request, user) is False:
            _burn(method)
            return VerifyResult(False, method, "throttled", 30)
    for rule in conf.get("RULES"):
        if not rule(user, request):
            _burn(method)
            events.record("suspicious", request, user=user, reason="vetoed by rule")
            return VerifyResult(False, method, "vetoed")

    if method == "recovery" and not conf.get("ALLOW_RECOVERY_CODES"):
        _burn(method)
        return _fail(user, request, "disabled_method", count_failures, method)

    if method == "totp":
        return _verify_totp(user, cleaned, request, count_failures)
    return _verify_recovery(user, cleaned, request, count_failures)


def _verify_totp(user, code, request, count_failures):
    devices = confirmed_devices(user)
    found = []
    replay = False
    for device in devices:  # every device and every window candidate is evaluated, no early exit
        step, offset = _device_step(device, code)
        if step == "replay":
            replay = True
        elif step is not None:
            found.append((device, step, offset))
    if not devices:
        _burn("totp")
        return _fail(user, request, "no_device", count_failures, "totp")
    if not found:
        if replay:
            events.record("replay", request, user=user)
        return _fail(user, request, "replay" if replay else "invalid", count_failures, "totp")
    device, step, offset = found[0]
    validator = conf.get("CODE_VALIDATOR")
    if validator and not validator(user, code, request):
        return _fail(user, request, "invalid", count_failures, "totp")
    if not _claim_step(device, step, offset):  # lost the race against a concurrent identical request
        events.record("replay", request, user=user)
        return _fail(user, request, "replay", count_failures, "totp")
    return _succeed(user, request, VerifyResult(True, "totp", device=device, step=step))


def _verify_recovery(user, code, request, count_failures):
    code = code.upper()
    unused = list(RecoveryCode.objects.filter(user=user, used_at__isnull=True))
    matched = None
    well_formed = len(code) >= 10 and all(ch in RECOVERY_ALPHABET for ch in code)
    probe = code if well_formed else "!"
    for row in unused:  # check all rows, no early exit
        if check_password(probe, row.code_hash) and matched is None and well_formed:
            matched = row
    for _unused in range(max(0, conf.int_setting("RECOVERY_CODE_COUNT", 1) - len(unused))):
        _burn_hash()  # same amount of hashing whether the user has 10 codes or none
    if matched is None:
        return _fail(user, request, "invalid", count_failures, "recovery")
    validator = conf.get("CODE_VALIDATOR")
    if validator and not validator(user, code, request):
        return _fail(user, request, "invalid", count_failures, "recovery")
    claimed = RecoveryCode.objects.filter(pk=matched.pk, used_at__isnull=True).update(
        used_at=timezone.now(), used_ip=storable_ip(request) if request is not None else None)
    if claimed != 1:
        return _fail(user, request, "replay", count_failures, "recovery")
    remaining = RecoveryCode.objects.filter(user=user, used_at__isnull=True).count()
    events.record("recovery_used", request, user=user, remaining=remaining)
    totp_recovery_code_used.send(sender=type(user), user=user, request=request, remaining=remaining)
    notifier.notify(user, "recovery_used", request, remaining=remaining)
    if remaining <= conf.int_setting("RECOVERY_LOW_THRESHOLD", 0):
        notifier.notify(user, "recovery_low", request, remaining=remaining)
    return _succeed(user, request, VerifyResult(True, "recovery"))


def _succeed(user, request, result):
    ratelimit.clear_user_counters(user)
    events.record("verified", request, user=user, method=result.method)
    totp_verified.send(sender=type(user), user=user, request=request, method=result.method)
    for hook in conf.get("ON_VERIFIED"):
        hook(user, request, result.method)
    return result


# ---------------------------------------------------------------- setup / confirmation

def confirm_secret(user, secret_b32, code, request=None, name="Authenticator"):
    """Create a confirmed device from a session held ``secret_b32`` if ``code`` is currently valid for it.

    Rate limited exactly like a login code, so setup cannot be used to guess against an existing device.
    Returns (VerifyResult, device or None).
    """
    started = time.monotonic()
    if max_devices_reached(user):
        return VerifyResult(False, "totp", "max_devices"), None
    ip = client_ip(request) if request is not None else ""
    if ip and is_denied(ip):
        return VerifyResult(False, "totp", "denied"), None
    gate = ratelimit.check_gate(user, request)
    if not gate:
        return VerifyResult(False, "totp", "locked", gate.retry_after), None
    params = default_params()
    probe = TOTPDevice(user=user, name="probe", last_used_step=0, **params)
    probe.secret = secret_b32
    step, offset = _device_step(probe, code)
    if step is None or step == "replay":
        result = _fail(user, request, "invalid", True, "totp")
        _delay(started)
        return result, None
    with transaction.atomic():
        first = not TOTPDevice.objects.filter(user=user, confirmed=True).exists()
        device = TOTPDevice(user=user, name=_unique_name(user, name), confirmed=True, primary=first,
                            confirmed_at=timezone.now(), last_used_at=timezone.now(), last_used_step=step, **params)
        device.secret = secret_b32
        device.save()
    ratelimit.clear_user_counters(user)
    events.record("device_added", request, user=user, device=device.pk, name=device.name)
    totp_device_confirmed.send(sender=TOTPDevice, device=device, user=user, request=request)
    notifier.notify(user, "device_added", request, device=device.name)
    return VerifyResult(True, "totp", device=device, step=step), device


def confirm_device(device, code, request=None):
    """Confirm an unconfirmed device created with create_device(). Returns a VerifyResult."""
    user = device.user
    if device.confirmed:
        return VerifyResult(False, "totp", "already_confirmed")
    started = time.monotonic()
    gate = ratelimit.check_gate(user, request)
    if not gate:
        return VerifyResult(False, "totp", "locked", gate.retry_after)
    step, offset = _device_step(device, code)
    if step is None or step == "replay":
        result = _fail(user, request, "invalid", True, "totp")
        _delay(started)
        return result
    first = not TOTPDevice.objects.filter(user=user, confirmed=True).exists()
    updated = TOTPDevice.objects.filter(pk=device.pk, confirmed=False).update(
        confirmed=True, confirmed_at=timezone.now(), last_used_step=step, last_used_at=timezone.now(), primary=first)
    if updated != 1:
        return VerifyResult(False, "totp", "already_confirmed")
    device.refresh_from_db()
    ratelimit.clear_user_counters(user)
    events.record("device_added", request, user=user, device=device.pk, name=device.name)
    totp_device_confirmed.send(sender=TOTPDevice, device=device, user=user, request=request)
    notifier.notify(user, "device_added", request, device=device.name)
    return VerifyResult(True, "totp", device=device, step=step)


def remove_device(device, request=None, actor=None):
    user, name = device.user, device.name
    device.delete()
    events.record("device_removed", request, user=user, name=name, actor=getattr(actor, "pk", None))
    totp_device_removed.send(sender=TOTPDevice, user=user, name=name, request=request)
    notifier.notify(user, "device_removed", request, device=name)


def rename_device(device, name, request=None):
    new = _unique_name(device.user, name) if name != device.name else name
    device.name = new
    device.save(update_fields=["name"])
    events.record("device_renamed", request, user=device.user, device=device.pk)
    return new


# ---------------------------------------------------------------- recovery codes

def _new_recovery_code(length):
    while True:
        code = "".join(secrets.choice(RECOVERY_ALPHABET) for _unused in range(length))
        if not code.isdigit():  # a code of only digits could be mistaken for an app code
            return code


def format_recovery_code(code):
    return "-".join(code[i:i + 5] for i in range(0, len(code), 5))


def generate_recovery_codes(user, count=None, request=None):
    """Replace all recovery codes with a new batch. Returns the plaintext codes (xxxxx-xxxxx); keep them out of logs."""
    count = conf.int_setting("RECOVERY_CODE_COUNT", 1) if count is None else count
    length = max(10, int(conf.get("RECOVERY_CODE_LENGTH")))
    codes = [_new_recovery_code(length) for _unused in range(count)]
    hasher = conf.get("RECOVERY_HASHER") or "default"
    with transaction.atomic():
        RecoveryCode.objects.filter(user=user).delete()
        RecoveryCode.objects.bulk_create([RecoveryCode(user=user, code_hash=make_password(c, hasher=hasher)) for c in codes])
    events.record("recovery_regenerated", request, user=user, count=count)
    return [format_recovery_code(c) for c in codes]


def recovery_codes_remaining(user):
    return RecoveryCode.objects.filter(user=user, used_at__isnull=True).count()


# ---------------------------------------------------------------- disable / reset / export

def disable(user, request=None, actor=None, event="disabled"):
    """Remove every device, recovery code and trusted browser of ``user``."""
    with transaction.atomic():
        n_devices = TOTPDevice.objects.filter(user=user).count()
        TOTPDevice.objects.filter(user=user).delete()
        RecoveryCode.objects.filter(user=user).delete()
        TrustedBrowser.objects.filter(user=user).delete()
    ratelimit.clear_user_counters(user)
    events.record(event, request, user=user, devices=n_devices, actor=getattr(actor, "pk", None))
    totp_disabled.send(sender=type(user), user=user, request=request, actor=actor)
    if event == "disabled":
        notifier.notify(user, "disabled", request)
    return n_devices


def export_user_data(user):
    """Everything stored about ``user`` (no secrets, no hashes) as plain data for a data-subject request."""
    return {
        "devices": list(TOTPDevice.objects.filter(user=user).values(
            "name", "algorithm", "digits", "period", "confirmed", "primary", "created_at", "confirmed_at", "last_used_at")),
        "recovery_codes": {"unused": recovery_codes_remaining(user),
                           "used": RecoveryCode.objects.filter(user=user, used_at__isnull=False).count()},
        "trusted_browsers": list(TrustedBrowser.objects.filter(user=user).values(
            "label", "user_agent_summary", "ip", "created_at", "expires_at", "last_seen_at")),
        "events": list(TwoFactorEvent.objects.filter(user=user).values("event", "ip", "user_agent", "details", "created_at")),
    }


# ---------------------------------------------------------------- trusted browsers (helpers)

def trust_browser(request, response, user):
    return trusted.issue(request, response, user)


def revoke_trusted_browsers(user, pk=None, request=None):
    return trusted.revoke(user, pk, request)


# ---------------------------------------------------------------- step-up / re-authentication

def reauthenticate(user, request, password="", code=""):
    """Re-verify an already signed in user with their password or a current app code (never a recovery code).

    Counted and locked out like a login code, because a stolen session must not become a free guessing oracle.
    """
    started = time.monotonic()
    wait = ratelimit.throttle(request, "reauth") if request is not None else 0
    if wait:
        return VerifyResult(False, "", "throttled", wait)
    if code:
        return verify_code(user, code, request, method="totp")
    gate = ratelimit.check_gate(user, request)
    if not gate:
        return VerifyResult(False, "password", "locked", gate.retry_after)
    if password and user.check_password(password):
        events.record("reauth_ok", request, user=user, method="password")
        return VerifyResult(True, "password")
    if not password:
        user.check_password("dj-totp-2fa-dummy")
    result = _fail(user, request, "invalid", True, "password")
    _delay(started)
    return result
