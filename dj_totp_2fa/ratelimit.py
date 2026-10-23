"""Failure counters (cache), progressive lockouts (database) and endpoint throttles.

* Counters live in the Django cache as two-bucket sliding windows with atomic ``incr``.
* Lockouts live in the database (``Lockout``) so they survive a cache flush and are shared by all processes.
* Every key is an HMAC of the raw value, so neither the cache nor the database holds raw IPs or ids in keys.
"""
import hashlib
import hmac
import math
import time
from datetime import timedelta

from django.conf import settings
from django.core.cache import caches
from django.db import IntegrityError, transaction
from django.utils import timezone

from . import conf, events
from .clientip import client_ip, ip_group, is_allowlisted
from .models import Lockout


def cache():
    return caches[conf.get("CACHE_ALIAS")]


def key_hash(scope, value):
    digest = hmac.new(settings.SECRET_KEY.encode(), ("dj_totp_2fa:%s:%s" % (scope, value)).encode(), hashlib.sha256)
    return digest.hexdigest()


def _bucket_key(scope, value, bucket):
    return "djtotp:%s:%s:%d" % (scope, key_hash(scope, value)[:32], bucket)


def hit(scope, value, window):
    """Count one event and return the sliding window estimate (current bucket + weighted previous bucket)."""
    window = max(1, int(window))
    now = time.time()
    bucket = int(now // window)
    c = cache()
    key = _bucket_key(scope, value, bucket)
    c.add(key, 0, timeout=window * 2 + 5)
    try:
        current = c.incr(key)
    except ValueError:  # evicted between add and incr
        c.set(key, 1, timeout=window * 2 + 5)
        current = 1
    previous = c.get(_bucket_key(scope, value, bucket - 1), 0) or 0
    weight = 1 - (now % window) / window
    return int(math.ceil(current + previous * weight))


def fixed_hit(scope, value, ttl):
    """Exact counter that expires ``ttl`` seconds after its first hit (used for one pending login)."""
    c = cache()
    key = "djtotp:fx:%s:%s" % (scope, key_hash(scope, value)[:32])
    c.add(key, 0, timeout=ttl)
    try:
        return c.incr(key)
    except ValueError:
        c.set(key, 1, timeout=ttl)
        return 1


def fixed_count(scope, value):
    return cache().get("djtotp:fx:%s:%s" % (scope, key_hash(scope, value)[:32]), 0) or 0


def count(scope, value, window):
    window = max(1, int(window))
    now = time.time()
    bucket = int(now // window)
    c = cache()
    current = c.get(_bucket_key(scope, value, bucket), 0) or 0
    previous = c.get(_bucket_key(scope, value, bucket - 1), 0) or 0
    return int(math.ceil(current + previous * (1 - (now % window) / window)))


def reset(scope, value, window):
    window = max(1, int(window))
    bucket = int(time.time() // window)
    c = cache()
    c.delete_many([_bucket_key(scope, value, bucket), _bucket_key(scope, value, bucket - 1)])


def enabled():
    return bool(conf.get("RATE_LIMITS_ENABLED"))


# ---------------------------------------------------------------- lockouts (database)

def active_lockout(scope, value):
    if not enabled():
        return None
    row = Lockout.objects.filter(scope=scope, key_hash=key_hash(scope, value), until__gt=timezone.now()).first()
    return row


def retry_after(row):
    return max(1, int(math.ceil((row.until - timezone.now()).total_seconds()))) if row else 0


def apply_lockout(scope, value, user=None, reason=""):
    """Start (or escalate) a lockout and return the row. Escalates through LOCKOUT_STEPS; resets after quiet time."""
    steps = [int(s) for s in (conf.get("LOCKOUT_STEPS") or [60])] or [60]
    now = timezone.now()
    kh = key_hash(scope, value)
    reset_after = timedelta(seconds=int(conf.get("LOCKOUT_RESET_AFTER")))
    with transaction.atomic():
        try:
            row = Lockout.objects.select_for_update().filter(scope=scope, key_hash=kh).first()
        except Exception:  # pragma: no cover - backends without row locks
            row = Lockout.objects.filter(scope=scope, key_hash=kh).first()
        if row is None:
            level = 0
            try:
                with transaction.atomic():
                    row = Lockout.objects.create(scope=scope, key_hash=kh, user=user, until=now, reason=reason[:120])
            except IntegrityError:
                row = Lockout.objects.get(scope=scope, key_hash=kh)
                level = row.level + 1
        else:
            level = row.level + 1 if now - row.until < reset_after else 0
        seconds = steps[min(level, len(steps) - 1)]
        row.level = level
        row.until = now + timedelta(seconds=seconds)
        row.reason = reason[:120]
        row.updated_at = now
        if user is not None:
            row.user = user
        row.save()
    return row


def clear_lockouts(user=None, ip=None, everything=False):
    qs = Lockout.objects.all()
    if not everything:
        if user is not None:
            qs = qs.filter(scope=Lockout.SCOPE_USER, key_hash=key_hash("user", user.pk))
        elif ip is not None:
            qs = qs.filter(scope=Lockout.SCOPE_IP, key_hash=key_hash("ip", ip_group(ip)))
        else:
            return 0
    n = qs.count()
    qs.delete()
    if user is not None:
        reset("ufail", user.pk, conf.get("USER_FAILURE_WINDOW"))
    if ip is not None:
        reset("ipfail", ip_group(ip), conf.get("IP_FAILURE_WINDOW"))
    return n


# ---------------------------------------------------------------- gates

class Gate:
    __slots__ = ("allowed", "reason", "retry_after")

    def __init__(self, allowed=True, reason="", retry_after=0):
        self.allowed, self.reason, self.retry_after = allowed, reason, retry_after

    def __bool__(self):
        return self.allowed


def check_gate(user, request):
    """Are verification attempts currently allowed for this user and client? Pure check, counts nothing."""
    if not enabled():
        return Gate()
    waits = []
    if user is not None and getattr(user, "pk", None):
        row = active_lockout(Lockout.SCOPE_USER, user.pk)
        if row:
            waits.append(("user", retry_after(row)))
    ip = client_ip(request) if request is not None else ""
    if ip and not is_allowlisted(ip):
        row = active_lockout(Lockout.SCOPE_IP, ip_group(ip))
        if row:
            waits.append(("ip", retry_after(row)))
    if waits:
        scope, wait = max(waits, key=lambda w: w[1])
        return Gate(False, "locked", wait)
    return Gate()


def circuit_open():
    threshold = int(conf.get("GLOBAL_FAILURE_THRESHOLD") or 0)
    return enabled() and threshold > 0 and bool(cache().get("djtotp:circuit"))


def register_failure(user, request, reason="invalid"):
    """Count one failed attempt against user, IP and the whole site. Returns a list of ('scope', lockout row)."""
    if not enabled():
        return []
    started = []
    ip = client_ip(request) if request is not None else ""
    if user is not None and getattr(user, "pk", None):
        n = hit("ufail", user.pk, conf.get("USER_FAILURE_WINDOW"))
        if n >= int(conf.get("USER_FAILURE_LIMIT")):
            row = apply_lockout(Lockout.SCOPE_USER, user.pk, user=user, reason="too many failed codes")
            started.append(("user", row))
    if ip and not is_allowlisted(ip):
        n = hit("ipfail", ip_group(ip), conf.get("IP_FAILURE_WINDOW"))
        if n >= int(conf.get("IP_FAILURE_LIMIT")):
            row = apply_lockout(Lockout.SCOPE_IP, ip_group(ip), reason="too many failed codes from this network")
            started.append(("ip", row))
    threshold = int(conf.get("GLOBAL_FAILURE_THRESHOLD") or 0)
    if threshold:
        window = int(conf.get("GLOBAL_FAILURE_WINDOW"))
        g = hit("global", "all", window)
        if g >= threshold and not cache().get("djtotp:circuit"):
            cache().set("djtotp:circuit", 1, timeout=window)
            events.record("global_alert", request, failures=g, window=window)
            alert = conf.get("STAFF_ALERT")
            if alert:
                alert("global_alert", {"failures": g, "window": window})
    return started


def clear_user_counters(user):
    reset("ufail", user.pk, conf.get("USER_FAILURE_WINDOW"))


def throttle(request, endpoint):
    """Per-IP request budget for one endpoint. Returns seconds to wait, or 0 when the request may go on."""
    if not enabled():
        return 0
    limits = conf.get("ENDPOINT_RATE_LIMITS").get(endpoint)
    if not limits:
        return 0
    allowed, seconds = int(limits[0]), int(limits[1])
    ip = client_ip(request)
    if ip and is_allowlisted(ip):
        return 0
    n = hit("ep:" + endpoint, ip_group(ip), seconds)
    if n > allowed:
        events.record("throttled", request, endpoint=endpoint)
        return max(1, seconds - int(time.time() % seconds))
    return 0
