"""The signed, time limited, session bound "password done, code still missing" state."""
import secrets
import time

from django.core import signing

from . import conf, ratelimit, session as sess
from .models import Lockout

SALT = "dj_totp_2fa.pending.v1"


class Pending:
    def __init__(self, data):
        self.data = data

    uid = property(lambda s: s.data["uid"])
    backend = property(lambda s: s.data.get("backend", ""))
    next = property(lambda s: s.data.get("next", ""))
    remember = property(lambda s: bool(s.data.get("remember", False)))
    kind = property(lambda s: s.data.get("kind", "login"))
    nonce = property(lambda s: s.data["nonce"])
    attempts = property(lambda s: int(s.data.get("attempts", 0)))
    created = property(lambda s: float(s.data["created"]))
    form_next = property(lambda s: s.data.get("next", ""))

    def expires_in(self):
        return max(0, int(self.created + int(conf.get("PENDING_TTL")) - time.time()))


def create(request, user, backend="", next_url="", remember=False, kind="login"):
    data = {"uid": str(user.pk), "backend": backend or "", "next": next_url or "", "remember": bool(remember),
            "attempts": 0, "created": time.time(), "kind": kind, "nonce": secrets.token_urlsafe(16)}
    pending = Pending(data)
    save(request, pending)
    return pending


def save(request, pending):
    request.session[sess.PENDING_KEY] = signing.dumps(pending.data, salt=SALT, compress=False)


def _burnt(nonce):
    return Lockout.objects.filter(scope=Lockout.SCOPE_PENDING, key_hash=ratelimit.key_hash("pending", nonce)).exists()


def load(request):
    token = request.session.get(sess.PENDING_KEY)
    if not token:
        return None
    try:
        data = signing.loads(token, salt=SALT, max_age=int(conf.get("PENDING_TTL")))
    except signing.BadSignature:
        request.session.pop(sess.PENDING_KEY, None)
        return None
    if not isinstance(data, dict) or "uid" not in data or "nonce" not in data or _burnt(data["nonce"]):
        request.session.pop(sess.PENDING_KEY, None)
        return None
    # The attempts counter also lives in the cache, so replaying an old session cookie cannot reset it.
    data["attempts"] = max(int(data.get("attempts", 0)), ratelimit.fixed_count("pend", data["nonce"]))
    return Pending(data)


def destroy(request, pending=None):
    request.session.pop(sess.PENDING_KEY, None)
    if pending is not None:
        from django.utils import timezone
        from datetime import timedelta
        Lockout.objects.update_or_create(
            scope=Lockout.SCOPE_PENDING, key_hash=ratelimit.key_hash("pending", pending.nonce),
            defaults={"until": timezone.now() + timedelta(seconds=int(conf.get("PENDING_TTL")) + 5),
                      "reason": "pending login destroyed"})


def record_failure(request, pending):
    """Count a wrong code. Returns attempts left; at zero the pending login is destroyed."""
    n = ratelimit.fixed_hit("pend", pending.nonce, int(conf.get("PENDING_TTL")) + 5)
    pending.data["attempts"] = n
    left = int(conf.get("PENDING_MAX_ATTEMPTS")) - n
    if left <= 0:
        destroy(request, pending)
        return 0
    save(request, pending)
    return left
