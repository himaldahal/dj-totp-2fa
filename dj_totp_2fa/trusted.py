"""Trusted browser cookie: a random 256 bit token, stored only as a SHA-256 hash and bound to one user."""
import hashlib
import secrets
from datetime import timedelta

from django.utils import timezone

from . import conf, events
from .clientip import storable_ip
from .models import TrustedBrowser


def enabled():
    return int(conf.get("REMEMBER_BROWSER") or 0) > 0


def _hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def cookie_name():
    return conf.get("REMEMBER_COOKIE_NAME")


def _set_cookie(request, response, token):
    days = int(conf.get("REMEMBER_BROWSER"))
    response.set_cookie(cookie_name(), token, max_age=days * 86400, httponly=True, secure=request.is_secure(),
                        samesite="Lax", path="/")


def issue(request, response, user):
    """Create a trusted browser for ``user`` and set the cookie on ``response``."""
    token = secrets.token_urlsafe(32)
    row = TrustedBrowser.objects.create(
        user=user, token_hash=_hash(token), label=events.summarize_ua(request.META.get("HTTP_USER_AGENT", "")),
        user_agent_summary=events.request_user_agent(request)[:160], ip=storable_ip(request),
        expires_at=timezone.now() + timedelta(days=int(conf.get("REMEMBER_BROWSER"))))
    _set_cookie(request, response, token)
    events.record("trusted_added", request, user=user, browser=row.pk)
    return row


def lookup(request, user):
    """The TrustedBrowser matching the request cookie for ``user``, else None. Rotates the token when configured."""
    if not enabled() or not user or not getattr(user, "pk", None):
        return None
    token = request.COOKIES.get(cookie_name())
    if not token or len(token) > 200:
        return None
    row = TrustedBrowser.objects.filter(token_hash=_hash(token), user=user, expires_at__gt=timezone.now()).first()
    if row is None:
        return None
    row.last_seen_at = timezone.now()
    fields = ["last_seen_at"]
    if conf.get("ROTATE_TRUSTED_TOKEN"):
        new = secrets.token_urlsafe(32)
        row.token_hash = _hash(new)
        fields.append("token_hash")
        request._dj_totp_new_cookie = new
    row.save(update_fields=fields)
    return row


def apply_rotation(request, response):
    token = getattr(request, "_dj_totp_new_cookie", None)
    if token:
        _set_cookie(request, response, token)
        request._dj_totp_new_cookie = None


def forget_cookie(response):
    response.delete_cookie(cookie_name(), path="/", samesite="Lax")


def revoke(user, pk=None, request=None):
    qs = TrustedBrowser.objects.filter(user=user)
    if pk is not None:
        qs = qs.filter(pk=pk)
    n = qs.count()
    qs.delete()
    if n:
        events.record("trusted_revoked", request, user=user, count=n)
    return n
