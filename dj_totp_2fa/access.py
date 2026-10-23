"""Decides whether a request has satisfied two-factor authentication. Shared by the middleware and decorators."""
import re
import time

from django.conf import settings
from django.contrib import messages
from django.urls import Resolver404, resolve
from django.utils.translation import gettext as _

from . import conf, events, policy, session as sess, trusted

DEFAULT_EXEMPT_NAMES = {"login", "logout", "admin:login", "admin:logout", "admin:jsi18n", "set_language", "javascript-catalog"}
NAG_INTERVAL = 3600


def resolved_names(request):
    try:
        match = resolve(request.path_info)
    except Resolver404:
        return "", ""
    full = match.view_name or ""
    return match.url_name or "", full


def matches(entries, request, name, full):
    for entry in entries or []:
        if entry in (name, full):
            return True
        try:
            if re.match(entry, request.path_info):
                return True
        except re.error:
            continue
    return False


def is_exempt_request(request):
    static_url = getattr(settings, "STATIC_URL", None) or ""
    if static_url and request.path.startswith(static_url) and not static_url.startswith("http"):
        return True
    name, full = resolved_names(request)
    if full.startswith("dj_totp_2fa:"):
        return True
    if full in DEFAULT_EXEMPT_NAMES:
        return True
    return matches(conf.get("EXEMPT_URLS"), request, name, full)


def needs_fresh(request):
    name, full = resolved_names(request)
    return matches(conf.get("REQUIRE_REVERIFY_FOR"), request, name, full)


def nag(request, until):
    now = time.time()
    last = request.session.get(sess.NAG_KEY, 0)
    if now - last < NAG_INTERVAL:
        return
    request.session[sess.NAG_KEY] = now
    from django.utils import timezone
    days = max(0, (until - timezone.now()).days)
    messages.add_message(request, messages.WARNING, _("Set up two-factor authentication. It becomes mandatory in %(days)d days.") % {"days": days}, fail_silently=True)


def evaluate(request, strict=False):
    """None when the request may proceed, otherwise 'verify' or 'enrol'.

    ``strict`` is for decorators: a user without any 2FA is sent to enrol even when no policy requires it.
    """
    user = request.user
    if not user.is_authenticated:
        return None
    if sess.is_verified(request):
        return None
    if policy.request_has_device(request):
        row = trusted.lookup(request, user)
        if row is not None:
            sess.mark_verified(request, user, "trusted_browser", fresh=False)
            events.record("trusted_login", request, user=user, browser=row.pk)
            return None
        return "verify"
    if policy.is_required(user, request):
        until = policy.grace_until(user)
        from django.utils import timezone
        if until is not None and until > timezone.now() and not strict:
            nag(request, until)
            return None
        return "enrol"
    return "enrol" if strict else None
