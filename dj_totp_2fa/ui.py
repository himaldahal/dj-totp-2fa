"""Rendering helpers shared by every 2FA page: theme assets, security headers, JSON errors, redirects."""
import re
import time
from urllib.parse import urlencode

from django.contrib import messages
from django.core import signing
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.urls import NoReverseMatch, reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext as _

from . import conf

THEMES = ("clean", "midnight", "aurora", "auto")
FORM_SALT = "dj_totp_2fa.form-token"


def theme():
    value = str(conf.get("THEME")).lower()
    return value if value in THEMES else "clean"


def theme_css(name=None):
    name = name or theme()
    files = {"clean": ["clean"], "midnight": ["midnight"], "aurora": ["aurora"], "auto": ["clean", "midnight"]}[name]
    return ["dj_totp_2fa/css/base.css"] + ["dj_totp_2fa/css/themes/%s.css" % f for f in files]


def secure_headers(response):
    response["Cache-Control"] = "no-store, no-cache, max-age=0, must-revalidate, private"
    response["Pragma"] = "no-cache"
    response["X-Frame-Options"] = "DENY"
    response["Referrer-Policy"] = "no-referrer"
    response["X-Content-Type-Options"] = "nosniff"
    return response


def ui_context(request):
    from .api import get_issuer
    return {
        "totp_theme": theme(), "totp_css": theme_css(), "totp_extra_css": list(conf.get("EXTRA_CSS") or []),
        "totp_brand": conf.get("BRAND_NAME") or get_issuer(request), "totp_logo": conf.get("LOGO_URL"),
        "totp_base": conf.get("BASE_TEMPLATE"), "totp_remember_days": int(conf.get("REMEMBER_BROWSER") or 0),
    }


def page(request, template, context=None, status=200, **kwargs):
    ctx = ui_context(request)
    ctx.update(context or {})
    response = render(request, template, ctx, status=status, **kwargs)
    return secure_headers(response)


def url(name, **query):
    base = reverse("dj_totp_2fa:" + name)
    query = {k: v for k, v in query.items() if v}
    return base + ("?" + urlencode(query) if query else "")


def safe_next(request, candidate):
    if candidate and url_has_allowed_host_and_scheme(candidate, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
        return candidate
    return ""


def add_message(request, level, text):
    messages.add_message(request, level, text, fail_silently=True)


def wants_json(request):
    for prefix in conf.get("API_PREFIXES") or []:
        if request.path_info.startswith(prefix) or request.path.startswith(prefix):
            return True
    accept = request.headers.get("Accept", "")
    if "application/json" in accept and "text/html" not in accept.split("application/json")[0]:
        return True
    return (request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or (request.content_type or "").startswith("application/json"))


def json_error(code, detail, status, **extra):
    response = JsonResponse(dict({"ok": False, "code": code, "detail": str(detail)}, **extra), status=status)
    if "retry_after" in extra and extra["retry_after"]:
        response["Retry-After"] = str(int(extra["retry_after"]))
    return secure_headers(response)


def json_ok(payload=None, status=200):
    return secure_headers(JsonResponse(dict({"ok": True}, **(payload or {})), status=status))


def challenge_response(request, action, next_url=None):
    """What an unverified request gets. action is 'verify', 'enrol' or 'reverify'."""
    next_url = next_url if next_url is not None else request.get_full_path()
    details = {"verify": ("verify", _("A verification code is required.")),
               "reverify": ("verify", _("Please confirm with a fresh verification code.")),
               "enrol": ("setup", _("Two-factor authentication must be set up for this account."))}[action]
    try:
        target = url(details[0], next=next_url, fresh="1" if action == "reverify" else "")
    except NoReverseMatch:
        target = "/"
    if wants_json(request):
        status = 403 if action == "enrol" else 401
        return json_error("two_factor_required", details[1], status, action=action, url=target)
    return secure_headers(HttpResponseRedirect(target))


def new_form_token():
    return signing.dumps({"t": time.time()}, salt=FORM_SALT)


def form_token_ok(token):
    """False for a missing, forged or too fresh token (the form was 'submitted' faster than a person can)."""
    minimum = float(conf.get("MIN_SUBMIT_SECONDS") or 0)
    if minimum <= 0:
        return True
    try:
        data = signing.loads(token or "", salt=FORM_SALT, max_age=3600 * 6)
    except signing.BadSignature:
        return False
    return time.time() - float(data["t"]) >= minimum


def honeypot_tripped(request):
    name = conf.get("HONEYPOT_FIELD")
    return bool(name and request.POST.get(name))


def group_for_display(text, n=4):
    return " ".join(text[i:i + n] for i in range(0, len(text), n))


CODE_IN_URL = re.compile(r"^(code|otp|token|recovery_code|totp)$", re.I)
