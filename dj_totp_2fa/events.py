"""Append-only audit trail plus structured log lines."""
import logging
import re

from . import conf
from .clientip import client_ip, storable_ip
from .logutil import log_event
from .models import TwoFactorEvent

# event name -> logger child
CHILD = {
    "login_pending": "auth", "verified": "auth", "failed": "auth", "pending_destroyed": "auth", "trusted_login": "auth",
    "recovery_used": "auth", "step_up": "auth", "reauth_failed": "auth", "reauth_ok": "auth",
    "lockout": "security", "ip_denied": "security", "global_alert": "security", "suspicious": "security",
    "code_in_url": "security", "throttled": "security", "bot_suspected": "security", "replay": "security",
    "setup_started": "setup", "device_added": "setup", "device_removed": "setup", "device_renamed": "setup",
    "disabled": "setup", "recovery_regenerated": "setup", "trusted_added": "setup", "trusted_revoked": "setup",
    "grace_started": "setup",
    "admin_reset": "admin", "admin_disabled": "admin", "lockout_cleared": "admin",
}
LEVEL = {"lockout": logging.WARNING, "ip_denied": logging.WARNING, "global_alert": logging.ERROR,
         "suspicious": logging.WARNING, "failed": logging.INFO, "admin_reset": logging.WARNING,
         "code_in_url": logging.WARNING, "bot_suspected": logging.WARNING, "replay": logging.WARNING}


def summarize_ua(ua):
    """'Firefox on Linux' from a User-Agent string. Short and free of version numbers."""
    ua = ua or ""
    browser = next((name for pat, name in (
        (r"Edg(e|A|iOS)?/", "Edge"), (r"OPR/|Opera", "Opera"), (r"Firefox/|FxiOS", "Firefox"),
        (r"Chrome/|CriOS", "Chrome"), (r"Safari/", "Safari")) if re.search(pat, ua)), "Browser")
    system = next((name for pat, name in (
        (r"Windows", "Windows"), (r"Android", "Android"), (r"iPhone|iPad|iOS", "iOS"), (r"Mac OS X|Macintosh", "macOS"),
        (r"Linux|X11", "Linux")) if re.search(pat, ua)), "")
    return ("%s on %s" % (browser, system) if system else browser)[:160]


def request_user_agent(request):
    if request is None or not conf.get("STORE_USER_AGENT"):
        return ""
    return (request.META.get("HTTP_USER_AGENT", "") or "")[:255]


def record(event, request=None, user=None, identifier="", **details):
    if user is not None and not getattr(user, "pk", None):
        user = None
    ident = identifier or (user.get_username() if user is not None else "")
    obj = TwoFactorEvent.objects.create(
        user=user, identifier=ident[:150], event=event, ip=storable_ip(request) if request is not None else None,
        user_agent=request_user_agent(request), details={k: v for k, v in details.items() if v is not None})
    log_event(CHILD.get(event, "auth"), LEVEL.get(event, logging.INFO), event,
              user=getattr(user, "pk", None), ip=client_ip(request) if request is not None else "", **details)
    return obj
