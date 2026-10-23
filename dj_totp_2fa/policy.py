"""Who must use two-factor authentication, and whether they currently may skip it."""
from datetime import timedelta

from django.utils import timezone

from . import conf, events
from .models import TOTPDevice, TwoFactorProfile


def has_device(user):
    if not user or not getattr(user, "is_authenticated", False):
        return False
    return TOTPDevice.objects.filter(user=user, confirmed=True).exists()


def request_has_device(request):
    """has_device() cached on the request object."""
    cached = getattr(request, "_dj_totp_has_device", None)
    if cached is None:
        cached = has_device(request.user)
        request._dj_totp_has_device = cached
    return cached


def is_exempt(user):
    profile = TwoFactorProfile.objects.filter(user=user, exempt=True).exists()
    if profile:
        return True
    rule = conf.get("EXEMPT_USERS")
    if callable(rule):
        return bool(rule(user))
    wanted = {str(v) for v in (rule or [])}
    return bool(wanted) and (str(user.get_username()) in wanted or str(user.pk) in wanted)


def is_required(user, request=None):
    """Does the REQUIRED policy apply to this user (ignoring whether they already enrolled)?"""
    if not user or not user.is_authenticated:
        return False
    rule = conf.get("REQUIRED")
    if not rule:
        return False
    if is_exempt(user):
        return False
    if callable(rule):
        return bool(rule(user, request))
    if rule is True:
        return True
    if rule == "staff":
        return bool(user.is_staff or user.is_superuser)
    if rule == "superuser":
        return bool(user.is_superuser)
    if isinstance(rule, (list, tuple, set)):
        return user.groups.filter(name__in=list(rule)).exists()
    return False


def grace_until(user):
    """Deadline for a required, not yet enrolled user, starting the clock on first sight. None means no grace."""
    days = int(conf.get("ENROLMENT_GRACE_DAYS") or 0)
    if days <= 0:
        return None
    profile, created = TwoFactorProfile.objects.get_or_create(user=user)
    if profile.grace_until is None:
        now = timezone.now()
        profile.grace_started_at = now
        profile.grace_until = now + timedelta(days=days)
        profile.save(update_fields=["grace_started_at", "grace_until"])
        events.record("grace_started", None, user=user, until=profile.grace_until.isoformat())
    return profile.grace_until


def in_grace(user):
    until = grace_until(user)
    return until is not None and until > timezone.now()


def status(request):
    """Summary used by the middleware, templates and the API."""
    user = request.user
    from . import session as sess
    enabled = request_has_device(request)
    required = is_required(user, request)
    return {"enabled": enabled, "required": required, "verified": sess.is_verified(request),
            "grace_until": None if enabled or not required else grace_until(user)}
