"""Email notifications to the user and the staff alert hook."""
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.translation import gettext as _

from . import conf
from .logutil import logger

SUBJECTS = {
    "lockout": lambda: _("Multiple failed two-factor attempts on your account"),
    "trusted_browser": lambda: _("A browser was trusted for your account"),
    "disabled": lambda: _("Two-factor authentication was turned off"),
    "device_added": lambda: _("A new authenticator was added to your account"),
    "device_removed": lambda: _("An authenticator was removed from your account"),
    "recovery_used": lambda: _("A recovery code was used on your account"),
    "recovery_low": lambda: _("You are running low on recovery codes"),
    "recovery_regenerated": lambda: _("Your recovery codes were regenerated"),
}


def notify(user, event, request=None, **context):
    if not conf.get("NOTIFY").get(event, False):
        return False
    custom = conf.get("NOTIFY_SENDER")
    if custom:
        custom(user, event, context)
        return True
    email = getattr(user, "email", "")
    if not email or event not in SUBJECTS:
        return False
    from .api import get_issuer
    ctx = dict(context, user=user, event=event, site=get_issuer(request))
    try:
        body = render_to_string("dj_totp_2fa/email/%s.txt" % event, ctx)
        send_mail(str(SUBJECTS[event]()), body, conf.get("EMAIL_FROM") or settings.DEFAULT_FROM_EMAIL, [email], fail_silently=False)
    except Exception:  # an unreachable mail server must never break a login
        logger("security").warning("Could not send %s notice to user %s", event, user.pk, exc_info=True)
        return False
    return True


def alert_staff(event, details):
    hook = conf.get("STAFF_ALERT")
    if hook:
        try:
            hook(event, details)
        except Exception:
            logger("security").exception("STAFF_ALERT hook failed")
