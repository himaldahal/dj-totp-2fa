"""Signal receivers that keep the session honest for logins that did not go through our view."""
from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver

from . import session as sess


@receiver(user_logged_in, dispatch_uid="dj_totp_2fa.reset_verified")
def reset_verified_on_login(sender, request, user, **kwargs):
    """Any login that is not completing our own 2FA flow starts unverified.

    This is what makes enforcement work for admin, allauth and custom login views: the middleware sees an
    authenticated but unverified session and sends the user to the verify (or enrolment) page.
    """
    if request is None or getattr(request, "_dj_totp_flow", False):
        return
    session = getattr(request, "session", None)
    if session is not None:
        sess.clear(request)
