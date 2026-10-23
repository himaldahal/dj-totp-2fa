"""Decorators and mixins for views that need a verified second factor."""
from functools import wraps

from django.contrib.auth.mixins import AccessMixin
from django.contrib.auth.views import redirect_to_login

from . import access, conf, session as sess, ui


def is_verified(request):
    """True when the session passed a second-factor check. Works with any user model."""
    return sess.is_verified(request)


def _guard(request, max_age=None, fresh=False):
    if not request.user.is_authenticated:
        return redirect_to_login(request.get_full_path())
    action = access.evaluate(request, strict=not fresh)
    if action:
        return ui.challenge_response(request, action)
    if fresh and sess.is_verified(request):
        limit = conf.get("FRESH_MAX_AGE") if max_age is None else max_age
        if not sess.is_fresh(request, limit):
            return ui.challenge_response(request, "reverify")
    return None


def two_factor_required(view=None):
    """The user must have passed 2FA in this session. Users without 2FA are sent to set it up."""
    def decorator(func):
        @wraps(func)
        def inner(request, *args, **kwargs):
            denied = _guard(request)
            return denied if denied is not None else func(request, *args, **kwargs)
        return inner
    return decorator(view) if callable(view) else decorator


def otp_fresh(max_age=None):
    """Step-up: a code must have been entered within ``max_age`` seconds. Users with no 2FA at all pass unless the
    REQUIRED policy applies to them (the middleware then makes them enrol)."""
    def decorator(func):
        @wraps(func)
        def inner(request, *args, **kwargs):
            if request.user.is_authenticated:
                from . import policy
                if not policy.request_has_device(request) and not policy.is_required(request.user, request):
                    return func(request, *args, **kwargs)
            denied = _guard(request, max_age, fresh=True)
            return denied if denied is not None else func(request, *args, **kwargs)
        return inner
    return decorator


class TwoFactorRequiredMixin(AccessMixin):
    def dispatch(self, request, *args, **kwargs):
        denied = _guard(request)
        return denied if denied is not None else super().dispatch(request, *args, **kwargs)


class OTPFreshMixin(AccessMixin):
    otp_max_age = None

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            from . import policy
            if not policy.request_has_device(request) and not policy.is_required(request.user, request):
                return super().dispatch(request, *args, **kwargs)
        denied = _guard(request, self.otp_max_age, fresh=True)
        return denied if denied is not None else super().dispatch(request, *args, **kwargs)
