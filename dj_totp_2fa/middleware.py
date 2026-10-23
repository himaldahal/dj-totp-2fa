"""Enforces two-factor authentication for every route, whatever login view created the session."""
from . import access, conf, session as sess, trusted, ui


class TwoFactorMiddleware:
    """Place after AuthenticationMiddleware (and SessionMiddleware, MessageMiddleware)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if user is not None:
            self.attach(request)
        if user is not None and user.is_authenticated and not access.is_exempt_request(request):
            action = access.evaluate(request)
            if action is None and sess.is_verified(request) and access.needs_fresh(request) and not sess.is_fresh(request, conf.get("REVERIFY_MAX_AGE")):
                action = "reverify"
            if action:
                return ui.challenge_response(request, action)
        response = self.get_response(request)
        trusted.apply_rotation(request, response)
        return response

    @staticmethod
    def attach(request):
        request.is_two_factor_verified = lambda: sess.is_verified(request)
        try:
            request.user.is_two_factor_verified = request.is_two_factor_verified
        except Exception:  # custom user objects that refuse attributes
            pass
