"""Optional Django REST framework integration (imported lazily; DRF is not a dependency).

    from dj_totp_2fa.drf import two_factor_permission
    class SecretView(APIView):
        permission_classes = [IsAuthenticated, two_factor_permission()]
"""
from django.core.exceptions import ImproperlyConfigured

from . import access, session as sess


def two_factor_permission(fresh_seconds=None):
    """Build a DRF permission class: authenticated users must have verified 2FA (and optionally within N seconds)."""
    try:
        from rest_framework.exceptions import APIException
        from rest_framework.permissions import BasePermission
    except ImportError:
        raise ImproperlyConfigured("Django REST framework is not installed.")

    class TwoFactorRequired(APIException):
        status_code = 401
        default_code = "two_factor_required"
        default_detail = "Two-factor verification is required."

    class IsTwoFactorVerified(BasePermission):
        message = "Two-factor verification is required."

        def has_permission(self, request, view):
            dj_request = getattr(request, "_request", request)
            user = dj_request.user
            if not user.is_authenticated:
                return False
            action = access.evaluate(dj_request, strict=True)
            if action:
                raise TwoFactorRequired()
            if fresh_seconds is not None and sess.is_verified(dj_request) and not sess.is_fresh(dj_request, fresh_seconds):
                raise TwoFactorRequired()
            return True

    return IsTwoFactorVerified
