from django.utils.functional import SimpleLazyObject

from . import policy, session as sess


class _State:
    def __init__(self, request):
        self.request = request

    @property
    def enabled(self):
        return policy.request_has_device(self.request) if self.request.user.is_authenticated else False

    @property
    def verified(self):
        return sess.is_verified(self.request)

    @property
    def required(self):
        return policy.is_required(self.request.user, self.request)

    @property
    def devices(self):
        from .models import TOTPDevice
        return TOTPDevice.objects.filter(user=self.request.user, confirmed=True) if self.request.user.is_authenticated else []

    @property
    def grace_until(self):
        if not self.request.user.is_authenticated or self.enabled or not self.required:
            return None
        return policy.grace_until(self.request.user)


def two_factor(request):
    return {"two_factor": SimpleLazyObject(lambda: _State(request))}
