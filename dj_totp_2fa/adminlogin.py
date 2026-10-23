"""Django admin integration: the admin login requires 2FA when PROTECT_ADMIN is on.

``install()`` (called from AppConfig.ready) wraps ``AdminSite.login`` and ``AdminSite.has_permission`` once. The
decision is made at request time, so the setting can be changed without a restart in tests. ``OTPAdminSite`` is a
stricter base class for sites that must never be reachable without 2FA.
"""
from django.conf import settings
from django.contrib.admin import AdminSite
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils.translation import gettext as _

from . import access, conf, ui


def _protected():
    return bool(conf.get("PROTECT_ADMIN"))


def _login(original):
    def login(self, request, extra_context=None):
        if not _protected():
            return original(self, request, extra_context)
        if request.method == "GET" and request.user.is_authenticated and request.user.is_staff and not self.has_permission(request):
            action = access.evaluate(request, strict=isinstance(self, OTPAdminSite))
            if action:
                return ui.challenge_response(request, action, next_url=request.GET.get(REDIRECT_FIELD_NAME) or reverse("admin:index", current_app=self.name))
        if request.method == "GET" and self.has_permission(request):
            return HttpResponseRedirect(reverse("admin:index", current_app=self.name))
        from django.contrib.admin.forms import AdminAuthenticationForm
        from .views import TwoFactorLoginView
        context = {**self.each_context(request), "title": _("Log in"), "subtitle": None,
                   "app_path": request.get_full_path(), "username": request.user.get_username()}
        if REDIRECT_FIELD_NAME not in request.GET and REDIRECT_FIELD_NAME not in request.POST:
            context[REDIRECT_FIELD_NAME] = reverse("admin:index", current_app=self.name)
        context.update(extra_context or {})
        defaults = {"extra_context": context, "authentication_form": self.login_form or AdminAuthenticationForm,
                    "template_name": self.login_template or "admin/login.html"}
        request.current_app = self.name
        return TwoFactorLoginView.as_view(**defaults)(request)
    login.__doc__ = original.__doc__
    return login


def _has_permission(original):
    def has_permission(self, request):
        if not original(self, request):
            return False
        if not _protected():
            return True
        return access.evaluate(request, strict=isinstance(self, OTPAdminSite)) is None
    return has_permission


def install():
    if getattr(AdminSite, "_dj_totp_installed", False):
        return
    AdminSite.login = _login(AdminSite.login)
    AdminSite.has_permission = _has_permission(AdminSite.has_permission)
    AdminSite._dj_totp_installed = True


class OTPAdminSite(AdminSite):
    """Admin site where every user, enrolled or not, must pass 2FA (users without a device are sent to set one up)."""
