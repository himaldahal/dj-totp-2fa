"""Server rendered pages. Every response carries no-store and anti-framing headers (see ui.secure_headers)."""
from datetime import timedelta

from django.conf import settings
from django.contrib import auth, messages
from django.contrib.auth import get_user_model
from django.contrib.auth.views import LoginView, redirect_to_login
from django.core.exceptions import ValidationError
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import get_object_or_404, resolve_url
from django.urls import reverse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.translation import gettext as _, gettext_lazy as _l
from django.views import View
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters

from . import api, conf, events, pending as pending_mod, policy, ratelimit, session as sess, trusted, ui
from .clientip import is_denied, client_ip
from .forms import DeviceNameForm, DisableForm, ReauthForm, SetupConfirmForm, VerifyForm
from .models import RecoveryCode, TOTPDevice, TrustedBrowser, TwoFactorEvent

UserModel = get_user_model()

EVENT_LABELS = {
    "verified": _l("Signed in with a code"), "failed": _l("Wrong code entered"), "lockout": _l("Account locked after failed attempts"),
    "recovery_used": _l("Recovery code used"), "device_added": _l("Authenticator added"), "device_removed": _l("Authenticator removed"),
    "device_renamed": _l("Authenticator renamed"), "disabled": _l("Two-factor authentication turned off"),
    "recovery_regenerated": _l("Recovery codes regenerated"), "trusted_added": _l("Browser trusted"),
    "trusted_revoked": _l("Trusted browser revoked"), "trusted_login": _l("Signed in from a trusted browser"),
    "admin_reset": _l("Reset by an administrator"), "setup_started": _l("Setup started"), "replay": _l("Reused code refused"),
    "reauth_ok": _l("Identity re-confirmed"), "reauth_failed": _l("Identity check failed"),
}
VISIBLE_EVENTS = set(EVENT_LABELS)


def get_user_by_id(uid):
    try:
        return UserModel._default_manager.get(pk=UserModel._meta.pk.to_python(uid))
    except (UserModel.DoesNotExist, ValueError, ValidationError, TypeError):
        return None


def finish_verification(request, user, pending, method):
    """Complete a pending login or step-up. Returns the (safe) URL to go to."""
    request._dj_totp_flow = True
    if pending is not None and pending.kind == "login":
        backend = pending.backend or settings.AUTHENTICATION_BACKENDS[0]
        auth.login(request, user, backend=backend)
        if pending.data.get("browser_session"):
            request.session.set_expiry(0)
    sess.mark_verified(request, user, method)
    request.session.cycle_key()  # new session id after the privilege change
    nxt = ui.safe_next(request, pending.next) if pending is not None else ""
    if pending is not None:
        pending_mod.destroy(request)
    return nxt or resolve_url(conf.get("REDIRECT_AFTER_VERIFY") or settings.LOGIN_REDIRECT_URL)


def load_flow(request, create=True):
    """(pending, user) for the verify page: a password-step pending login, or an authenticated unverified session."""
    p = pending_mod.load(request)
    if p is not None:
        user = get_user_by_id(p.uid)
        if user is None or not user.is_active or (p.kind == "session" and str(request.user.pk) != p.uid):
            pending_mod.destroy(request)
        else:
            return p, user
    if create and request.user.is_authenticated and policy.has_device(request.user):
        wanted = request.GET.get("next") or request.POST.get("next") or ""
        p = pending_mod.create(request, request.user, next_url=ui.safe_next(request, wanted), kind="session")
        return p, request.user
    return None, None


@method_decorator([sensitive_post_parameters(), never_cache], name="dispatch")
class TwoFactorLoginView(LoginView):
    """LoginView that stops after the password step when the user has a confirmed device."""

    template_name = "dj_totp_2fa/login.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        for key, value in ui.ui_context(self.request).items():
            ctx.setdefault(key, value)
        return ctx

    def render_to_response(self, context, **kwargs):
        return ui.secure_headers(super().render_to_response(context, **kwargs))

    def form_valid(self, form):
        user = form.get_user()
        request = self.request
        if not policy.has_device(user):
            return super().form_valid(form)  # no 2FA: normal login (the middleware enforces enrolment if required)
        if is_denied(client_ip(request)):
            events.record("ip_denied", request, user=user)
            form.add_error(None, _("Sign in is not available from your network."))
            return self.form_invalid(form)
        nxt = self.get_redirect_url()
        row = trusted.lookup(request, user)
        if row is not None:
            request._dj_totp_flow = True
            auth.login(request, user, backend=getattr(user, "backend", None))
            sess.mark_verified(request, user, "trusted_browser", fresh=False)
            events.record("trusted_login", request, user=user, browser=row.pk)
            response = HttpResponseRedirect(nxt or resolve_url(settings.LOGIN_REDIRECT_URL))
            trusted.apply_rotation(request, response)
            return response
        pending = pending_mod.create(request, user, backend=getattr(user, "backend", ""), next_url=nxt, kind="login")
        if "remember_me" in request.POST or "remember_present" in request.POST:
            pending.data["browser_session"] = not request.POST.get("remember_me")
            pending_mod.save(request, pending)
        events.record("login_pending", request, user=user)
        return ui.secure_headers(HttpResponseRedirect(ui.url("verify")))


class SecureView(View):
    """Base for pages: only signed in users, and users who enabled 2FA must have verified first."""

    needs_verified = True

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return ui.secure_headers(redirect_to_login(request.get_full_path()))
        if self.needs_verified and policy.request_has_device(request) and not sess.is_verified(request):
            return ui.challenge_response(request, "verify")
        return super().dispatch(request, *args, **kwargs)


# ---------------------------------------------------------------- verify

class VerifyView(View):
    recovery = False
    template_name = "dj_totp_2fa/verify.html"

    def dispatch(self, request, *args, **kwargs):
        stray = [k for k in request.GET if ui.CODE_IN_URL.match(k)]
        if stray:
            events.record("code_in_url", request, user=request.user if request.user.is_authenticated else None)
            clean = request.GET.copy()
            for key in stray:
                clean.pop(key)
            return ui.secure_headers(HttpResponseRedirect(request.path + ("?" + clean.urlencode() if clean else "")))
        return super().dispatch(request, *args, **kwargs)

    def _flow(self, request):
        pending, user = load_flow(request)
        if pending is None:
            if request.user.is_authenticated and sess.is_verified(request) and request.method == "GET":
                return None, None, ui.secure_headers(HttpResponseRedirect(resolve_url(conf.get("REDIRECT_AFTER_VERIFY") or settings.LOGIN_REDIRECT_URL)))
            return None, None, ui.secure_headers(HttpResponseRedirect(self._login_url(request)))
        if (request.user.is_authenticated and sess.is_verified(request) and pending.kind == "session"
                and request.method == "GET" and not request.GET.get("fresh")):
            pending_mod.destroy(request)
            return None, None, ui.secure_headers(HttpResponseRedirect(ui.safe_next(request, request.GET.get("next")) or resolve_url(settings.LOGIN_REDIRECT_URL)))
        return pending, user, None

    @staticmethod
    def _login_url(request):
        try:
            return resolve_url(settings.LOGIN_URL)
        except Exception:
            return ui.url("login")

    def _render(self, request, pending, user, method, error="", locked=False, retry_after=0, left=None, status=200):
        ctx = {
            "method": method, "error": error, "locked": locked, "retry_after": retry_after, "attempts_left": left,
            "form_token": ui.new_form_token(),
            "honeypot": conf.get("HONEYPOT_FIELD"), "allow_recovery": bool(conf.get("ALLOW_RECOVERY_CODES")),
            "can_trust": trusted.enabled(), "trust_days": int(conf.get("REMEMBER_BROWSER") or 0),
            "next": pending.next if pending else "", "expires_in": pending.expires_in(), "kind": pending.kind,
            "fresh": pending.kind == "session" and sess.is_verified(request),
        }
        ctx["digits"] = self._digits(user)
        ctx["digits_range"] = range(ctx["digits"])
        response = ui.page(request, self.template_name, ctx, status=status)
        if locked and retry_after:
            response["Retry-After"] = str(int(retry_after))
        return response

    @staticmethod
    def _digits(user):
        device = TOTPDevice.objects.filter(user=user, confirmed=True).first()
        return device.digits if device else api.default_params()["digits"]

    def get(self, request):
        pending, user, redirect = self._flow(request)
        if redirect:
            return redirect
        method = "recovery" if self.recovery and conf.get("ALLOW_RECOVERY_CODES") else "totp"
        gate = ratelimit.check_gate(user, request)
        if not gate:
            return self._render(request, pending, user, method, locked=True, retry_after=gate.retry_after, status=429)
        return self._render(request, pending, user, method)

    def post(self, request):
        pending, user, redirect = self._flow(request)
        if redirect:
            return redirect
        form = VerifyForm(request.POST)
        method = form.data.get("method") if form.data.get("method") in ("totp", "recovery") else ("recovery" if self.recovery else "totp")
        if method == "recovery" and not conf.get("ALLOW_RECOVERY_CODES"):
            method = "totp"
        wait = ratelimit.throttle(request, "recovery" if method == "recovery" else "verify")
        if wait:
            return self._render(request, pending, user, method, locked=True, retry_after=wait, status=429)
        generic = _("That code did not work. Check the code and try again.")
        if not form.is_valid():
            return self._render(request, pending, user, method, error=_("Enter the code from your authenticator app."))
        if ui.honeypot_tripped(request) or not ui.form_token_ok(form.cleaned_data.get("form_token")):
            events.record("bot_suspected", request, user=user)
            ratelimit.register_failure(None, request, "bot")
            left = pending_mod.record_failure(request, pending)
            if left <= 0:
                return self._exhausted(request, pending)
            return self._render(request, pending, user, method, error=generic, left=left)
        result = api.verify_code(user, form.cleaned_data["code"], request, method=method)
        if result.ok:
            nxt = finish_verification(request, user, pending, result.method)
            response = ui.secure_headers(HttpResponseRedirect(nxt))
            if form.cleaned_data.get("trust") and trusted.enabled():
                trusted.issue(request, response, user)
                from . import notify
                notify.notify(user, "trusted_browser", request, browser=events.summarize_ua(request.META.get("HTTP_USER_AGENT", "")))
            return response
        if result.locked:
            return self._render(request, pending, user, method, locked=True, retry_after=result.retry_after, status=429)
        left = pending_mod.record_failure(request, pending)
        if left <= 0:
            return self._exhausted(request, pending)
        return self._render(request, pending, user, method, error=generic, left=left)

    def _exhausted(self, request, pending):
        events.record("pending_destroyed", request, user=get_user_by_id(pending.uid), reason="too many wrong codes")
        ui.add_message(request, messages.ERROR, _("Too many wrong codes. Please sign in again."))
        if pending.kind == "login":
            return ui.secure_headers(HttpResponseRedirect(self._login_url(request)))
        return ui.secure_headers(HttpResponseRedirect(ui.url("verify")))


class CancelView(View):
    """Abandon a pending login and go back to the password step."""

    def post(self, request):
        pending_mod.destroy(request)
        return ui.secure_headers(HttpResponseRedirect(VerifyView._login_url(request)))


# ---------------------------------------------------------------- overview and pages

def _overview_context(request):
    user = request.user
    devices = list(TOTPDevice.objects.filter(user=user, confirmed=True))
    trusted_qs = TrustedBrowser.objects.filter(user=user, expires_at__gt=timezone.now())
    recent = [dict(e=e, label=EVENT_LABELS[e.event]) for e in TwoFactorEvent.objects.filter(user=user, event__in=VISIBLE_EVENTS)[:6]]
    status = policy.status(request)
    return {
        "devices": devices, "enabled": bool(devices), "remaining": api.recovery_codes_remaining(user),
        "recovery_total": RecoveryCode.objects.filter(user=user).count(), "trusted_count": trusted_qs.count(),
        "recent": recent, "required": status["required"], "grace_until": status["grace_until"],
        "low_codes": bool(devices) and api.recovery_codes_remaining(user) <= conf.int_setting("RECOVERY_LOW_THRESHOLD", 0),
        "max_devices": api.max_devices_reached(user),
    }


class OverviewView(SecureView):
    def get(self, request):
        return ui.page(request, "dj_totp_2fa/overview.html", dict(_overview_context(request), active="overview"))


class DoneView(SecureView):
    def get(self, request):
        return ui.page(request, "dj_totp_2fa/done.html", {"active": "overview", "next": ui.safe_next(request, request.GET.get("next"))
                                                              or ui.url("overview")})


class DevicesView(SecureView):
    def get(self, request):
        ctx = _overview_context(request)
        ctx.update(active="devices", password_ok=request.user.has_usable_password(), can_remove_last=not ctx["required"])
        return ui.page(request, "dj_totp_2fa/devices.html", ctx)


class TrustedView(SecureView):
    def get(self, request):
        rows = TrustedBrowser.objects.filter(user=request.user, expires_at__gt=timezone.now())
        current = request.COOKIES.get(trusted.cookie_name())
        import hashlib
        current_hash = hashlib.sha256(current.encode()).hexdigest() if current else ""
        return ui.page(request, "dj_totp_2fa/trusted.html", {"browsers": rows, "current_hash": current_hash, "active": "trusted",
                                                            "enabled": trusted.enabled()})


class TrustedRevokeView(SecureView):
    def post(self, request, pk=None):
        if pk is not None:
            get_object_or_404(TrustedBrowser, pk=pk, user=request.user)
        n = trusted.revoke(request.user, pk, request)
        response = ui.secure_headers(HttpResponseRedirect(ui.url("trusted")))
        if pk is None:
            trusted.forget_cookie(response)
        ui.add_message(request, messages.SUCCESS, _("Trusted browser revoked.") if pk else _("All trusted browsers revoked."))
        return response


# ---------------------------------------------------------------- re-authentication helper

def reauth_or_error(request, form):
    """Returns (ok, error text, retry_after) after checking the password/code fields of a bound valid form."""
    result = api.reauthenticate(request.user, request, password=form.cleaned_data.get("password", ""), code=form.cleaned_data.get("code", ""))
    if result.ok:
        sess.mark_fresh(request)
        return True, "", 0
    if result.locked:
        return False, _("Too many attempts. Please wait before trying again."), result.retry_after
    return False, _("Your password or code was not correct."), 0


# ---------------------------------------------------------------- setup

SETUP_MAX_AGE = 1800
APPS = ["Google Authenticator", "Microsoft Authenticator", "Authy", "1Password", "Aegis", "Bitwarden"]


class SetupView(SecureView):
    template_name = "dj_totp_2fa/setup.html"

    def _state(self, request, fresh=False):
        state = request.session.get(sess.SETUP_KEY)
        import time
        if fresh or not state or time.time() - state.get("t", 0) > SETUP_MAX_AGE:
            state = {"secret": api.new_secret(), "t": time.time()}
            request.session[sess.SETUP_KEY] = state
            events.record("setup_started", request, user=request.user)
        return state

    def _context(self, request, state, error="", extra=None):
        params = api.default_params()
        from . import totp as core
        uri = core.otpauth_uri(state["secret"], api.account_label(request.user), api.get_issuer(request), **params)
        status = policy.status(request)
        ctx = {
            "secret": state["secret"], "secret_grouped": api.group4(state["secret"]), "uri": uri, "issuer": api.get_issuer(request),
            "account": api.account_label(request.user), "digits": params["digits"], "period": params["period"],
            "algorithm": params["algorithm"], "apps": APPS, "error": error, "active": "setup",
            "forced": status["required"] and not status["enabled"] and status["grace_until"] is None,
            "next": ui.safe_next(request, request.GET.get("next") or request.POST.get("next")),
            "default_name": api._unique_name(request.user, "Authenticator"), "first_device": not status["enabled"],
        }
        ctx.update(extra or {})
        return ctx

    def get(self, request):
        if api.max_devices_reached(request.user):
            ui.add_message(request, messages.WARNING, _("You have reached the maximum number of devices."))
            return ui.secure_headers(HttpResponseRedirect(ui.url("devices")))
        state = self._state(request)
        return ui.page(request, self.template_name, self._context(request, state))

    def post(self, request):
        if request.POST.get("action") == "restart":
            state = self._state(request, fresh=True)
            return ui.page(request, self.template_name, self._context(request, state))
        wait = ratelimit.throttle(request, "setup")
        state = self._state(request)
        if wait:
            return ui.page(request, self.template_name, self._context(request, state, error=_("Too many attempts. Please wait before trying again.")), status=429)
        form = SetupConfirmForm(request.POST)
        if not form.is_valid():
            return ui.page(request, self.template_name, self._context(request, state, error=_("Enter the 6-digit code shown in your app.")))
        result, device = api.confirm_secret(request.user, state["secret"], form.cleaned_data["code"], request,
                                            name=form.cleaned_data.get("name") or "Authenticator")
        if not result.ok:
            if result.reason == "max_devices":
                ui.add_message(request, messages.WARNING, _("You have reached the maximum number of devices."))
                return ui.secure_headers(HttpResponseRedirect(ui.url("devices")))
            status = 429 if result.locked else 200
            msg = result.message if result.locked else _("That code did not match. Make sure your phone's clock is automatic and try the next code.")
            response = ui.page(request, self.template_name, self._context(request, state, error=msg), status=status)
            if result.retry_after:
                response["Retry-After"] = str(int(result.retry_after))
            return response
        request.session.pop(sess.SETUP_KEY, None)
        request._dj_totp_flow = True
        sess.mark_verified(request, request.user, "totp")
        request.session.cycle_key()
        nxt = ui.safe_next(request, request.POST.get("next"))
        if api.recovery_codes_remaining(request.user) == 0:
            codes = api.generate_recovery_codes(request.user, request=request)
            return ui.page(request, "dj_totp_2fa/recovery_codes.html", {
                "codes": codes, "first_time": True, "active": "recovery", "done_url": ui.url("done", next=nxt), "device": device})
        ui.add_message(request, messages.SUCCESS, _("Authenticator added."))
        return ui.secure_headers(HttpResponseRedirect(nxt or ui.url("devices")))


# ---------------------------------------------------------------- devices

class DeviceActionView(SecureView):
    action = ""
    template_name = "dj_totp_2fa/device_action.html"

    def _device(self, request, pk):
        return get_object_or_404(TOTPDevice, pk=pk, user=request.user, confirmed=True)

    def get(self, request, pk):
        device = self._device(request, pk)
        return ui.page(request, self.template_name, {"device": device, "action": self.action, "active": "devices",
                                                     "last_device": TOTPDevice.objects.filter(user=request.user, confirmed=True).count() == 1})

    def post(self, request, pk):
        device = self._device(request, pk)
        form = DeviceNameForm(request.POST) if self.action == "rename" else ReauthForm(request.POST)
        ctx = {"device": device, "action": self.action, "active": "devices"}
        last = TOTPDevice.objects.filter(user=request.user, confirmed=True).count() == 1
        ctx["last_device"] = last
        if not form.is_valid():
            ctx["error"] = _("Enter your password or a current code.") if self.action == "remove" else _("Enter a name and your password or a current code.")
            return ui.page(request, self.template_name, ctx)
        if self.action == "remove" and last:
            ui.add_message(request, messages.ERROR, _("This is your only authenticator. Turn off two-factor authentication instead."))
            return ui.secure_headers(HttpResponseRedirect(ui.url("disable")))
        ok, error, retry = reauth_or_error(request, form)
        if not ok:
            ctx["error"] = error
            response = ui.page(request, self.template_name, ctx, status=429 if retry else 200)
            if retry:
                response["Retry-After"] = str(retry)
            return response
        if self.action == "rename":
            api.rename_device(device, form.cleaned_data["name"], request)
            ui.add_message(request, messages.SUCCESS, _("Authenticator renamed."))
        else:
            api.remove_device(device, request)
            ui.add_message(request, messages.SUCCESS, _("Authenticator removed."))
        return ui.secure_headers(HttpResponseRedirect(ui.url("devices")))


class RenameDeviceView(DeviceActionView):
    action = "rename"


class RemoveDeviceView(DeviceActionView):
    action = "remove"


# ---------------------------------------------------------------- recovery codes and disable

class RecoveryView(SecureView):
    def get(self, request):
        ctx = _overview_context(request)
        ctx["active"] = "recovery"
        return ui.page(request, "dj_totp_2fa/recovery.html", ctx)

    def post(self, request):
        if not policy.request_has_device(request):
            return ui.secure_headers(HttpResponseRedirect(ui.url("setup")))
        form = ReauthForm(request.POST)
        ctx = dict(_overview_context(request), active="recovery")
        if not form.is_valid():
            ctx["error"] = _("Enter your password or a current code.")
            return ui.page(request, "dj_totp_2fa/recovery.html", ctx)
        ok, error, retry = reauth_or_error(request, form)
        if not ok:
            ctx["error"] = error
            return ui.page(request, "dj_totp_2fa/recovery.html", ctx, status=429 if retry else 200)
        codes = api.generate_recovery_codes(request.user, request=request)
        from . import notify
        notify.notify(request.user, "recovery_regenerated", request)
        return ui.page(request, "dj_totp_2fa/recovery_codes.html", {
            "codes": codes, "first_time": False, "active": "recovery", "done_url": ui.url("overview")})


class DisableView(SecureView):
    def get(self, request):
        return ui.page(request, "dj_totp_2fa/disable.html", dict(_overview_context(request), active="disable",
                                                                  blocked=policy.is_required(request.user, request)))

    def post(self, request):
        ctx = dict(_overview_context(request), active="disable", blocked=policy.is_required(request.user, request))
        if ctx["blocked"]:
            return ui.page(request, "dj_totp_2fa/disable.html", ctx, status=403)
        form = DisableForm(request.POST)
        if not form.is_valid():
            ctx["error"] = _("Enter your password or a current code and tick the confirmation box.")
            return ui.page(request, "dj_totp_2fa/disable.html", ctx)
        ok, error, retry = reauth_or_error(request, form)
        if not ok:
            ctx["error"] = error
            return ui.page(request, "dj_totp_2fa/disable.html", ctx, status=429 if retry else 200)
        api.disable(request.user, request, actor=request.user)
        sess.clear(request)
        response = ui.secure_headers(HttpResponseRedirect(ui.url("overview")))
        trusted.forget_cookie(response)
        ui.add_message(request, messages.SUCCESS, _("Two-factor authentication is now off."))
        return response
