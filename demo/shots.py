"""Helper views for scripts/capture_screenshots.py. Only mounted when DEMO_SHOTS=1 (never in a real project).

Every scenario prepares the session and then redirects (or renders) in a single request, because the headless
browser is started once per screenshot and does not keep cookies between runs.
"""
from django.contrib.auth import get_user_model
from django.http import Http404, HttpResponseRedirect

from dj_totp_2fa import api, pending, ratelimit, totp as core, ui
from dj_totp_2fa.models import Lockout, TOTPDevice
from dj_totp_2fa.views import VerifyView, finish_verification


def current_code(user):
    """What the user's authenticator would show now (the same idea as the totp_code command; demo only)."""
    device = TOTPDevice.objects.filter(user=user, confirmed=True).first()
    return core.totp(device.secret_bytes, None, device.digits, device.period, device.algorithm)


def sign_in_fully(request, user):
    """A genuine login: password step, then a real code through api.verify_code."""
    request.session.flush()
    TOTPDevice.objects.filter(user=user).update(last_used_step=0)  # demo only: several logins inside one 30 second step
    p = pending.create(request, user, backend="django.contrib.auth.backends.ModelBackend", next_url="/", kind="login")
    result = api.verify_code(user, current_code(user), request, method="totp")
    assert result.ok, result
    finish_verification(request, user, p, result.method)


def shot(request, scenario):
    User = get_user_model()
    target = request.GET.get("to", "/")
    ratelimit.clear_lockouts(everything=True)  # an earlier "locked" screenshot must not affect the others
    if scenario == "logout":
        request.session.flush()
        return HttpResponseRedirect(target)
    if scenario in ("verify", "verify-error", "verify-locked", "verify-recovery"):
        user = User.objects.get(username="alice")
        request.session.flush()
        p = pending.create(request, user, backend="django.contrib.auth.backends.ModelBackend", next_url="/", kind="login")
        if scenario == "verify":
            return HttpResponseRedirect(ui.url("verify"))
        if scenario == "verify-recovery":
            return HttpResponseRedirect(ui.url("verify_recovery"))
        if scenario == "verify-error":
            p.data["attempts"] = 1
            return VerifyView()._render(request, p, user, "totp", error="That code did not work. Check the code and try again.", left=4)
        ratelimit.apply_lockout(Lockout.SCOPE_USER, user.pk, user=user, reason="demo")
        ratelimit.apply_lockout(Lockout.SCOPE_USER, user.pk, user=user, reason="demo")  # second level: 5 minutes
        return HttpResponseRedirect(ui.url("verify"))
    username = {"alice": "alice", "newbie": "newbie", "forced": "forced"}.get(scenario)
    if scenario == "recovery-codes":
        user = User.objects.get(username="alice")
        sign_in_fully(request, user)
        codes = api.generate_recovery_codes(user, request=request)
        return ui.page(request, "dj_totp_2fa/recovery_codes.html", {
            "codes": codes, "first_time": True, "active": "recovery", "done_url": ui.url("done")})
    if username is None:
        raise Http404(scenario)
    user = User.objects.get(username=username)
    request.session.flush()
    if username == "alice":
        sign_in_fully(request, user)
    else:
        from django.contrib.auth import login
        request._dj_totp_flow = True
        login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    return HttpResponseRedirect(target)
