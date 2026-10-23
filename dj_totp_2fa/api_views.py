"""JSON endpoints for single page apps. Session authentication; Django's CSRF protection applies to every POST.

    GET  api/status/         who am I, is 2FA on, am I verified
    POST api/verify/         {"code": "123456", "method": "totp|recovery", "trust": false}
    POST api/setup/start/    -> secret + otpauth URI (signed in users)
    POST api/setup/confirm/  {"code": "123456", "name": "Phone"} -> recovery codes (once)
"""
import json

from django.http import JsonResponse
from django.views import View

from . import api, conf, events, pending as pending_mod, policy, ratelimit, session as sess, trusted, ui
from . import totp as core
from .views import finish_verification, load_flow, SETUP_MAX_AGE


def body(request):
    if (request.content_type or "").startswith("application/json"):
        try:
            data = json.loads(request.body or b"{}")
            return data if isinstance(data, dict) else {}
        except ValueError:
            return {}
    return request.POST


class JsonView(View):
    needs_login = True

    def dispatch(self, request, *args, **kwargs):
        if self.needs_login and not request.user.is_authenticated and not pending_mod.load(request):
            return ui.json_error("not_authenticated", "Authentication required.", 401)
        for key in request.GET:
            if ui.CODE_IN_URL.match(key):
                events.record("code_in_url", request)
                return ui.json_error("code_in_url", "Codes must never be sent in the URL.", 400)
        return super().dispatch(request, *args, **kwargs)


class StatusApi(JsonView):
    needs_login = False

    def get(self, request):
        pending = pending_mod.load(request)
        authed = request.user.is_authenticated
        data = {"authenticated": authed, "pending": bool(pending), "enabled": False, "verified": False, "required": False,
                "recovery_codes_remaining": 0, "methods": ["totp"] + (["recovery"] if conf.get("ALLOW_RECOVERY_CODES") else [])}
        if authed:
            status = policy.status(request)
            data.update(enabled=status["enabled"], verified=status["verified"], required=status["required"],
                        recovery_codes_remaining=api.recovery_codes_remaining(request.user),
                        grace_until=status["grace_until"].isoformat() if status["grace_until"] else None)
        data["urls"] = {"verify": ui.url("verify"), "setup": ui.url("setup")}
        return ui.json_ok(data)


class VerifyApi(JsonView):
    needs_login = False

    def post(self, request):
        wait = ratelimit.throttle(request, "api")
        if wait:
            return ui.json_error("rate_limited", "Too many requests.", 429, retry_after=wait)
        pending, user = load_flow(request)
        if pending is None:
            return ui.json_error("no_pending_login", "Sign in with your password first.", 401)
        data = body(request)
        code = str(data.get("code", ""))
        method = data.get("method") if data.get("method") in ("totp", "recovery") else "auto"
        if not code:
            return ui.json_error("invalid_code", "Enter a code.", 400)
        result = api.verify_code(user, code, request, method=method)
        if result.locked:
            return ui.json_error("locked", result.message, 429, retry_after=result.retry_after)
        if not result.ok:
            left = pending_mod.record_failure(request, pending)
            if left <= 0:
                return ui.json_error("pending_expired", "Too many wrong codes. Sign in again.", 401)
            return ui.json_error("invalid_code", result.message, 400, attempts_left=left)
        nxt = finish_verification(request, user, pending, result.method)
        response = ui.json_ok({"verified": True, "method": result.method, "next": nxt})
        if data.get("trust") in (True, "true", "1", "on") and trusted.enabled():
            trusted.issue(request, response, user)
        return response


class SetupStartApi(JsonView):
    def post(self, request):
        if policy.request_has_device(request) and not sess.is_verified(request):
            return ui.challenge_response(request, "verify")
        if api.max_devices_reached(request.user):
            return ui.json_error("max_devices", "Maximum number of devices reached.", 400)
        import time
        state = {"secret": api.new_secret(), "t": time.time()}
        request.session[sess.SETUP_KEY] = state
        events.record("setup_started", request, user=request.user)
        params = api.default_params()
        uri = core.otpauth_uri(state["secret"], api.account_label(request.user), api.get_issuer(request), **params)
        return ui.json_ok({"secret": state["secret"], "manual_key": api.group4(state["secret"]), "otpauth_uri": uri,
                           "issuer": api.get_issuer(request), **params})


class SetupConfirmApi(JsonView):
    def post(self, request):
        import time
        wait = ratelimit.throttle(request, "setup")
        if wait:
            return ui.json_error("rate_limited", "Too many requests.", 429, retry_after=wait)
        if policy.request_has_device(request) and not sess.is_verified(request):
            return ui.challenge_response(request, "verify")
        state = request.session.get(sess.SETUP_KEY)
        if not state or time.time() - state.get("t", 0) > SETUP_MAX_AGE:
            return ui.json_error("no_setup", "Start the setup first.", 400)
        data = body(request)
        result, device = api.confirm_secret(request.user, state["secret"], str(data.get("code", "")), request,
                                            name=str(data.get("name") or "Authenticator"))
        if not result.ok:
            if result.locked:
                return ui.json_error("locked", result.message, 429, retry_after=result.retry_after)
            code = result.reason if result.reason in ("max_devices", "denied") else "invalid_code"
            return ui.json_error(code, result.message, 400)
        request.session.pop(sess.SETUP_KEY, None)
        request._dj_totp_flow = True
        sess.mark_verified(request, request.user, "totp")
        request.session.cycle_key()
        payload = {"device": {"id": device.pk, "name": device.name}}
        if api.recovery_codes_remaining(request.user) == 0:
            payload["recovery_codes"] = api.generate_recovery_codes(request.user, request=request)
        return ui.json_ok(payload, status=201)
