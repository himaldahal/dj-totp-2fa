"""End-to-end check of the login flow in-process: password -> code -> protected page. Rolls everything back."""
import secrets

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction
from django.test import Client, override_settings
from django.urls import reverse

from dj_totp_2fa import api, totp as core
from dj_totp_2fa.management.commands._util import get_user, table
from dj_totp_2fa.models import TOTPDevice


class _Rollback(Exception):
    pass


class Command(BaseCommand):
    help = "Simulate password -> verify -> access with the Django test client and print PASS/FAIL per step."

    def add_arguments(self, parser):
        parser.add_argument("--user", help="Use an existing user that already has a device (no wrong-code test, nothing is kept).")

    def handle(self, *args, user=None, **options):
        rows = []

        def step(name, ok, detail=""):
            rows.append((name, "PASS" if ok else "FAIL", detail))

        try:
            with override_settings(ALLOWED_HOSTS=["*"], TOTP_MIN_SUBMIT_SECONDS=0, TOTP_FAIL_DELAY_MS=0, TOTP_RATE_LIMITS_ENABLED=False):
                with transaction.atomic():
                    self.run_flow(user, step)
                    raise _Rollback()
        except _Rollback:
            pass
        except Exception as exc:  # report, never crash with a traceback
            step("unexpected error", False, "%s: %s" % (type(exc).__name__, exc))
        self.stdout.write(table(rows, ("Step", "Result", "Detail")))
        if any(r[1] == "FAIL" for r in rows):
            raise SystemExit(1)
        self.stdout.write(self.style.SUCCESS("All steps passed. Nothing was saved."))

    def run_flow(self, username, step):
        User = get_user_model()
        password = secrets.token_urlsafe(12)
        if username:
            account = get_user(username)
            device = TOTPDevice.objects.filter(user=account, confirmed=True).first()
            if device is None:
                step("user has a confirmed device", False, "enable 2FA for this user first")
                return
            account.set_password(password)
            account.save()
        else:
            fields = {User.USERNAME_FIELD: "totp-sim-" + secrets.token_hex(4)}
            if "email" in [f.name for f in User._meta.fields] and User.USERNAME_FIELD != "email":
                fields["email"] = "sim@example.com"
            account = User._default_manager.create_user(password=password, **fields)
            device = api.create_device(account, "Simulation")
            from django.utils import timezone
            TOTPDevice.objects.filter(pk=device.pk).update(confirmed=True, confirmed_at=timezone.now())
            device.refresh_from_db()
        client = Client()
        login_url = reverse("dj_totp_2fa:login")
        r = client.post(login_url, {"username": account.get_username(), "password": password})
        step("password step redirects to the verify page", r.status_code == 302 and r["Location"].endswith(reverse("dj_totp_2fa:verify")), "HTTP %s" % r.status_code)
        step("not signed in yet", "_auth_user_id" not in client.session)
        r = client.get(reverse("dj_totp_2fa:verify"))
        step("verify page renders", r.status_code == 200, "HTTP %s" % r.status_code)
        if not username:
            r = client.post(reverse("dj_totp_2fa:verify"), {"code": "000000" if core.totp(device.secret_bytes, None, device.digits, device.period, device.algorithm) != "000000" else "111111"})
            step("wrong code is refused", r.status_code == 200 and "_auth_user_id" not in client.session, "HTTP %s" % r.status_code)
        code = core.totp(device.secret_bytes, None, device.digits, device.period, device.algorithm)
        r = client.post(reverse("dj_totp_2fa:verify"), {"code": code})
        step("correct code signs in", r.status_code == 302 and "_auth_user_id" in client.session, "HTTP %s" % r.status_code)
        step("session is marked verified", bool(client.session.get("dj_totp_verified")))
        r = client.get(reverse("dj_totp_2fa:overview"))
        step("account page is reachable", r.status_code == 200, "HTTP %s" % r.status_code)
        other = Client()
        other.post(login_url, {"username": account.get_username(), "password": password})
        r = other.post(reverse("dj_totp_2fa:verify"), {"code": code})
        step("the same code cannot be replayed", "_auth_user_id" not in other.session, "HTTP %s" % r.status_code)
        forced = Client()
        forced.force_login(account)
        r = forced.get(reverse("dj_totp_2fa:overview"))
        step("middleware blocks an unverified session", r.status_code == 302 and "verify" in r["Location"], "HTTP %s" % r.status_code)
        r = forced.get(reverse("dj_totp_2fa:overview"), HTTP_ACCEPT="application/json")
        step("JSON clients get 401", r.status_code == 401 and r.json().get("code") == "two_factor_required", "HTTP %s" % r.status_code)
