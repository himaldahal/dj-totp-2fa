from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.utils import timezone

from dj_totp_2fa import api, policy
from dj_totp_2fa.management.commands._util import get_user, table
from dj_totp_2fa.models import Lockout, TOTPDevice, TrustedBrowser


class Command(BaseCommand):
    help = "Show two-factor status for one user, or a summary for everyone."

    def add_arguments(self, parser):
        parser.add_argument("user", nargs="?")

    def handle(self, *args, user=None, **options):
        if user:
            u = get_user(user)
            devices = TOTPDevice.objects.filter(user=u)
            self.stdout.write("User: %s (id %s)" % (u.get_username(), u.pk))
            self.stdout.write("2FA enabled: %s   required by policy: %s" % (api.is_enabled(u), policy.is_required(u)))
            self.stdout.write("Recovery codes left: %d   trusted browsers: %d" % (
                api.recovery_codes_remaining(u), TrustedBrowser.objects.filter(user=u).count()))
            rows = [(d.pk, d.name, d.algorithm, d.digits, d.period, "yes" if d.confirmed else "no", d.last_used_at or "never", d.failure_count) for d in devices]
            if rows:
                self.stdout.write(table(rows, ("id", "name", "algo", "digits", "period", "confirmed", "last used", "failures")))
            return
        User = get_user_model()
        total = User._default_manager.count()
        enabled = TOTPDevice.objects.filter(confirmed=True).values("user").distinct().count()
        self.stdout.write("Users: %d   with 2FA: %d (%.0f%%)   active lockouts: %d" % (
            total, enabled, 100.0 * enabled / total if total else 0, Lockout.objects.filter(until__gt=timezone.now()).count()))
