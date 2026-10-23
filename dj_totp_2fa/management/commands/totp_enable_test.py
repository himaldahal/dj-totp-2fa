from django.core.management.base import BaseCommand

from dj_totp_2fa import api, totp as core
from dj_totp_2fa.management.commands._util import get_user, require_debug


class Command(BaseCommand):
    help = "DEVELOPMENT ONLY: give a user a confirmed device and print the otpauth URI and the current code."

    def add_arguments(self, parser):
        parser.add_argument("user")
        parser.add_argument("--code-only", action="store_true", help="Print just the current code.")
        parser.add_argument("--force", action="store_true", help="Run even with DEBUG=False (never in production).")

    def handle(self, *args, user, **options):
        require_debug("totp_enable_test", options)
        u = get_user(user)
        device = api.create_device(u, "Test device")
        from django.utils import timezone
        device.confirmed, device.primary, device.confirmed_at = True, True, timezone.now()
        device.save()
        code = core.totp(device.secret_bytes, None, device.digits, device.period, device.algorithm)
        if options["code_only"]:
            self.stdout.write(code)
            return
        self.stdout.write("Device #%d created for %s" % (device.pk, u.get_username()))
        self.stdout.write("otpauth URI: %s" % device.uri())
        self.stdout.write("Current code: %s" % code)
