from django.core.management.base import BaseCommand, CommandError

from dj_totp_2fa import totp as core
from dj_totp_2fa.management.commands._util import get_user, require_debug
from dj_totp_2fa.models import TOTPDevice


class Command(BaseCommand):
    help = "DEVELOPMENT ONLY: print the code a user's authenticator shows right now."

    def add_arguments(self, parser):
        parser.add_argument("user")
        parser.add_argument("--force", action="store_true")

    def handle(self, *args, user, **options):
        require_debug("totp_code", options)
        device = TOTPDevice.objects.filter(user=get_user(user), confirmed=True).first()
        if device is None:
            raise CommandError("That user has no confirmed device.")
        self.stdout.write(core.totp(device.secret_bytes, None, device.digits, device.period, device.algorithm))
