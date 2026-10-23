from django.core.management.base import BaseCommand

from dj_totp_2fa import api
from dj_totp_2fa.management.commands._util import get_user


class Command(BaseCommand):
    help = "Turn off two-factor authentication for a user (audited). Use when a user lost their device and recovery codes."

    def add_arguments(self, parser):
        parser.add_argument("user")

    def handle(self, *args, user, **options):
        u = get_user(user)
        n = api.disable(u, None, actor=None, event="admin_disabled")
        self.stdout.write(self.style.SUCCESS("Removed %d device(s) for %s. Recovery codes and trusted browsers were deleted." % (n, u.get_username())))
