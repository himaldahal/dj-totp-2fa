from django.core.management.base import BaseCommand, CommandError

from dj_totp_2fa import events, ratelimit
from dj_totp_2fa.management.commands._util import get_user


class Command(BaseCommand):
    help = "Clear lockouts and failure counters for a user, an IP, or everything (--all)."

    def add_arguments(self, parser):
        parser.add_argument("user", nargs="?")
        parser.add_argument("--ip")
        parser.add_argument("--all", action="store_true")

    def handle(self, *args, user=None, ip=None, **options):
        if not (user or ip or options["all"]):
            raise CommandError("Give a user, --ip ADDRESS or --all.")
        n = 0
        if options["all"]:
            n += ratelimit.clear_lockouts(everything=True)
        if user:
            u = get_user(user)
            n += ratelimit.clear_lockouts(user=u)
            events.record("lockout_cleared", None, user=u, via="command")
        if ip:
            n += ratelimit.clear_lockouts(ip=ip)
        self.stdout.write(self.style.SUCCESS("Cleared %d lockout record(s)." % n))
