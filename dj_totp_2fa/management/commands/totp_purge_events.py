from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from dj_totp_2fa import conf
from dj_totp_2fa.models import Lockout, TwoFactorEvent


class Command(BaseCommand):
    help = "Delete audit events older than TOTP_EVENT_RETENTION_DAYS (or --days), and expired lockout rows."

    def add_arguments(self, parser):
        parser.add_argument("--days", type=int)
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, days=None, **options):
        days = days if days is not None else conf.get("EVENT_RETENTION_DAYS")
        now = timezone.now()
        stale_locks = Lockout.objects.filter(until__lt=now - timedelta(days=1), updated_at__lt=now - timedelta(seconds=int(conf.get("LOCKOUT_RESET_AFTER"))))
        if days is None:
            self.stdout.write("EVENT_RETENTION_DAYS is None: events are kept.")
            events_qs = TwoFactorEvent.objects.none()
        else:
            events_qs = TwoFactorEvent.objects.filter(created_at__lt=now - timedelta(days=days))
        n_events, n_locks = events_qs.count(), stale_locks.count()
        if not options["dry_run"]:
            events_qs.delete()
            stale_locks.delete()
        self.stdout.write("%s %d event(s) and %d expired lockout row(s)." % ("Would delete" if options["dry_run"] else "Deleted", n_events, n_locks))
