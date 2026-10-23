from django.core.management.base import BaseCommand, CommandError

from dj_totp_2fa import crypto
from dj_totp_2fa.models import TOTPDevice


class Command(BaseCommand):
    help = ("Re-encrypt every stored secret with the current settings (first Fernet key, or the active mode). "
            "Put the new key FIRST in TOTP_ENCRYPTION_KEYS and keep the old ones until this has run.")

    def add_arguments(self, parser):
        parser.add_argument("--generate-key", action="store_true", help="Print a new Fernet key and exit.")
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **options):
        if options["generate_key"]:
            if not crypto.cryptography_available():
                raise CommandError("Install the cryptography package: pip install dj-totp-2fa[crypto]")
            self.stdout.write(crypto.generate_key())
            return
        changed = skipped = failed = 0
        for device in TOTPDevice.objects.all().iterator():
            try:
                if crypto.is_current(device.secret_encrypted):
                    skipped += 1
                    continue
                plain = crypto.decrypt(device.secret_encrypted)
            except crypto.SecretError as exc:
                failed += 1
                self.stderr.write("Device %s: %s" % (device.pk, exc))
                continue
            if not options["dry_run"]:
                TOTPDevice.objects.filter(pk=device.pk).update(secret_encrypted=crypto.encrypt(plain))
            changed += 1
        self.stdout.write("Mode: %s. Re-encrypted: %d, already current: %d, failed: %d." % (crypto.active_mode(), changed, skipped, failed))
        if failed:
            raise CommandError("Some secrets could not be decrypted. Keep the old keys in TOTP_ENCRYPTION_KEYS.")
